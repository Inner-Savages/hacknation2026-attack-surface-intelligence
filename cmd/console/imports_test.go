package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func invServer(t *testing.T) (*server, string, string) {
	t.Helper()
	s, ts, tok := testServer(t)
	t.Cleanup(ts.Close)
	inv, err := openInventory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.inv = inv
	return s, ts.URL, tok
}

func call(t *testing.T, method, url, tok, body string) (int, []byte) {
	t.Helper()
	r, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		withAuth(r, tok)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestNormalizeTarget(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1": "10.0.0.1", "10.0.0.7/24": "10.0.0.0/24", "Example.COM": "example.com", "2001:db8::1": "2001:db8::1",
	} {
		if got, _, err := normalizeTarget(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "10.0.0.1-20", "not a host", "10.0.0.0/8", "http://x", "a/b"} {
		if _, _, err := normalizeTarget(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestImportTargetsAllFormatsDedup(t *testing.T) {
	s, base, tok := invServer(t)
	imp := func(q, body string) (int, map[string]interface{}) {
		code, b := call(t, "POST", base+"/api/import?kind=targets"+q, tok, body)
		var m map[string]interface{}
		json.Unmarshal(b, &m)
		return code, m
	}
	code, m := imp("", "# comment\n10.0.0.1\n10.0.0.1, example.com\n192.168.1.9/24\nbad!host\n")
	if code != 200 || m["added"].(float64) != 3 || m["duplicates"].(float64) != 1 || m["rejected"].(float64) != 1 {
		t.Fatalf("txt: %d %v", code, m)
	}
	code, m = imp("&tags=prod", "target,tags\n10.0.0.2,web;edge\nexample.com,dmz\n")
	if code != 200 || m["added"].(float64) != 1 || m["duplicates"].(float64) != 1 {
		t.Fatalf("csv: %d %v", code, m)
	}
	code, m = imp("", `{"targets":["10.0.0.3",{"value":"10.0.0.4","tags":["a"]}]}`)
	if code != 200 || m["added"].(float64) != 2 {
		t.Fatalf("json: %d %v", code, m)
	}
	ts := s.inv.listTargets()
	if len(ts) != 6 {
		t.Fatalf("targets: %+v", ts)
	}
	if code, _ := imp("", "garbage!!"); code != 400 {
		t.Fatal("all-invalid file accepted")
	}
	// tags merged onto an existing target
	for _, tg := range ts {
		if tg.Value == "example.com" && len(tg.Tags) != 2 {
			t.Fatalf("tags not merged: %+v", tg)
		}
	}
}

func TestImportSizeLimitAndAuth(t *testing.T) {
	_, base, tok := invServer(t)
	if code, _ := call(t, "POST", base+"/api/import?kind=targets", "", "10.0.0.1"); code != 401 {
		t.Fatalf("unauthenticated import: %d", code)
	}
	big := strings.Repeat("10.0.0.1\n", maxImportBytes/8)
	if code, _ := call(t, "POST", base+"/api/import?kind=targets", tok, big); code != 413 {
		t.Fatalf("oversize: %d", code)
	}
	if code, _ := call(t, "POST", base+"/api/import?kind=nope", tok, "x"); code != 400 {
		t.Fatalf("bad kind: %d", code)
	}
}

const scanA = `{"started_at":"2026-05-01T10:00:00Z","targets":["10.0.0.1","10.0.0.2"],"hosts":[
 {"address":"10.0.0.1","state":"up","services":[{"port":80,"proto":"tcp","state":"open","name":"http","product":"nginx","version":"1.18",
   "http":{"url":"http://10.0.0.1/","status":200,"title":"Welcome"},"tech":[{"name":"nginx","version":"1.18","confidence":0.9,"tags":["web"],"evidence":["h"]}]}]},
 {"address":"10.0.0.2","state":"up","services":[{"port":22,"proto":"tcp","state":"open","name":"ssh"}]}]}`

const scanB = `{"started_at":"2026-05-02T10:00:00Z","targets":["10.0.0.1","10.0.0.2"],"hosts":[
 {"address":"10.0.0.1","state":"up","services":[{"port":80,"proto":"tcp","state":"open","name":"http","product":"nginx","version":"1.24",
   "http":{"url":"http://10.0.0.1/","status":200,"title":"Welcome v2"}}]},
 {"address":"10.0.0.2","state":"up","services":[{"port":22,"proto":"tcp","state":"open","name":"ssh"},{"port":3306,"proto":"tcp","state":"open","name":"mysql"}]}]}`

func entryByKey(t *testing.T, base, tok, key string) Entry {
	t.Helper()
	_, b := call(t, "GET", base+"/api/inventory", tok, "")
	var r struct{ Entries []Entry }
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Entries {
		if e.Key == key {
			return e
		}
	}
	t.Fatalf("no entry %s in %s", key, b)
	return Entry{}
}

func TestScanImportDiffAndOverrideSurvivesRescan(t *testing.T) {
	s, base, tok := invServer(t)
	if code, b := call(t, "POST", base+"/api/import?kind=scan", tok, scanA); code != 200 {
		t.Fatalf("scan A: %d %s", code, b)
	}
	key := "svc:10.0.0.1:tcp:80"
	e := entryByKey(t, base, tok, key)
	if e.Original.Title != "Welcome" || e.Effective.Technology != "nginx 1.18" || e.Override != nil {
		t.Fatalf("original: %+v", e)
	}
	code, b := call(t, "PUT", base+"/api/overrides/"+key, tok, `{"title":"Corporate portal","tags":["Crown-Jewel"," prod"],"note":"owner: web team","status":"potwierdzony"}`)
	if code != 200 {
		t.Fatalf("put override: %d %s", code, b)
	}
	e = entryByKey(t, base, tok, key)
	if e.Effective.Title != "Corporate portal" || e.Original.Title != "Welcome" || e.Effective.Status != "potwierdzony" ||
		strings.Join(e.Effective.Tags, ",") != "crown-jewel,prod" || e.Effective.Technology != "nginx 1.18" {
		t.Fatalf("layered: %+v", e)
	}
	// Second scan: diff computed, original data replaced, override untouched.
	code, b = call(t, "POST", base+"/api/import?kind=scan", tok, scanB)
	if code != 200 || !strings.Contains(string(b), `"new_services":1`) || !strings.Contains(string(b), `"changed_services":1`) {
		t.Fatalf("scan B: %d %s", code, b)
	}
	e = entryByKey(t, base, tok, key)
	if e.Original.Title != "Welcome v2" || e.Effective.Title != "Corporate portal" || e.Effective.Status != "potwierdzony" {
		t.Fatalf("override lost after rescan: %+v", e)
	}
	// restart: state and override are durable
	inv2, err := openInventory(s.inv.dir[:len(s.inv.dir)-len("/inventory")])
	if err != nil {
		t.Fatal(err)
	}
	if o := inv2.st.Overrides[key]; o == nil || *o.Title != "Corporate portal" || inv2.scan == nil || len(inv2.scan.Hosts) != 2 {
		t.Fatal("not persisted")
	}
	// DELETE restores the original
	if code, _ := call(t, "DELETE", base+"/api/overrides/"+key, tok, ""); code != 204 {
		t.Fatal("delete")
	}
	if e = entryByKey(t, base, tok, key); e.Effective.Title != "Welcome v2" || e.Override != nil {
		t.Fatalf("not restored: %+v", e)
	}
	if code, _ := call(t, "DELETE", base+"/api/overrides/"+key, tok, ""); code != 404 {
		t.Fatal("second delete should 404")
	}
}

func TestOverrideValidation(t *testing.T) {
	_, base, tok := invServer(t)
	for body, want := range map[string]int{`{}`: 400, `{"status":"bogus"}`: 400, `not json`: 400, `{"note":"ok"}`: 200} {
		if code, _ := call(t, "PUT", base+"/api/overrides/host:10.0.0.9", tok, body); code != want {
			t.Errorf("%s -> %d, want %d", body, code, want)
		}
	}
	if code, _ := call(t, "PUT", base+"/api/overrides/evil", tok, `{"note":"x"}`); code != 400 {
		t.Error("bad key accepted")
	}
	if code, _ := call(t, "PUT", base+"/api/overrides/host:1.1.1.1", "", `{"note":"x"}`); code != 401 {
		t.Error("unauthenticated PUT")
	}
}

func TestScanCSVImportRoundTripAndMultipart(t *testing.T) {
	_, base, tok := invServer(t)
	csvData := "address,hostnames,port,proto,service,product,version,http_status,http_title,technologies,tags\n" +
		"10.1.1.1,a.example.com,443,tcp,https,nginx,1.25,200,Login,nginx 1.25; WordPress 6.4,admin-panel\n" +
		"10.1.1.1,,443,tcp,https,nginx,1.25,200,Login,,\n" + // duplicate
		"10.1.1.2,,70000,tcp,,,,,,,\n" // bad port
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "scan.csv")
	fw.Write([]byte(csvData))
	mw.Close()
	r, _ := http.NewRequest("POST", base+"/api/import?kind=scan", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	withAuth(r, tok)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"hosts":1`) || !strings.Contains(string(b), "duplicate") {
		t.Fatalf("csv import: %d %s", resp.StatusCode, b)
	}
	e := entryByKey(t, base, tok, "svc:10.1.1.1:tcp:443")
	if e.Original.Title != "Login" || e.Original.Technology != "nginx 1.25; WordPress 6.4" || len(e.Original.Tags) != 1 {
		t.Fatalf("%+v", e)
	}
}

func TestManualTargetShowsAsEntryAndOverridable(t *testing.T) {
	_, base, tok := invServer(t)
	code, _ := call(t, "POST", base+"/api/targets", tok, `{"value":"Staging.Example.com","tags":["Staging"]}`)
	if code != 201 {
		t.Fatalf("add: %d", code)
	}
	if code, _ = call(t, "POST", base+"/api/targets", tok, `{"value":"staging.example.com"}`); code != 200 {
		t.Fatal("duplicate should be 200 (merged)")
	}
	if code, _ = call(t, "POST", base+"/api/targets", tok, `{"value":"10.0.0.0/8"}`); code != 400 {
		t.Fatal("huge cidr accepted")
	}
	e := entryByKey(t, base, tok, "host:staging.example.com")
	if e.Kind != "target" || e.Effective.Tags[0] != "staging" {
		t.Fatalf("%+v", e)
	}
	_, txt := call(t, "GET", base+"/api/targets.txt", tok, "")
	if strings.TrimSpace(string(txt)) != "staging.example.com" {
		t.Fatalf("txt export: %q", txt)
	}
	if code, _ = call(t, "DELETE", base+"/api/targets/staging.example.com", tok, ""); code != 204 {
		t.Fatal("delete target")
	}
}
