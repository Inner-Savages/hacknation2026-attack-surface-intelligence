package defectdojo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/export"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

const testToken = "0123456789abcdef"

// fakeDojo mimics the parts of DefectDojo 3.5's API v2 the client uses,
// including its habits: substring name filters, paging, and titles rewritten
// in title case.
type fakeDojo struct {
	t  *testing.T
	mu sync.Mutex

	objects  map[string][]map[string]any // by collection path
	writes   []string                    // "POST /products/"
	uploads  []map[string]string
	dropAll  bool // accept imports but store nothing
	maxLimit int
}

func newFake(t *testing.T) (*fakeDojo, *Client) {
	f := &fakeDojo{t: t, objects: map[string][]map[string]any{
		"/test_types/": {{"id": 1, "name": "Generic Findings Import"}, {"id": 2, "name": "Nmap Scan"}},
		// A product whose name merely contains ours must not be picked.
		"/products/": {{"id": 1, "name": "Silence on the Wire (old)"}},
	}, maxLimit: 2}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testToken, false)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func (f *fakeDojo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Token "+testToken {
		http.Error(w, `{"detail":"Invalid token."}`, http.StatusForbidden)
		return
	}
	if strings.Contains(r.URL.String(), testToken) {
		f.t.Error("token in URL")
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v2")
	if r.Method != http.MethodGet {
		f.writes = append(f.writes, r.Method+" "+path)
	}
	switch {
	case r.Method == http.MethodGet:
		f.list(w, r, path)
	case path == "/reimport-scan/":
		f.reimport(w, r)
	case r.Method == http.MethodPost:
		var obj map[string]any
		f.decode(r.Body, &obj)
		obj["id"] = len(f.objects[path]) + 100
		f.objects[path] = append(f.objects[path], obj)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(obj)
	case r.Method == http.MethodPatch:
		var patch map[string]any
		f.decode(r.Body, &patch)
		parts := strings.Split(path, "/")
		for _, o := range f.objects["/findings/"] {
			if fmt.Sprint(o["id"]) == parts[2] {
				for k, v := range patch {
					o[k] = v
				}
				_ = json.NewEncoder(w).Encode(o)
				return
			}
		}
		http.NotFound(w, r)
	}
}

func (f *fakeDojo) decode(r io.Reader, v any) {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		f.t.Error(err)
	}
}

func (f *fakeDojo) list(w http.ResponseWriter, r *http.Request, path string) {
	q := r.URL.Query()
	var hits []map[string]any
	for _, o := range f.objects[path] {
		if n := q.Get("name"); n != "" && !strings.Contains(fmt.Sprint(o["name"]), n) {
			continue
		}
		if n := q.Get("test"); n != "" && n != fmt.Sprint(o["test"]) {
			continue
		}
		if n := q.Get("test_type"); n != "" && n != fmt.Sprint(o["test_type"]) {
			continue
		}
		hits = append(hits, o)
	}
	count := len(hits)
	off, _ := strconv.Atoi(q.Get("offset"))
	hits = hits[min(off, count):]
	hits = hits[:min(len(hits), f.maxLimit)]
	if hits == nil {
		hits = []map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"count": count, "next": "http://elsewhere.invalid/", "results": hits})
}

func (f *fakeDojo) reimport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		f.t.Error(err)
	}
	fields := map[string]string{}
	for k := range r.MultipartForm.Value {
		fields[k] = r.FormValue(k)
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		f.t.Error(err)
		return
	}
	data, _ := io.ReadAll(file)
	fields["file"] = string(data)
	f.uploads = append(f.uploads, fields)
	if fields["scan_type"] == genericScan && !f.dropAll {
		var rep struct{ Findings []map[string]any }
		f.decode(strings.NewReader(fields["file"]), &rep)
		for _, o := range rep.Findings {
			o["id"] = len(f.objects["/findings/"]) + 1
			o["test"] = fields["test"]
			o["title"] = strings.Title(o["title"].(string)) //nolint:staticcheck // what DefectDojo does
			f.objects["/findings/"] = append(f.objects["/findings/"], o)
		}
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"test_id":100}`))
}

var t0 = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

func observations(at time.Time, ports ...int) []export.Observation {
	s := &result.Scan{FinishedAt: at, Hosts: []result.Host{{Address: "10.0.0.5", State: "up"}}}
	for _, p := range ports {
		s.Hosts[0].Services = append(s.Hosts[0].Services, result.Service{Port: p, Proto: "tcp", State: "open", Name: "http",
			Tech: []result.Tech{{Name: "Admin panel", Confidence: 0.6, Tags: []string{"admin-panel"}, Evidence: []string{"title"}}}})
	}
	obs, err := export.Observe(export.Selection{}, s)
	if err != nil {
		panic(err)
	}
	return obs
}

func TestSyncIsIdempotent(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	obs := observations(t0, 80, 81, 82, 83, 84) // more than one page

	rep, err := c.Sync(ctx, Context{}, obs)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Count(Created) != 5 || len(f.uploads) != 1 {
		t.Fatalf("first run: %+v, %d uploads", rep, len(f.uploads))
	}
	up := f.uploads[0]
	if up["close_old_findings"] != "false" || up["test"] != strconv.Itoa(rep.TestID) || up["scan_type"] != genericScan {
		t.Errorf("import fields: %v", up)
	}
	if n := len(f.objects["/products/"]); n != 2 {
		t.Errorf("%d products, want the similar one and ours", n)
	}

	f.writes = nil
	if rep, err = c.Sync(ctx, Context{}, obs); err != nil {
		t.Fatal(err)
	}
	if rep.Count(Unchanged) != 5 || len(f.writes) != 0 {
		t.Fatalf("second run: %+v, writes %v", rep, f.writes)
	}

	// A later scan refreshes the evidence, keeps first-seen, adds only what is new.
	if rep, err = c.Sync(ctx, Context{}, observations(t0.AddDate(0, 0, 2), 80, 81, 82, 83, 84, 85)); err != nil {
		t.Fatal(err)
	}
	if rep.Count(Updated) != 5 || rep.Count(Created) != 1 || len(f.objects["/findings/"]) != 6 {
		t.Fatalf("third run: %+v", rep)
	}
	d := f.objects["/findings/"][0]["description"].(string)
	if !strings.Contains(d, "First seen: `2026-11-22`") || !strings.Contains(d, "Last seen: `2026-11-24T10:00:00Z`") {
		t.Errorf("description:\n%s", d)
	}
}

func TestSyncRespectsAnalysts(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	if _, err := c.Sync(ctx, Context{}, observations(t0, 80, 81)); err != nil {
		t.Fatal(err)
	}
	closed, tagged := f.objects["/findings/"][0], f.objects["/findings/"][1]
	closed["active"] = false
	before := closed["description"]
	tagged["tags"] = []string{"owner-x", "silence-on-the-wire", "admin-panel"}
	tagged["severity"] = "High"

	rep, err := c.Sync(ctx, Context{}, observations(t0.Add(time.Hour), 80, 81))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Count(Closed) != 1 || rep.Count(Updated) != 1 {
		t.Fatalf("%+v", rep)
	}
	if closed["active"] != false || closed["description"] != before {
		t.Error("a closed finding was changed")
	}
	if len(tagged["tags"].([]string)) != 3 || tagged["severity"] != "High" {
		t.Errorf("analyst's tag or severity lost: %v %v", tagged["tags"], tagged["severity"])
	}

	// A lost tag of ours comes back without dropping theirs.
	tagged["tags"] = []string{"owner-x"}
	if _, err := c.Sync(ctx, Context{}, observations(t0.Add(time.Hour), 81)); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(tagged["tags"]); got != "[owner-x silence-on-the-wire admin-panel]" {
		t.Errorf("tags %s", got)
	}
}

func TestSyncNoticesLostFindings(t *testing.T) {
	f, c := newFake(t)
	f.dropAll = true
	if _, err := c.Sync(context.Background(), Context{}, observations(t0, 80)); err == nil {
		t.Error("import that stored nothing reported as success")
	}
}

func TestSeparateContexts(t *testing.T) {
	f, c := newFake(t)
	for _, name := range []string{"site A", "site B"} {
		rep, err := c.Sync(context.Background(), Context{Test: name}, observations(t0, 80))
		if err != nil {
			t.Fatal(err)
		}
		if rep.Count(Created) != 1 {
			t.Errorf("%s: %+v", name, rep)
		}
	}
	if len(f.objects["/tests/"]) != 2 || len(f.objects["/engagements/"]) != 1 {
		t.Errorf("tests %v", f.objects["/tests/"])
	}
}

func TestImportNmap(t *testing.T) {
	f, c := newFake(t)
	s := &result.Scan{FinishedAt: t0, Hosts: []result.Host{
		{Address: "10.0.0.5", State: "up", Services: []result.Service{{Port: 80, Proto: "tcp", State: "open", Name: "http"}}},
		{Address: "fd00::1", State: "up"}, // the importer crashes on hosts without IPv4
	}}
	_, skipped, err := c.ImportNmap(context.Background(), Context{}, s)
	if err != nil || skipped != 1 {
		t.Fatalf("skipped %d, err %v", skipped, err)
	}
	up := f.uploads[0]
	if up["scan_type"] != "Nmap Scan" || up["scan_date"] != "2026-11-22" || !strings.Contains(up["file"], "<nmaprun") || strings.Contains(up["file"], "fd00::1") {
		t.Errorf("upload: %v", up)
	}
}

func TestNewRejectsUnsafeURLs(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://dojo.example.org":          true,
		"https://dojo.example.org/api/v2/":  true,
		"http://127.0.0.1:8080":             true,
		"http://localhost:8080/":            true,
		"http://[::1]:8080":                 true,
		"http://dojo.example.org":           false,
		"http://localhost.evil.example":     false,
		"https://user:pw@dojo.example.org":  false,
		"https://dojo.example.org/?token=x": false,
		"dojo.example.org":                  false,
		"ftp://dojo.example.org":            false,
	} {
		c, err := New(url, testToken, false)
		if (err == nil) != ok {
			t.Errorf("%s: err %v", url, err)
		}
		if err == nil && !strings.HasSuffix(c.base, "/api/v2") || err == nil && strings.Count(c.base, "/api/v2") != 1 {
			t.Errorf("%s: base %s", url, c.base)
		}
	}
	if _, err := New("http://dojo.example.org", testToken, true); err != nil {
		t.Error(err)
	}
	if _, err := New("https://dojo.example.org", " \n", false); err == nil {
		t.Error("empty token accepted")
	}
}

func TestErrors(t *testing.T) {
	_, c := newFake(t)
	c.token = "wrong"
	_, err := c.Sync(context.Background(), Context{}, nil)
	var de *Error
	if !errors.As(err, &de) || de.Status != http.StatusForbidden {
		t.Errorf("err = %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Error("token in error message")
	}

	// A redirect must not carry the token away.
	leaked := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked = true }))
	defer other.Close()
	redir := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusFound))
	defer redir.Close()
	c, _ = New(redir.URL, testToken, false)
	if _, err := c.Sync(context.Background(), Context{}, nil); err == nil || leaked {
		t.Errorf("redirect: err %v, followed %v", err, leaked)
	}

	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer html.Close()
	c, _ = New(html.URL, testToken, false)
	if _, err := c.Sync(context.Background(), Context{}, nil); err == nil || !strings.Contains(err.Error(), "URL right") {
		t.Errorf("html: %v", err)
	}
}

func TestDescriptionNeutralizesHostileContent(t *testing.T) {
	o := export.Observation{
		ID: "sotw:x", Rule: "category:db admin", Title: "T", Why: "why", Address: "fd00::1",
		Service: result.Service{Port: 443, Proto: "tcp", Product: "\x00\x1b[31m", HTTP: &result.HTTP{
			URL:   "https://[fd00::1]/",
			Title: "a` [x](javascript:1)\n\n# big\x00 <script>" + strings.Repeat("é", 500),
		}},
		VulnIDs: []string{"CVE-2021-23017"},
	}
	f := NewFinding(o)
	if strings.ContainsRune(f.Description, 0) || strings.Contains(f.Description, "\x1b") || strings.Contains(f.Description, "\n# big") {
		t.Errorf("control characters or markup survived:\n%q", f.Description)
	}
	for _, line := range strings.Split(f.Description, "\n") {
		if strings.Count(line, "`")%2 != 0 {
			t.Errorf("unbalanced code span: %q", line)
		}
		if strings.HasPrefix(line, "- Title: ") && (strings.Count(line, "`") != 2 || len([]rune(line)) > maxValue+20) {
			t.Errorf("title line: %q", line)
		}
	}
	if f.Endpoints[0] != "https://[fd00::1]:443" || f.Tags[1] != "category-db-admin" || f.Severity != "Info" || f.VulnerabilityIDs[0] != "CVE-2021-23017" {
		t.Errorf("%+v", f)
	}
}
