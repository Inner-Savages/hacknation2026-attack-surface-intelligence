package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// findingJSON is a trigger finding for host 10.0.4.17 port 22, the same
// target the escalation helper uses.
func findingJSON(verdict string) string {
	f := map[string]interface{}{
		"time":    time.Now().Format(time.RFC3339Nano),
		"target":  map[string]interface{}{"ip": "10.0.4.17", "port": 22},
		"kind":    "scan-service",
		"verdict": verdict,
		"score":   0.86,
		"reason":  "remote_rank_max",
		"events": []map[string]interface{}{
			{"time": time.Now().Format(time.RFC3339Nano), "type": "service_changed", "ip": "10.0.4.17", "port": 22, "proto": "tcp"},
		},
		"services": []map[string]interface{}{
			{"port": 22, "name": "ssh", "product": "OpenSSH", "version": "9.6", "tech": []string{"SSH"}},
		},
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func postFinding(h http.Handler, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/findings", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// A finding about a host with an open case correlates: the active evidence
// lands on the case as an audited note and history entry, and the live feed
// shows the verification.
func TestFindingsCorrelateWithOpenCase(t *testing.T) {
	s, _, _ := testServer(t)
	h := s.routes()
	if postFinding(h, findingJSON("gone-confirmed"), "").Code != 401 {
		t.Fatal("accepted finding without token")
	}
	if postFinding(h, "{}", "test-token").Code != 400 {
		t.Fatal("accepted invalid finding")
	}
	// Open a case for the host through the normal intake.
	r := httptest.NewRequest("POST", "/events", strings.NewReader(escalation("e1", "edge-a-1")))
	r.Header.Set("Authorization", "Bearer test-token")
	w0 := httptest.NewRecorder()
	h.ServeHTTP(w0, r)
	if w0.Code != 202 {
		t.Fatalf("intake failed: %d", w0.Code)
	}
	w := postFinding(h, findingJSON("gone-confirmed"), "test-token")
	if w.Code != 200 {
		t.Fatalf("finding rejected: %d %s", w.Code, w.Body.String())
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["correlated"] != true || res["case"] != "e1" {
		t.Fatalf("finding did not correlate: %v", res)
	}
	c, _ := s.store.Get("e1")
	var sawVerify bool
	for _, e := range c.History {
		if e.Kind == "verify" && strings.Contains(e.Text, "POTWIERDZIŁA zniknięcie") {
			sawVerify = true
		}
	}
	if !sawVerify {
		t.Fatalf("verification missing from case history: %+v", c.History)
	}
	if len(c.Notes) == 0 || !strings.Contains(c.Notes[0].Text, "22/ssh OpenSSH") {
		t.Fatalf("evidence note missing or incomplete: %+v", c.Notes)
	}
	// The finding is evidence, not a verdict on the case: the human (or the
	// AI operator) still owns the status.
	if c.Status != StatusNew {
		t.Fatalf("finding changed the case status: %s", c.Status)
	}
	// And it is visible in the live feed.
	items, _ := s.feed.Since(0, 100)
	var sawFeed bool
	for _, e := range items {
		if e.Kind == "verify" && strings.Contains(e.Text, "10.0.4.17:22") {
			sawFeed = true
		}
	}
	if !sawFeed {
		t.Fatal("verification missing from the live feed")
	}
}

// A finding about a host with no open case opens one, so verified evidence
// is never orphaned.
func TestFindingsWithoutCaseOpensOne(t *testing.T) {
	s, _, _ := testServer(t)
	h := s.routes()
	w := postFinding(h, findingJSON("still-open"), "test-token")
	if w.Code != 200 {
		t.Fatalf("finding rejected: %d %s", w.Code, w.Body.String())
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["correlated"] != false {
		t.Fatalf("expected a new case, got %v", res)
	}
	id, _ := res["case"].(string)
	if !strings.HasPrefix(id, "fx-") {
		t.Fatalf("bad derived case id: %q", id)
	}
	c, ok := s.store.Get(id)
	if !ok {
		t.Fatal("finding did not open a case")
	}
	if c.Source != "10.0.4.17" || c.Target != "tcp:22" || c.Score != 0.86 || c.SensorID != "trigger" {
		t.Fatalf("bad derived case: %+v", c)
	}
	// The second identical finding deduplicates onto the same case.
	w = postFinding(h, findingJSON("still-open"), "test-token")
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["case"] != id {
		t.Fatalf("duplicate finding opened a second case: %v", res)
	}
}

// The console's scan action requests active verification from the trigger:
// a targeted event for the case's host and port, through the trigger's
// normal policy (allow list, debounce, cooldown).
func TestScanActionRequestsVerification(t *testing.T) {
	var got atomic.Int32
	var lastBody atomic.Value
	trig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer trig-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		lastBody.Store(string(buf))
		got.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"received":1,"accepted":1}`))
	}))
	defer trig.Close()

	s, _, tok := testServer(t)
	s.triggerURL = trig.URL + "/events"
	s.triggerToken = "trig-token"
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e2", "edge-b-2")); err != nil {
		t.Fatal(err)
	}
	h := s.routes()
	r := withAuth(httptest.NewRequest("POST", "/api/alerts/e2/actions", strings.NewReader(`{"action":"scan"}`)), tok)
	w0 := httptest.NewRecorder()
	h.ServeHTTP(w0, r)
	if w0.Code != 200 {
		t.Fatalf("scan action failed: %d", w0.Code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for got.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got.Load() != 1 {
		t.Fatal("trigger never received the verification request")
	}
	body, _ := lastBody.Load().(string)
	if !strings.Contains(body, `"type":"service_new"`) || !strings.Contains(body, `"ip":"10.0.4.17"`) || !strings.Contains(body, `"port":22`) {
		t.Fatalf("bad verification request: %s", body)
	}
}

// RBAC: POST /findings is machine intake (bearer token). A logged-in viewer's
// session is not a credential for it, so it cannot write findings, and the
// case actions that drive verification stay behind cases:update.
func TestViewerCannotWriteFindings(t *testing.T) {
	s, _, _ := testServer(t)
	h := s.routes()
	viewer := userWithRole(t, s, "vera", "viewer")
	if w := call(t, h, "POST", "/findings", findingJSON("gone-confirmed"), viewer); w.Code != 401 {
		t.Errorf("viewer session POST /findings = %d, want 401", w.Code)
	}
	if w := call(t, h, "POST", "/api/alerts/x/actions", `{"action":"scan"}`, viewer); w.Code != 403 {
		t.Errorf("viewer scan action = %d, want 403", w.Code)
	}
}
