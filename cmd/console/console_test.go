package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &server{store: store, token: "test-token", demo: true}
	return s, httptest.NewServer(s.routes())
}

func escalation(id, sensor string) string {
	env := map[string]interface{}{
		"event":    map[string]interface{}{"time": time.Now().Format(time.RFC3339), "type": "service_changed", "ip": "10.0.4.17", "port": 22, "proto": "tcp"},
		"event_id": id, "sensor_id": sensor, "forward": true, "unresolved": false, "reason": "remote_rank_max",
		"systemone_scores": map[string]interface{}{"kev": map[string]interface{}{"score": 0.86}},
	}
	b, _ := json.Marshal(env)
	return string(b)
}

func post(t *testing.T, url, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	return w
}

func TestIntakeRequiresAuthPersistsAndDeduplicates(t *testing.T) {
	s, _ := testServer(t)
	h := s.routes()
	req := func(body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/events", strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if req(escalation("e1", "edge-a-1"), "").Code != 401 {
		t.Fatal("accepted without token")
	}
	if req("{}", "test-token").Code != 400 {
		t.Fatal("accepted invalid envelope")
	}
	if req(escalation("e1", "edge-a-1"), "test-token").Code != 202 {
		t.Fatal("did not accept escalation")
	}
	if req(escalation("e1", "edge-a-1"), "test-token").Code != 202 {
		t.Fatal("duplicate was not acknowledged")
	}
	if len(s.store.ListCases()) != 1 {
		t.Fatal("duplicate created a second case")
	}
	c, _ := s.store.Get("e1")
	if c.Status != StatusNew || c.Score != 0.86 || c.Source != "10.0.4.17" || c.Target != "tcp:22" {
		t.Fatalf("bad derived fields: %+v", c)
	}
	if len(c.History) != 1 || !strings.Contains(c.History[0].Text, "remote_rank_max") {
		t.Fatal("missing creation history entry")
	}
	reloaded, err := openStore(s.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Get("e1"); !ok {
		t.Fatal("case was not durable across reopen")
	}
}

func TestWorkflowAndTwoStepIsolate(t *testing.T) {
	s, _ := testServer(t)
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e2", "edge-b-2")); err != nil {
		t.Fatal(err)
	}
	h := s.routes()
	call := func(path string, body map[string]string) (int, map[string]interface{}) {
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(b)))
		var out map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := call("/api/alerts/e2/status", map[string]string{"status": "bogus"}); code != 400 {
		t.Fatal("accepted bogus status")
	}
	if code, _ := call("/api/alerts/e2/status", map[string]string{"status": StatusVerify, "actor": "M. Kowalska"}); code != 200 {
		t.Fatal("status change failed")
	}
	if code, _ := call("/api/alerts/e2/notes", map[string]string{"text": "kontroler hali B", "actor": "A. Lis"}); code != 200 {
		t.Fatal("note failed")
	}
	code, out := call("/api/alerts/e2/actions", map[string]string{"action": "isolate", "actor": "A. Lis"})
	if code != 200 || out["state"] != "confirmation_required" {
		t.Fatalf("isolate was not two-step: %v %v", code, out)
	}
	if code, _ := call("/api/alerts/e2/actions", map[string]string{"action": "isolate", "actor": "A. Lis", "confirm": "true"}); code != 200 {
		t.Fatal("confirmed isolate failed")
	}
	c, _ := s.store.Get("e2")
	if c.Status != StatusVerify || len(c.Notes) != 1 || len(c.Actions) != 1 || c.PendingAction != "" {
		t.Fatalf("bad final case: %+v", c)
	}
	var kinds []string
	for _, h := range c.History {
		kinds = append(kinds, h.Kind)
	}
	if strings.Join(kinds, ",") != "alert,status,note,action,action" {
		t.Fatalf("unexpected history: %v", kinds)
	}
}

// The UI sends confirm as a JSON boolean; decoding must not drop the action.
func TestActionAcceptsBooleanConfirm(t *testing.T) {
	s, _ := testServer(t)
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e3", "edge-c-3")); err != nil {
		t.Fatal(err)
	}
	h := s.routes()
	raw := func(body string) (int, map[string]interface{}) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/alerts/e3/actions", strings.NewReader(body)))
		var out map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := raw(`{"action":"isolate","actor":"A. Lis","confirm":false}`)
	if code != 200 || out["state"] != "confirmation_required" {
		t.Fatalf("arming failed: %v %v", code, out)
	}
	code, out = raw(`{"action":"isolate","actor":"A. Lis","confirm":true}`)
	if code != 200 || out["state"] != "executed" {
		t.Fatalf("confirm failed: %v %v", code, out)
	}
}

func caseFromEnvForTest(id, sensor string) *Case {
	raw := []byte(escalation(id, sensor))
	var env escalationEnvelope
	json.Unmarshal(raw, &env)
	return caseFromEnvelope(raw, &env)
}

func TestFleetScalePaginationAndFilters(t *testing.T) {
	s, _ := testServer(t)
	seedDemo(s.store, 137)
	s.store.markOffline(90 * time.Second)
	sensors := s.store.ListSensors()
	if len(sensors) != 137 {
		t.Fatalf("expected 137 sensors, got %d", len(sensors))
	}
	h := s.routes()
	get := func(path string) map[string]interface{} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		var out map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	sum := get("/api/summary")["sensors"].(map[string]interface{})
	if sum["online"].(float64)+sum["offline"].(float64) != 137 {
		t.Fatal("summary sensor counts do not add up")
	}
	page1 := get("/api/sensors?status=offline&per_page=25")
	if page1["total"].(float64) == 0 {
		t.Fatal("expected some offline sensors in the demo fleet")
	}
	alerts := get("/api/alerts?status=nowe&per_page=20")
	if alerts["total"].(float64) == 0 {
		t.Fatal("expected new alerts in demo data")
	}
	filtered := get("/api/alerts?sensor=edge-warszawa-1&per_page=200")
	for _, it := range filtered["items"].([]interface{}) {
		if it.(map[string]interface{})["sensor_id"] != "edge-warszawa-1" {
			t.Fatal("sensor filter leaked another sensor")
		}
	}
}
