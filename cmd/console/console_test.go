package main

import (
	"bytes"
	"encoding/json"
	"net/http"
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
	s := &server{store: store, token: "test-token", demo: true, feed: newLiveFeed(100), operator: "Janek Baumgart"}
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

// The passive sensor ships NDJSON lines; the console feeds them to the live
// dashboard and treats the sender as alive.
func TestSensorLogIntakeFeedsDashboardAndLiveness(t *testing.T) {
	s, _ := testServer(t)
	h := s.routes()
	body := `{"time":"2026-11-21T17:28:55.812537553+01:00","type":"service_silent","ip":"172.28.0.30","port":80,"proto":"tcp","source":"passive"}
{"time":"2026-11-21T17:29:00.812662051+01:00","type":"host_silent","ip":"172.28.0.1","source":"passive"}
{"time":"2026-11-21T17:29:00.812662051+01:00","type":"host_silent","ip":"172.28.0.30","source":"passive"}`
	call := func(b, token, sensor string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/logs", strings.NewReader(b))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if sensor != "" {
			r.Header.Set("X-Sensor-Id", sensor)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if call(body, "", "edge-lab-1").Code != 401 {
		t.Fatal("log intake accepted without token")
	}
	if call(body, "test-token", "edge-lab-1").Code != 202 {
		t.Fatal("log intake rejected valid NDJSON")
	}
	// A single JSON object is accepted too, with the sensor id taken from source.
	single := `{"time":"2026-11-21T17:29:05Z","type":"host_new","ip":"172.28.0.41","source":"edge-lab-2"}`
	if call(single, "test-token", "").Code != 202 {
		t.Fatal("log intake rejected a single object")
	}
	items, last := s.feed.Since(0, 100)
	if len(items) != 4 || last != 4 {
		t.Fatalf("expected 4 feed entries, got %d (last %d)", len(items), last)
	}
	if items[0].Kind != "sensor" || items[0].Sensor != "edge-lab-1" || items[0].Text != "service_silent 172.28.0.30:80/tcp" {
		t.Fatalf("bad first entry: %+v", items[0])
	}
	if items[1].Text != "host_silent 172.28.0.1" {
		t.Fatalf("bad second entry: %+v", items[1])
	}
	if !strings.Contains(string(items[0].Raw), `"service_silent"`) {
		t.Fatal("raw payload was not preserved")
	}
	if items[3].Sensor != "edge-lab-2" {
		t.Fatalf("sensor id was not derived from source: %+v", items[3])
	}
	// Both senders are now visible as online sensors.
	found := map[string]bool{}
	for _, sen := range s.store.ListSensors() {
		found[sen.ID] = sen.Online
	}
	if !found["edge-lab-1"] || !found["edge-lab-2"] {
		t.Fatalf("log intake did not mark sensors online: %v", found)
	}
	// Incremental polling returns only new entries.
	items, _ = s.feed.Since(2, 100)
	if len(items) != 2 {
		t.Fatalf("since=2 should return 2 entries, got %d", len(items))
	}
	if call(`{"type":"bogus"}`, "test-token", "x").Code != 400 {
		t.Fatal("accepted a malformed log line")
	}
}

// The AI analysis endpoint works against any OpenAI-compatible provider; the
// answer is recorded as an auditable note and history entry.
func TestAIAnalysisWithFakeProvider(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing bearer auth")
		}
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		if req["model"] != "test-model" {
			t.Errorf("unexpected model %v", req["model"])
		}
		msgs := req["messages"].([]interface{})
		user := msgs[1].(map[string]interface{})["content"].(string)
		if !strings.Contains(user, "remote_rank_max") || !strings.Contains(user, "service_silent 172.28.0.30") {
			t.Errorf("prompt misses envelope or sensor logs")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{{"message": map[string]string{"role": "assistant", "content": "OCENA: test\nPEWNOŚĆ: wysoka\nREKOMENDACJA: obserwacja"}}},
		})
	}))
	defer fake.Close()

	s, _ := testServer(t)
	s.ai = &AIClient{baseURL: fake.URL + "/v1", apiKey: "test-key", model: "test-model", http: fake.Client()}
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e9", "edge-lab-1")); err != nil {
		t.Fatal(err)
	}
	s.feed.Append("sensor", "edge-lab-1", "service_silent 172.28.0.30", nil)
	h := s.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/alerts/e9/analysis", nil))
	if w.Code != 200 {
		t.Fatalf("analysis failed: %d %s", w.Code, w.Body.String())
	}
	c, _ := s.store.Get("e9")
	if len(c.Notes) != 1 || c.Notes[0].Actor != "AI · test-model" || !strings.Contains(c.Notes[0].Text, "REKOMENDACJA") {
		t.Fatalf("analysis was not stored as a note: %+v", c.Notes)
	}
	last := c.History[len(c.History)-1]
	if last.Kind != "ai" || last.Actor != "AI · test-model" {
		t.Fatalf("missing ai history entry: %+v", last)
	}
	// AI status reports the configured provider.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/ai/status", nil))
	var st map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &st)
	if st["enabled"] != true || st["model"] != "test-model" {
		t.Fatalf("bad ai status: %v", st)
	}
	// Without a configured provider the endpoint degrades gracefully.
	s2, _ := testServer(t)
	w2 := httptest.NewRecorder()
	s2.routes().ServeHTTP(w2, httptest.NewRequest("POST", "/api/alerts/e9/analysis", nil))
	if w2.Code != 503 {
		t.Fatalf("expected 503 without provider, got %d", w2.Code)
	}
}

// UI actions without an explicit actor are recorded under the configured
// operator name.
func TestOperatorNameIsDefaultActor(t *testing.T) {
	s, _ := testServer(t)
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e10", "edge-x-1")); err != nil {
		t.Fatal(err)
	}
	h := s.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/alerts/e10/status", strings.NewReader(`{"status":"do_weryfikacji"}`)))
	if w.Code != 200 {
		t.Fatalf("status change failed: %d", w.Code)
	}
	c, _ := s.store.Get("e10")
	last := c.History[len(c.History)-1]
	if last.Actor != "Janek Baumgart" {
		t.Fatalf("expected default operator actor, got %q", last.Actor)
	}
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
