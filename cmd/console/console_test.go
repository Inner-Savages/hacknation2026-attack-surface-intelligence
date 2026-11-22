package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testServer builds a console with one registered admin and returns the
// session cookie used to authenticate operator API calls.
func testServer(t *testing.T) (*server, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := openAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := openSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.register("janek", "Janek Baumgart", "testowe1")
	if err != nil {
		t.Fatal(err)
	}
	sess := a.newSession(u)
	s := &server{
		store: store, token: "test-token", demoData: true, feed: newLiveFeed(100),
		operator: "Janek Baumgart", aiAuto: true,
		auth: a, settings: st,
	}
	return s, httptest.NewServer(s.routes()), sess.Token
}

// withAuth adds the session cookie to an API request.
func withAuth(r *http.Request, token string) *http.Request {
	r.AddCookie(&http.Cookie{Name: "sotw_session", Value: token})
	return r
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
	s, _, _ := testServer(t)
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
	s, _, tok := testServer(t)
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e2", "edge-b-2")); err != nil {
		t.Fatal(err)
	}
	h := s.routes()
	call := func(path string, body map[string]string) (int, map[string]interface{}) {
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", path, bytes.NewReader(b)), tok))
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
	// A cut-off host can be restored to the network, single-step, audited.
	code, out = call("/api/alerts/e2/actions", map[string]string{"action": "reconnect", "actor": "A. Lis"})
	if code != 200 || out["state"] != "executed" {
		t.Fatalf("reconnect failed: %v %v", code, out)
	}
	c, _ := s.store.Get("e2")
	if c.Status != StatusVerify || len(c.Notes) != 1 || len(c.Actions) != 2 || c.PendingAction != "" {
		t.Fatalf("bad final case: %+v", c)
	}
	if c.Actions[1].Action != "reconnect" {
		t.Fatalf("reconnect was not recorded: %+v", c.Actions)
	}
	var kinds []string
	for _, h := range c.History {
		kinds = append(kinds, h.Kind)
	}
	if strings.Join(kinds, ",") != "alert,status,note,action,action,action" {
		t.Fatalf("unexpected history: %v", kinds)
	}
}

// The UI sends confirm as a JSON boolean; decoding must not drop the action.
func TestActionAcceptsBooleanConfirm(t *testing.T) {
	s, _, tok := testServer(t)
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e3", "edge-c-3")); err != nil {
		t.Fatal(err)
	}
	h := s.routes()
	raw := func(body string) (int, map[string]interface{}) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/alerts/e3/actions", strings.NewReader(body)), tok))
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
	s, _, _ := testServer(t)
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

	s, _, tok := testServer(t)
	s.settings.AIBaseURL = fake.URL + "/v1"
	s.settings.AIAPIKey = "test-key"
	s.settings.AIModel = "test-model"
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e9", "edge-lab-1")); err != nil {
		t.Fatal(err)
	}
	s.feed.Append("sensor", "edge-lab-1", "service_silent 172.28.0.30", nil)
	h := s.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/alerts/e9/analysis", nil), tok))
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
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/ai/status", nil), tok))
	var st map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &st)
	if st["enabled"] != true || st["model"] != "test-model" {
		t.Fatalf("bad ai status: %v", st)
	}
	// Without a configured provider the endpoint degrades gracefully.
	s2, _, tok2 := testServer(t)
	w2 := httptest.NewRecorder()
	s2.routes().ServeHTTP(w2, withAuth(httptest.NewRequest("POST", "/api/alerts/e9/analysis", nil), tok2))
	if w2.Code != 503 {
		t.Fatalf("expected 503 without provider, got %d", w2.Code)
	}
}

// UI actions run under the logged-in operator's identity, regardless of the
// actor field sent by the client.
func TestOperatorNameIsDefaultActor(t *testing.T) {
	s, _, tok := testServer(t)
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e10", "edge-x-1")); err != nil {
		t.Fatal(err)
	}
	h := s.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/alerts/e10/status", strings.NewReader(`{"status":"do_weryfikacji"}`)), tok))
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
	s, _, tok := testServer(t)
	seedDemo(s.store, 137)
	s.store.markOffline(90 * time.Second)
	sensors := s.store.ListSensors()
	if len(sensors) != 137 {
		t.Fatalf("expected 137 sensors, got %d", len(sensors))
	}
	h := s.routes()
	get := func(path string) map[string]interface{} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", path, nil), tok))
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

// Registration, login, session protection and logout.
func TestAuthFlow(t *testing.T) {
	dir := t.TempDir()
	store, _ := openStore(dir)
	a, _ := openAuth(dir)
	st, _ := openSettings(dir)
	s := &server{store: store, token: "tok", feed: newLiveFeed(10), auth: a, settings: st}
	h := s.routes()

	// Before the first account, operator APIs are locked (setup required).
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/summary", nil))
	if w.Code != 401 {
		t.Fatalf("expected 401 before setup, got %d", w.Code)
	}
	postAuth := func(path string, body string) (*httptest.ResponseRecorder, []*http.Cookie) {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w, w.Result().Cookies()
	}
	// First registered operator becomes the admin and gets a session cookie.
	w, cookies := postAuth("/api/register", `{"login":"janek","name":"Janek Baumgart","password":"sekret1"}`)
	if w.Code != 200 || len(cookies) == 0 {
		t.Fatalf("register failed: %d %s", w.Code, w.Body.String())
	}
	if !a.users["janek"].Admin {
		t.Fatal("first operator must be admin")
	}
	// Weak and duplicate registrations are rejected.
	if w, _ = postAuth("/api/register", `{"login":"ab","name":"X Y","password":"sekret1"}`); w.Code != 400 {
		t.Fatal("accepted a short login")
	}
	if w, _ = postAuth("/api/register", `{"login":"janek","name":"Kto Inny","password":"sekret1"}`); w.Code != 400 {
		t.Fatal("accepted a duplicate login")
	}
	// A protected endpoint rejects anonymous and accepts the session.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/summary", nil))
	if w.Code != 401 {
		t.Fatal("anonymous request reached a protected endpoint")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/summary", nil), cookies[0].Value))
	if w.Code != 200 {
		t.Fatalf("session rejected: %d", w.Code)
	}
	// Wrong password fails, right password logs in.
	if w, _ = postAuth("/api/login", `{"login":"janek","password":"zle"}`); w.Code != 401 {
		t.Fatal("accepted a wrong password")
	}
	w, cookies2 := postAuth("/api/login", `{"login":"janek","password":"sekret1"}`)
	if w.Code != 200 || len(cookies2) == 0 {
		t.Fatalf("login failed: %d", w.Code)
	}
	// Logout kills the session.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/logout", nil), cookies2[0].Value))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/summary", nil), cookies2[0].Value))
	if w.Code != 401 {
		t.Fatal("session survived logout")
	}
	// Accounts survive a restart (users.json persisted).
	a2, err := openAuth(dir)
	if err != nil || !a2.hasUsers() {
		t.Fatal("accounts were not persisted")
	}
}

// The settings screen switches demo/live mode and configures the AI provider
// — including the API key — without a restart; the key never leaks back.
func TestConfigFromUI(t *testing.T) {
	s, _, tok := testServer(t)
	h := s.routes()
	call := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withAuth(httptest.NewRequest(method, path, strings.NewReader(body)), tok))
		return w
	}
	// Demo feed is on by default in demo mode; the toggle switches to live.
	s.demoDefault = true
	if !s.demoFeedOn() {
		t.Fatal("demo feed should default to on in demo mode")
	}
	if w := call("POST", "/api/config", `{"demo_feed":false}`); w.Code != 200 {
		t.Fatalf("config update failed: %s", w.Body.String())
	}
	if s.demoFeedOn() {
		t.Fatal("demo feed did not switch off")
	}
	// The change is persisted.
	st2, _ := openSettings(s.store.dir)
	if st2.DemoFeed == nil || *st2.DemoFeed != false {
		t.Fatal("demo_feed was not persisted")
	}
	// AI provider fully configurable from the UI; the key is write-only.
	w := call("POST", "/api/config", `{"ai_base_url":"http://127.0.0.1:11434/v1","ai_model":"llama3.2","ai_api_key":"sekretny-klucz"}`)
	if w.Code != 200 {
		t.Fatalf("AI config failed: %s", w.Body.String())
	}
	client := s.aiClient()
	if client == nil || client.baseURL != "http://127.0.0.1:11434/v1" || client.model != "llama3.2" || client.apiKey != "sekretny-klucz" {
		t.Fatalf("settings did not drive the AI client: %+v", client)
	}
	w = call("GET", "/api/config", ``)
	body := w.Body.String()
	if strings.Contains(body, "sekretny-klucz") {
		t.Fatal("API key leaked in the config response")
	}
	var cfg map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if cfg["ai_api_key_set"] != true || cfg["demo_feed"] != false {
		t.Fatalf("bad config view: %v", cfg)
	}
	// Config changes are mirrored into the live feed for auditability.
	items, _ := s.feed.Since(0, 100)
	var sawLive bool
	for _, e := range items {
		if strings.Contains(e.Text, "trybie live") {
			sawLive = true
		}
	}
	if !sawLive {
		t.Fatal("config change was not mirrored to the live feed")
	}
	// Non-admin operators cannot change configuration.
	u, _ := s.auth.register("ania", "Anna Lis", "haslo123")
	sess := a2Session(s.auth, u)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/config", strings.NewReader(`{"demo_feed":true}`)), sess))
	if w.Code != 403 {
		t.Fatalf("non-admin changed config: %d", w.Code)
	}
}

func a2Session(a *auth, u *user) string { return a.newSession(u).Token }

// Admins manage operators: promotion works, demotion of the last admin is
// refused, and changes apply to live sessions immediately.
func TestOperatorAdminManagement(t *testing.T) {
	s, _, tok := testServer(t) // janek is the seeded admin
	h := s.routes()
	u, err := s.auth.register("ania", "Anna Lis", "haslo123")
	if err != nil {
		t.Fatal(err)
	}
	aniaTok := a2Session(s.auth, u)
	// Ania is not an admin: config is out of reach.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/config", nil), aniaTok))
	if w.Code != 403 {
		t.Fatalf("expected 403 for non-admin, got %d", w.Code)
	}
	// The last admin cannot demote themselves.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/users/janek/admin", strings.NewReader(`{"admin":false}`)), tok))
	if w.Code != 400 {
		t.Fatalf("demoted the last admin: %d", w.Code)
	}
	// Promote Ania; her existing session gains the flag at once.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/users/ania/admin", strings.NewReader(`{"admin":true}`)), tok))
	if w.Code != 200 {
		t.Fatalf("promotion failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/config", nil), aniaTok))
	if w.Code != 200 {
		t.Fatalf("promoted operator still locked out: %d", w.Code)
	}
	// The users list reflects the change and promotion persisted.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/users", nil), tok))
	var list struct {
		Items []struct {
			Login string `json:"login"`
			Admin bool   `json:"admin"`
		} `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	admins := 0
	for _, it := range list.Items {
		if it.Admin {
			admins++
		}
	}
	if admins != 2 {
		t.Fatalf("expected 2 admins, got %d (%+v)", admins, list.Items)
	}
	a2, err := openAuth(s.store.dir)
	if err != nil || !a2.users["ania"].Admin {
		t.Fatal("admin flag was not persisted")
	}

	// Account deletion: removes the user and their sessions, refuses the
	// last admin and self-deletion while logged in.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("DELETE", "/api/users/janek", nil), tok))
	if w.Code != 400 {
		t.Fatalf("self-deletion while logged in accepted: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("DELETE", "/api/users/ania", nil), tok))
	if w.Code != 200 {
		t.Fatalf("delete failed: %d %s", w.Code, w.Body.String())
	}
	if _, ok := s.auth.users["ania"]; ok {
		t.Fatal("account survived deletion")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/summary", nil), aniaTok))
	if w.Code != 401 {
		t.Fatal("deleted account's session still works")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("DELETE", "/api/users/janek", nil), aniaTok))
	if w.Code != 401 && w.Code != 403 {
		t.Fatalf("expected auth failure for deleted operator, got %d", w.Code)
	}
}

// Switching to live mode purges the synthetic fleet: demo cases and sensors
// disappear from memory and disk, real cases stay, and the summary stops
// reporting demo content.
func TestLiveSwitchPurgesDemoData(t *testing.T) {
	s, _, tok := testServer(t)
	s.demoDefault = true
	seedDemo(s.store, 137)
	// A real case that arrived over the wire must survive the purge.
	if _, err := s.store.AddEscalation(caseFromEnvForTest("real-1", "lab")); err != nil {
		t.Fatal(err)
	}
	before := len(s.store.ListCases())
	if before < 100 {
		t.Fatalf("demo seed too small for the test: %d", before)
	}
	h := s.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("POST", "/api/config", strings.NewReader(`{"demo_feed":false}`)), tok))
	if w.Code != 200 {
		t.Fatalf("config update failed: %s", w.Body.String())
	}
	cases := s.store.ListCases()
	if len(cases) != 1 {
		t.Fatalf("expected only the real case after purge, got %d", len(cases))
	}
	if cases[0].EventID != "real-1" {
		t.Fatalf("real case was purged: %+v", cases[0])
	}
	for _, sen := range s.store.ListSensors() {
		if isDemoSensorID(sen.ID) {
			t.Fatalf("demo sensor survived the purge: %s", sen.ID)
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.store.dir, "cases"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("demo case files left on disk: %v (%d)", err, len(entries))
	}
	// Summary flips to live without a demo badge.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(httptest.NewRequest("GET", "/api/summary", nil), tok))
	var sum map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &sum)
	if sum["demo"] != false || sum["live"] != true {
		t.Fatalf("summary still reports demo content: %v", sum)
	}
	if sum["sensors"].(map[string]interface{})["total"].(float64) != 1 {
		t.Fatalf("fleet was not rebuilt: %v", sum["sensors"])
	}
}

// The AI operator triages a case end to end: threat assessment, status,
// note and a safe action — all audited. Isolation is only armed, never
// executed by the AI.
func TestAIOperatorDecision(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{{"message": map[string]string{
				"role":    "assistant",
				"content": `{"threat":"medium","status":"potwierdzony","note":"Host zniknął z sieci tuż po zmianie usługi na porcie 22 — podejrzana sekwencja.","action":"observe","confidence":"średnia"}`,
			}}},
		})
	}))
	defer fake.Close()

	s, _, _ := testServer(t)
	s.settings.AIBaseURL = fake.URL + "/v1"
	s.settings.AIAPIKey = "k"
	s.settings.AIModel = "op-model"
	on := true
	s.settings.AIOperator = &on
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e21", "edge-op-1")); err != nil {
		t.Fatal(err)
	}
	c, _ := s.store.Get("e21")
	s.runAIOperator(context.Background(), c)

	c, _ = s.store.Get("e21")
	if c.Status != StatusConfirmed {
		t.Fatalf("AI operator did not set the status: %s", c.Status)
	}
	if len(c.Actions) != 1 || c.Actions[0].Action != "observe" || c.Actions[0].Actor != "AI · op-model (operator)" {
		t.Fatalf("AI action not audited: %+v", c.Actions)
	}
	if len(c.Notes) != 1 || !strings.Contains(c.Notes[0].Text, "OCENA ZAGROŻENIA: średnie") {
		t.Fatalf("missing threat note: %+v", c.Notes)
	}
	last := c.History[len(c.History)-1]
	if last.Kind != "ai" || last.Actor != "AI · op-model (operator)" {
		t.Fatalf("missing operator history entry: %+v", last)
	}

	// Isolation is armed for a human, never executed by the AI.
	fake2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{{"message": map[string]string{
				"role":    "assistant",
				"content": `{"threat":"high","status":"potwierdzony","note":"Aktywne skanowanie z sąsiedniego hosta.","action":"isolate","confidence":"wysoka"}`,
			}}},
		})
	}))
	defer fake2.Close()
	s.settings.AIBaseURL = fake2.URL + "/v1"
	if _, err := s.store.AddEscalation(caseFromEnvForTest("e22", "edge-op-1")); err != nil {
		t.Fatal(err)
	}
	c2, _ := s.store.Get("e22")
	s.runAIOperator(context.Background(), c2)
	c2, _ = s.store.Get("e22")
	if c2.PendingAction != "isolate" {
		t.Fatal("AI isolate was not armed for human confirmation")
	}
	for _, a := range c2.Actions {
		if a.Action == "isolate" {
			t.Fatal("AI executed isolation without a human")
		}
	}
}
