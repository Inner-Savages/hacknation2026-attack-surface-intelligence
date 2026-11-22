package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// escalationEnvelope mirrors the gate's cascadeEnvelope for intake. The
// console keeps the raw envelope and derives list fields from it.
type escalationEnvelope struct {
	Event struct {
		Time   string          `json:"time"`
		Type   string          `json:"type"`
		IP     string          `json:"ip"`
		Port   int             `json:"port"`
		Proto  string          `json:"proto"`
		Banner json.RawMessage `json:"banner"`
	} `json:"event"`
	EventID    string `json:"event_id"`
	SensorID   string `json:"sensor_id"`
	Forward    bool   `json:"forward"`
	Unresolved bool   `json:"unresolved"`
	Reason     string `json:"reason"`
	Scores     map[string]struct {
		Score float64 `json:"score"`
	} `json:"systemone_scores"`
	Remote *struct {
		Score *float64 `json:"score"`
	} `json:"remote_decision"`
}

func caseFromEnvelope(raw []byte, env *escalationEnvelope) *Case {
	score := 0.0
	for _, m := range env.Scores {
		if m.Score > score {
			score = m.Score
		}
	}
	if env.Remote != nil && env.Remote.Score != nil && *env.Remote.Score > score {
		score = *env.Remote.Score
	}
	target := "—"
	if env.Event.Port > 0 {
		target = env.Event.Proto + ":" + itoa(env.Event.Port)
		if env.Event.Proto == "" {
			target = ":" + itoa(env.Event.Port)
		}
	}
	return &Case{
		EventID: env.EventID, Received: time.Now(), Envelope: append([]byte{}, raw...),
		SensorID: env.SensorID, EventType: env.Event.Type, EventTime: env.Event.Time,
		Source: env.Event.IP, Target: target, Score: score,
		Unresolved: env.Unresolved, Reason: env.Reason, Status: StatusNew,
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

type server struct {
	store    *Store
	token    string
	demoData bool // the store was seeded with synthetic demo cases
	feed     *LiveFeed
	operator string

	aiAuto      bool // flag default: auto AI analysis of new escalations
	aiOpDefault bool // flag default: AI acts as an autonomous operator
	demoDefault bool // flag default: synthetic demo feed active

	auth     *auth
	settings *settings
}

func (s *server) aiClient() *AIClient { return s.settings.aiClient() }

// demoFeedOn reports whether the synthetic demo log generator should run.
// Off means live mode: only real events arriving from the edge.
func (s *server) demoFeedOn() bool {
	if snap := s.settings.snapshot(); snap.DemoFeed != nil {
		return *snap.DemoFeed
	}
	return s.demoDefault
}

// aiOperatorOn reports whether the LLM may act as an autonomous operator.
func (s *server) aiOperatorOn() bool {
	if snap := s.settings.snapshot(); snap.AIOperator != nil {
		return *snap.AIOperator
	}
	return s.aiOpDefault
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	// Public endpoints: account bootstrap and session management.
	mux.HandleFunc("POST /api/register", s.register)
	mux.HandleFunc("POST /api/login", s.loginHandler)
	mux.HandleFunc("POST /api/logout", s.logoutHandler)
	mux.HandleFunc("GET /api/me", s.me)
	// Operator endpoints behind a session.
	mux.Handle("GET /api/summary", s.needAuth(http.HandlerFunc(s.summary)))
	mux.Handle("GET /api/alerts", s.needAuth(http.HandlerFunc(s.alerts)))
	mux.Handle("GET /api/alerts/{id}", s.needAuth(http.HandlerFunc(s.alert)))
	mux.Handle("POST /api/alerts/{id}/status", s.needAuth(http.HandlerFunc(s.setStatus)))
	mux.Handle("POST /api/alerts/{id}/assign", s.needAuth(http.HandlerFunc(s.assign)))
	mux.Handle("POST /api/alerts/{id}/notes", s.needAuth(http.HandlerFunc(s.addNote)))
	mux.Handle("POST /api/alerts/{id}/actions", s.needAuth(http.HandlerFunc(s.action)))
	mux.Handle("POST /api/alerts/{id}/analysis", s.needAuth(http.HandlerFunc(s.analysis)))
	mux.Handle("GET /api/sensors", s.needAuth(http.HandlerFunc(s.sensors)))
	mux.Handle("GET /api/logs", s.needAuth(http.HandlerFunc(s.logs)))
	mux.Handle("GET /api/ai/status", s.needAuth(http.HandlerFunc(s.aiStatus)))
	mux.Handle("GET /api/config", s.needAdmin(http.HandlerFunc(s.getConfig)))
	mux.Handle("POST /api/config", s.needAdmin(http.HandlerFunc(s.setConfig)))
	// Machine intake: bearer token, unchanged contract.
	mux.HandleFunc("POST /events", s.intake)
	mux.HandleFunc("POST /logs", s.intakeLogs)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	return mux
}

// needAuth requires a logged-in operator. Before the first account exists it
// rejects everything but registration, so the UI lands on the setup screen.
func (s *server) needAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.hasUsers() {
			http.Error(w, "setup required", 401)
			return
		}
		if s.auth.who(r) == nil {
			http.Error(w, "authentication required", 401)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *server) needAdmin(h http.Handler) http.Handler {
	return s.needAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sess := s.auth.who(r); sess == nil || !sess.Admin {
			http.Error(w, "admin required", 403)
			return
		}
		h.ServeHTTP(w, r)
	}))
}

// --- accounts --------------------------------------------------------------

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	m := decodeBody(w, r)
	u, err := s.auth.register(m["login"], m["name"], m["password"])
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.feed.Append("status", "", "Zarejestrowano konto operatora "+u.Name+" ("+u.Login+")", nil)
	sess := s.auth.newSession(u)
	setSessionCookie(w, sess)
	writeJSON(w, 200, map[string]interface{}{"login": sess.Login, "name": sess.Name, "admin": sess.Admin})
}

func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	m := decodeBody(w, r)
	sess, err := s.auth.login(m["login"], m["password"])
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	setSessionCookie(w, sess)
	writeJSON(w, 200, map[string]interface{}{"login": sess.Login, "name": sess.Name, "admin": sess.Admin})
}

func (s *server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sotw_session"); err == nil {
		s.auth.logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "sotw_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

// me reports the session state and whether the console needs its first
// account — the UI routes to the setup, login or dashboard screen on it.
func (s *server) me(w http.ResponseWriter, r *http.Request) {
	if sess := s.auth.who(r); sess != nil {
		writeJSON(w, 200, map[string]interface{}{"authenticated": true, "login": sess.Login, "name": sess.Name, "admin": sess.Admin, "has_users": true})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"authenticated": false, "has_users": s.auth.hasUsers()})
}

func setSessionCookie(w http.ResponseWriter, sess *session) {
	http.SetCookie(w, &http.Cookie{
		Name: "sotw_session", Value: sess.Token, Path: "/",
		Expires: sess.Expires, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// intake accepts gate escalations using the same contract as the bundled
// receiver: bearer token, persist-then-202, deduplication by event_id.
func (s *server) intake(w http.ResponseWriter, r *http.Request) {
	if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8*1024*1024))
	if err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	var env escalationEnvelope
	if json.Unmarshal(b, &env) != nil || !env.Forward || env.EventID == "" {
		http.Error(w, "expected escalation envelope", 400)
		return
	}
	if _, err = s.store.AddEscalation(caseFromEnvelope(b, &env)); err != nil {
		http.Error(w, "persistence failed", 503)
		return
	}
	// AI triage of the fresh case, in the background. In operator mode the
	// LLM acts autonomously (audited like a human); otherwise auto-analysis
	// only annotates the case for the human operator.
	if client := s.aiClient(); client != nil {
		if c, ok := s.store.Get(env.EventID); ok {
			switch {
			case s.aiOperatorOn():
				go s.runAIOperator(context.Background(), c)
			case s.aiAuto:
				go func() {
					if _, err := s.analyzeCase(context.Background(), c); err != nil {
						s.feed.Append("ai", env.SensorID, "Autoanaliza AI nie powiodła się: "+err.Error(), nil)
					}
				}()
			}
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

// intakeLogs accepts raw sensor log lines (the passive sensor's NDJSON
// format) for the live feed. A sensor that ships logs is alive, so the
// fleet view is refreshed at the same time.
func (s *server) intakeLogs(w http.ResponseWriter, r *http.Request) {
	if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	logs, raws, err := parseSensorLogs(b)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	sensor := strings.TrimSpace(r.Header.Get("X-Sensor-Id"))
	if sensor == "" {
		sensor = strings.TrimSpace(r.URL.Query().Get("sensor"))
	}
	if sensor == "" {
		sensor = logs[0].Source
	}
	if sensor == "" {
		sensor = "unknown"
	}
	for i, l := range logs {
		s.feed.Append("sensor", sensor, l.line(), raws[i])
	}
	s.store.TouchSensor(sensor)
	w.WriteHeader(http.StatusAccepted)
}

// logs serves the live feed for the dashboard; clients poll with the last
// sequence they rendered.
func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	items, last := s.feed.Since(since, limit)
	writeJSON(w, 200, map[string]interface{}{"items": items, "last_seq": last})
}

func (s *server) aiStatus(w http.ResponseWriter, r *http.Request) {
	client := s.aiClient()
	out := map[string]interface{}{
		"enabled": client != nil, "auto": s.aiAuto && client != nil,
		"operator": s.aiOperatorOn() && client != nil,
		"model":    "", "base_url": "",
	}
	if client != nil {
		out["model"] = client.modelName()
		out["base_url"] = client.baseName()
	}
	writeJSON(w, 200, out)
}

// getConfig returns the persisted runtime configuration. The AI API key is
// never sent back — only whether one is set.
func (s *server) getConfig(w http.ResponseWriter, r *http.Request) {
	snap := s.settings.snapshot()
	writeJSON(w, 200, map[string]interface{}{
		"demo_feed":     s.demoFeedOn(),
		"demo_feed_src": srcOf(snap.DemoFeed),
		"ai_operator":   s.aiOperatorOn(),
		"ai_base_url":   snap.AIBaseURL,
		"ai_model":      snap.AIModel,
		"ai_api_key_set": snap.AIAPIKey != "" || firstNonEmpty(snap.AIAPIKey, "") != "" ||
			len(os.Getenv("ASI_AI_API_KEY")) > 0,
		"ai_base_url_effective": firstNonEmpty(snap.AIBaseURL, os.Getenv("ASI_AI_BASE_URL"), "https://api.openai.com/v1"),
		"ai_model_effective":    firstNonEmpty(snap.AIModel, os.Getenv("ASI_AI_MODEL"), "gpt-4o-mini"),
	})
}

func srcOf(b *bool) string {
	if b != nil {
		return "settings"
	}
	return "flag/env"
}

// setConfig applies runtime configuration from the UI (admin only). Every
// change is mirrored to the live feed, so configuration stays auditable too.
func (s *server) setConfig(w http.ResponseWriter, r *http.Request) {
	var p configPatch
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1*1024*1024))
	if err != nil || json.Unmarshal(b, &p) != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	before := s.settings.snapshot()
	if err := s.settings.update(p); err != nil {
		http.Error(w, "persistence failed", 503)
		return
	}
	sess := s.auth.who(r)
	who := "operator"
	if sess != nil {
		who = sess.Name
	}
	var changes []string
	if p.DemoFeed != nil && (before.DemoFeed == nil || *before.DemoFeed != *p.DemoFeed) {
		if *p.DemoFeed {
			changes = append(changes, "włączono syntetyczny feed demo")
		} else {
			changes = append(changes, "WYŁĄCZONO tryb demo — konsola w trybie live (tylko prawdziwe zdarzenia z edge)")
		}
	}
	if p.AIOperator != nil && (before.AIOperator == nil || *before.AIOperator != *p.AIOperator) {
		if *p.AIOperator {
			changes = append(changes, "włączono autonomicznego operatora AI")
		} else {
			changes = append(changes, "wyłączono autonomicznego operatora AI")
		}
	}
	if p.AIBaseURL != nil && *p.AIBaseURL != before.AIBaseURL {
		changes = append(changes, "zmieniono adres API AI")
	}
	if p.AIModel != nil && *p.AIModel != before.AIModel {
		changes = append(changes, "zmieniono model AI na "+*p.AIModel)
	}
	if p.AIAPIKey != nil && *p.AIAPIKey != "" && *p.AIAPIKey != before.AIAPIKey {
		changes = append(changes, "zaktualizowano klucz API AI")
	}
	if p.AIAPIKey != nil && *p.AIAPIKey == "" && before.AIAPIKey != "" {
		changes = append(changes, "usunięto klucz API AI z ustawień")
	}
	for _, ch := range changes {
		s.feed.Append("status", "", who+": "+ch, nil)
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

// analysis runs an on-demand AI triage of one case against any configured
// OpenAI-compatible provider (hosted or local).
func (s *server) analysis(w http.ResponseWriter, r *http.Request) {
	if s.aiClient() == nil {
		http.Error(w, "analiza AI nie jest skonfigurowana (ustaw ASI_AI_BASE_URL / ASI_AI_API_KEY w środowisku albo w Ustawieniach)", 503)
		return
	}
	c, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	text, err := s.analyzeCase(r.Context(), c)
	if err != nil {
		http.Error(w, "analiza AI nie powiodła się: "+err.Error(), 502)
		return
	}
	writeJSON(w, 200, map[string]string{"analysis": text})
}

// analyzeCase asks the model about one case and records the answer as a note
// and a history entry, so the triage is auditable like any operator action.
func (s *server) analyzeCase(ctx context.Context, c *Case) (string, error) {
	client := s.aiClient()
	if client == nil {
		return "", fmt.Errorf("brak skonfigurowanego dostawcy AI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	logs := s.feed.matching(c, 40)
	text, err := client.analyze(ctx, c.Envelope, logs)
	if err != nil {
		return "", err
	}
	who := "AI · " + client.modelName()
	err = s.store.mutate(c.EventID, func(c *Case) (HistoryEntry, error) {
		c.Notes = append(c.Notes, Note{At: time.Now(), Actor: who, Text: text})
		return HistoryEntry{At: time.Now(), Kind: "ai", Actor: who, Text: "Analiza AI — zapisano ocenę w notatkach sprawy"}, nil
	})
	if err != nil {
		return "", err
	}
	return text, nil
}

func (s *server) summary(w http.ResponseWriter, r *http.Request) {
	cards := map[string]int{}
	for _, st := range caseStatuses {
		cards[st] = 0
	}
	online, offline := 0, 0
	for _, sen := range s.store.ListSensors() {
		for st, n := range sen.Counts {
			cards[st] += n
		}
		if sen.Online {
			online++
		} else {
			offline++
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"cards": cards, "updated_at": time.Now().Format(time.RFC3339),
		"sensors": map[string]int{"total": online + offline, "online": online, "offline": offline},
		"demo":    s.demoData,
		"live":    !s.demoFeedOn(),
	})
}

type caseSummary struct {
	EventID    string    `json:"event_id"`
	Received   time.Time `json:"received"`
	EventTime  string    `json:"event_time"`
	SensorID   string    `json:"sensor_id"`
	EventType  string    `json:"event_type"`
	Source     string    `json:"source"`
	Target     string    `json:"target"`
	Score      float64   `json:"score"`
	Unresolved bool      `json:"unresolved"`
	Reason     string    `json:"reason"`
	Status     string    `json:"status"`
	Assignee   string    `json:"assignee,omitempty"`
}

func summarize(c *Case) caseSummary {
	return caseSummary{c.EventID, c.Received, c.EventTime, c.SensorID, c.EventType, c.Source, c.Target, c.Score, c.Unresolved, c.Reason, c.Status, c.Assignee}
}

func (s *server) alerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status, sensor, typ, search := q.Get("status"), q.Get("sensor"), q.Get("type"), strings.ToLower(q.Get("q"))
	page, perPage := 1, 20
	if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
		page = v
	}
	if v, err := strconv.Atoi(q.Get("per_page")); err == nil && v > 0 && v <= 200 {
		perPage = v
	}
	var filtered []caseSummary
	filtered = []caseSummary{}
	for _, c := range s.store.ListCases() {
		if status != "" && c.Status != status {
			continue
		}
		if sensor != "" && c.SensorID != sensor {
			continue
		}
		if typ != "" && c.EventType != typ {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(c.Source+" "+c.Target+" "+c.EventType+" "+c.Reason+" "+c.SensorID), search) {
			continue
		}
		filtered = append(filtered, summarize(c))
	}
	total := len(filtered)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	writeJSON(w, 200, map[string]interface{}{"items": filtered[start:end], "total": total, "page": page, "per_page": perPage})
}

func (s *server) alert(w http.ResponseWriter, r *http.Request) {
	c, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	var envelope interface{}
	json.Unmarshal(c.Envelope, &envelope)
	writeJSON(w, 200, map[string]interface{}{"case": summarize(c), "notes": c.Notes, "history": c.History, "actions": c.Actions, "pending_action": c.PendingAction, "envelope": envelope})
}

func (s *server) actor(r *http.Request, body map[string]string) string {
	// A logged-in session is authoritative for who acts from the UI.
	if sess := s.auth.who(r); sess != nil {
		return sess.Name
	}
	if a := strings.TrimSpace(body["actor"]); a != "" {
		return a
	}
	if s.operator != "" {
		return s.operator
	}
	return "operator"
}

func decodeBody(w http.ResponseWriter, r *http.Request) map[string]string {
	var raw map[string]interface{}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1*1024*1024))
	if err != nil || json.Unmarshal(b, &raw) != nil {
		return map[string]string{}
	}
	m := map[string]string{}
	for k, v := range raw {
		switch t := v.(type) {
		case string:
			m[k] = t
		case bool:
			m[k] = strconv.FormatBool(t)
		}
	}
	return m
}

func (s *server) setStatus(w http.ResponseWriter, r *http.Request) {
	m := decodeBody(w, r)
	st := m["status"]
	if !validStatus(st) {
		http.Error(w, "unknown status", 400)
		return
	}
	a := s.actor(r, m)
	err := s.store.mutate(r.PathValue("id"), func(c *Case) (HistoryEntry, error) {
		old := c.Status
		c.Status = st
		return HistoryEntry{At: time.Now(), Kind: "status", Actor: a, Text: "Status: " + labelStatus(old) + " → " + labelStatus(st)}, nil
	})
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (s *server) assign(w http.ResponseWriter, r *http.Request) {
	m := decodeBody(w, r)
	who := strings.TrimSpace(m["assignee"])
	if who == "" {
		http.Error(w, "assignee required", 400)
		return
	}
	a := s.actor(r, m)
	err := s.store.mutate(r.PathValue("id"), func(c *Case) (HistoryEntry, error) {
		c.Assignee = who
		return HistoryEntry{At: time.Now(), Kind: "assign", Actor: a, Text: "Przypisano do " + who}, nil
	})
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (s *server) addNote(w http.ResponseWriter, r *http.Request) {
	m := decodeBody(w, r)
	text := strings.TrimSpace(m["text"])
	if text == "" {
		http.Error(w, "note text required", 400)
		return
	}
	a := s.actor(r, m)
	err := s.store.mutate(r.PathValue("id"), func(c *Case) (HistoryEntry, error) {
		c.Notes = append(c.Notes, Note{At: time.Now(), Actor: a, Text: text})
		return HistoryEntry{At: time.Now(), Kind: "note", Actor: a, Text: "Notatka: " + text}, nil
	})
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

var validActions = map[string]string{
	"observe":   "Wzmocniono obserwację hosta",
	"scan":      "Zlecono aktywny skan hosta",
	"reanalyze": "Ponowiono analizę modeli",
	"isolate":   "Odetnij hosta od sieci",
	"reconnect": "Przywrócono hosta do sieci",
}

// action implements two-step execution for destructive actions. The first
// request arms the action; only a second request with confirm=true records
// execution. In demo mode nothing touches real traffic — the record is the
// audit trail for the human decision.
func (s *server) action(w http.ResponseWriter, r *http.Request) {
	m := decodeBody(w, r)
	act := m["action"]
	label, ok := validActions[act]
	if !ok {
		http.Error(w, "unknown action", 400)
		return
	}
	a := s.actor(r, m)
	confirm := m["confirm"] == "true"
	if act == "isolate" && !confirm {
		err := s.store.mutate(r.PathValue("id"), func(c *Case) (HistoryEntry, error) {
			c.PendingAction = act
			return HistoryEntry{At: time.Now(), Kind: "action", Actor: a, Text: label + " — oczekuje na potwierdzenie"}, nil
		})
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"state": "confirmation_required", "message": "Akcja dwustopniowa: potwierdź odcięcie hosta od sieci."})
		return
	}
	err := s.store.mutate(r.PathValue("id"), func(c *Case) (HistoryEntry, error) {
		if act == "isolate" && c.PendingAction != "isolate" {
			return HistoryEntry{}, errConfirmRequired
		}
		c.PendingAction = ""
		c.Actions = append(c.Actions, ActionRecord{At: time.Now(), Action: act, Actor: a, Executed: true})
		text := label
		if s.demoData {
			text += " (tryb demo — ruch sieciowy niezmieniony)"
		}
		return HistoryEntry{At: time.Now(), Kind: "action", Actor: a, Text: text}, nil
	})
	if err == errConfirmRequired {
		http.Error(w, "isolate requires the two-step confirmation", 409)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	writeJSON(w, 200, map[string]interface{}{"state": "executed", "demo": s.demoData})
}

var errConfirmRequired = errString("confirmation required")

type errString string

func (e errString) Error() string { return string(e) }

func labelStatus(s string) string {
	switch s {
	case StatusNew:
		return "Nowy"
	case StatusVerify:
		return "Do weryfikacji"
	case StatusConfirmed:
		return "Potwierdzony"
	case StatusFalseAlarm:
		return "Fałszywy alarm"
	case StatusClosed:
		return "Zamknięty"
	}
	return s
}

func (s *server) sensors(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search, status := strings.ToLower(q.Get("q")), q.Get("status")
	page, perPage := 1, 25
	if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
		page = v
	}
	if v, err := strconv.Atoi(q.Get("per_page")); err == nil && v > 0 && v <= 200 {
		perPage = v
	}
	filtered := []*Sensor{}
	for _, sen := range s.store.ListSensors() {
		if status == "online" && !sen.Online {
			continue
		}
		if status == "offline" && sen.Online {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(sen.ID), search) {
			continue
		}
		filtered = append(filtered, sen)
	}
	total := len(filtered)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	writeJSON(w, 200, map[string]interface{}{"items": filtered[start:end], "total": total, "page": page, "per_page": perPage})
}
