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
	rules    *ruleStore
	gt       *groundTruth
	inv      *inventory
	exposure *exposureCheck
	tlsMon   *tlsMonitor

	roles *roleStore
	audit *auditLog

	// registrationClosed turns off self-service sign-up (ASI_ALLOW_REGISTRATION=false).
	// The very first account can still be created while no user exists.
	registrationClosed bool
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

// ruleModeOn reports whether the deterministic rule engine replaces the
// model stack for triage. Default is off — models are the primary path.
func (s *server) ruleModeOn() bool {
	if snap := s.settings.snapshot(); snap.RuleMode != nil {
		return *snap.RuleMode
	}
	return false
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
	mux.Handle("POST /api/alerts/{id}/operator", s.needAuth(http.HandlerFunc(s.operatorRun)))
	mux.Handle("GET /api/sensors", s.needAuth(http.HandlerFunc(s.sensors)))
	mux.Handle("GET /api/logs", s.needAuth(http.HandlerFunc(s.logs)))
	mux.Handle("GET /api/ai/status", s.needAuth(http.HandlerFunc(s.aiStatus)))
	mux.Handle("GET /api/rules", s.needAuth(http.HandlerFunc(s.listRules)))
	mux.Handle("PUT /api/rules", s.needAdmin(http.HandlerFunc(s.putRules)))
	mux.Handle("POST /api/rules/apply", s.needAdmin(http.HandlerFunc(s.applyRulesHandler)))
	mux.Handle("GET /api/config", s.needAdmin(http.HandlerFunc(s.getConfig)))
	mux.Handle("POST /api/config", s.needAdmin(http.HandlerFunc(s.setConfig)))
	mux.Handle("GET /api/groundtruth", s.needAuth(http.HandlerFunc(s.groundTruthStatus)))
	mux.Handle("POST /api/groundtruth/run", s.needAdmin(http.HandlerFunc(s.groundTruthRun)))
	mux.Handle("GET /api/map", s.needAuth(http.HandlerFunc(s.attackMap)))
	mux.Handle("GET /api/exposure", s.needAuth(http.HandlerFunc(s.exposureStatus)))
	mux.Handle("POST /api/exposure/run", s.needAdmin(http.HandlerFunc(s.exposureRun)))
	mux.Handle("GET /api/tls", s.needAuth(http.HandlerFunc(s.tlsStatus)))
	mux.Handle("POST /api/tls/run", s.needAdmin(http.HandlerFunc(s.tlsRun)))
	mux.Handle("GET /api/users", s.needAdmin(http.HandlerFunc(s.users)))
	mux.Handle("POST /api/users/{login}/admin", s.needAdmin(http.HandlerFunc(s.setUserAdmin)))
	mux.Handle("DELETE /api/users/{login}", s.needAdmin(http.HandlerFunc(s.deleteUser)))
	s.registerInventoryRoutes(mux)
	// Machine intake: bearer token, unchanged contract.
	mux.HandleFunc("POST /events", s.intake)
	mux.HandleFunc("POST /logs", s.intakeLogs)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	s.registerRBACRoutes(mux)
	return s.rbac(mux)
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
		// Permission checks live in the RBAC wrapper (rbac.go).
		h.ServeHTTP(w, r)
	}))
}

// --- accounts --------------------------------------------------------------

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if s.registrationClosed && s.auth.hasUsers() {
		http.Error(w, "registration is disabled", 403)
		return
	}
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
		writeJSON(w, 200, map[string]interface{}{"authenticated": true, "login": sess.Login, "name": sess.Name, "admin": sess.Admin, "has_users": true, "registration_open": !s.registrationClosed})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"authenticated": false, "has_users": s.auth.hasUsers(), "registration_open": !s.registrationClosed || !s.auth.hasUsers()})
}

// users lists operator accounts for the admin's settings panel.
func (s *server) users(w http.ResponseWriter, r *http.Request) {
	items := []map[string]interface{}{}
	for _, u := range s.auth.list() {
		items = append(items, map[string]interface{}{
			"login": u.Login, "name": u.Name, "admin": u.Admin, "created_at": u.CreatedAt,
		})
	}
	writeJSON(w, 200, map[string]interface{}{"items": items})
}

// setUserAdmin grants or revokes admin rights; the change is audited in the
// live feed like any other operator-visible event.
func (s *server) setUserAdmin(w http.ResponseWriter, r *http.Request) {
	m := decodeBody(w, r)
	login := r.PathValue("login")
	grant := m["admin"] == "true"
	if err := s.auth.setAdmin(login, grant); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	who := "operator"
	if sess := s.auth.who(r); sess != nil {
		who = sess.Name
	}
	verb := "odebrał(a) uprawnienia administratora operatorowi "
	if grant {
		verb = "nadał(a) uprawnienia administratora operatorowi "
	}
	s.feed.Append("status", "", who+": "+verb+login, nil)
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

// deleteUser removes an operator account and kills its sessions.
func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	login := r.PathValue("login")
	if sess := s.auth.who(r); sess != nil && sess.Login == login {
		http.Error(w, "nie możesz usunąć własnego konta będąc zalogowanym", 400)
		return
	}
	if err := s.auth.delete(login); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	who := "operator"
	if sess := s.auth.who(r); sess != nil {
		who = sess.Name
	}
	s.feed.Append("status", "", who+": usunął(a) konto operatora "+login, nil)
	writeJSON(w, 200, map[string]string{"ok": "true"})
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
	created, err := s.store.AddEscalation(caseFromEnvelope(b, &env))
	if err != nil {
		http.Error(w, "persistence failed", 503)
		return
	}
	// AI triage of the fresh case, in the background (duplicates are only
	// acknowledged, never triaged twice).
	if created {
		s.triageNewCase(env.SensorID, env.EventID)
	}
	w.WriteHeader(http.StatusAccepted)
}

// triageNewCase routes a freshly created case to the active triage path.
// Rule mode wins: when the models digest too slowly, the operator can fall
// back to hard rules and the case never waits on any model at all.
func (s *server) triageNewCase(sensorID, eventID string) {
	c, ok := s.store.Get(eventID)
	if !ok {
		return
	}
	if s.ruleModeOn() {
		s.applyRules(c)
		return
	}
	if s.aiClient() == nil {
		return
	}
	switch {
	case s.aiOperatorOn():
		go s.runAIOperator(context.Background(), c)
	case s.aiAuto:
		go func() {
			if _, err := s.analyzeCase(context.Background(), c); err != nil {
				s.feed.Append("ai", sensorID, "Autoanaliza AI nie powiodła się: "+err.Error(), nil)
			}
		}()
	}
}

// backfillAIOperator hands the operator the backlog of open cases when its
// mode is switched on, so the toggle has an immediate, visible effect
// instead of waiting for the next escalation.
func (s *server) backfillAIOperator(limit int) {
	if s.aiClient() == nil {
		return
	}
	triaged := 0
	for _, c := range s.store.ListCases() {
		if triaged >= limit {
			break
		}
		if c.Status != StatusNew && c.Status != StatusVerify {
			continue
		}
		triaged++
		s.runAIOperator(context.Background(), c)
		time.Sleep(2 * time.Second) // be gentle with the provider's rate limits
	}
	if triaged > 0 {
		s.feed.Append("ai", "", fmt.Sprintf("Operator AI przejął triaż %d otwartych spraw z zaległości", triaged), nil)
	}
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
	// The passive record feeds ground truth: every log line updates what
	// the control scans will later verify. The timeline keeps the sensor's
	// own timestamps, so replaying the map shows when things really
	// happened, not when the console received them.
	if s.gt != nil {
		now := time.Now()
		for _, l := range logs {
			at := now
			if t, err := time.Parse(time.RFC3339Nano, l.Time); err == nil {
				at = t
			}
			s.gt.registry.Observe(l, sensor, at)
		}
	}
	s.store.TouchSensor(sensor)
	w.WriteHeader(http.StatusAccepted)
}

// exposureStatus reports the outside/inside diff: configuration, the last
// external view and the current findings.
func (s *server) exposureStatus(w http.ResponseWriter, r *http.Request) {
	if s.exposure == nil {
		writeJSON(w, 200, map[string]interface{}{"enabled": false, "configured": false})
		return
	}
	writeJSON(w, 200, s.exposure.status())
}

// exposureRun triggers an on-demand outside-view pull (admin only).
func (s *server) exposureRun(w http.ResponseWriter, r *http.Request) {
	if s.exposure == nil {
		http.Error(w, "exposure check unavailable", 503)
		return
	}
	sess := s.auth.who(r)
	who := "operator"
	if sess != nil {
		who = sess.Name
	}
	go s.exposure.run("ręcznie: " + who)
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

// tlsStatus reports the TLS certificate inventory and open findings.
func (s *server) tlsStatus(w http.ResponseWriter, r *http.Request) {
	if s.tlsMon == nil {
		writeJSON(w, 200, map[string]interface{}{"enabled": false, "issues": []interface{}{}})
		return
	}
	writeJSON(w, 200, s.tlsMon.status())
}

// tlsRun triggers an on-demand policy pass (admin only).
func (s *server) tlsRun(w http.ResponseWriter, r *http.Request) {
	if s.tlsMon == nil {
		http.Error(w, "tls monitor unavailable", 503)
		return
	}
	sess := s.auth.who(r)
	who := "operator"
	if sess != nil {
		who = sess.Name
	}
	go s.tlsMon.run("ręcznie: " + who)
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

// attackMap serves the attack-surface map: the current per-host state from
// the passive registry (the graph) plus the topology timeline (how the
// network drifted). Query params from/to (RFC3339) bound the timeline.
func (s *server) attackMap(w http.ResponseWriter, r *http.Request) {
	if s.gt == nil {
		writeJSON(w, 200, map[string]interface{}{"hosts": []interface{}{}, "events": []interface{}{}})
		return
	}
	var from, to time.Time
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"hosts":  s.gt.registry.hostsSnapshot(),
		"events": s.gt.registry.timeline(from, to),
	})
}

// groundTruthStatus reports the control-scan policy, the registry size and
// the last run's outcome.
func (s *server) groundTruthStatus(w http.ResponseWriter, r *http.Request) {
	if s.gt == nil {
		writeJSON(w, 200, map[string]interface{}{"enabled": false})
		return
	}
	writeJSON(w, 200, s.gt.status())
}

// groundTruthRun triggers a control scan on demand (admin); the run itself
// is audited in the live feed with the operator's name.
func (s *server) groundTruthRun(w http.ResponseWriter, r *http.Request) {
	if s.gt == nil {
		http.Error(w, "ground truth disabled", 409)
		return
	}
	who := "operator"
	if sess := s.auth.who(r); sess != nil {
		who = sess.Name
	}
	s.feed.Append("status", "", who+": uruchomił(a) ręcznie aktywny skan kontrolny (ground truth)", nil)
	go s.gt.run("ręcznie · " + who)
	writeJSON(w, 200, map[string]string{"ok": "true"})
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
		"enabled": client != nil, "auto": s.aiAuto && client != nil && !s.ruleModeOn(),
		"operator":  s.aiOperatorOn() && client != nil && !s.ruleModeOn(),
		"rule_mode": s.ruleModeOn(),
		"model":     "", "base_url": "",
	}
	if client != nil {
		out["model"] = client.modelName()
		out["base_url"] = client.baseName()
	}
	writeJSON(w, 200, out)
}

// listRules returns the ordered rule list for the rules tab.
func (s *server) listRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{"items": s.rules.list(), "rule_mode": s.ruleModeOn()})
}

// putRules replaces the whole ordered rule list (admin only). The change is
// mirrored to the live feed like any other configuration change.
func (s *server) putRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Items []*Rule `json:"items"`
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1*1024*1024))
	if err != nil || json.Unmarshal(b, &body) != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	if err := s.rules.replace(body.Items); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	who := "operator"
	if sess := s.auth.who(r); sess != nil {
		who = sess.Name
	}
	s.feed.Append("rule", "", fmt.Sprintf("%s: zapisał(a) konfigurację reguł (%d pozycji)", who, len(body.Items)), nil)
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

// applyRulesHandler re-runs the deterministic engine over the open backlog
// on demand — useful right after editing the rule list.
func (s *server) applyRulesHandler(w http.ResponseWriter, r *http.Request) {
	triaged, scanned := s.applyRulesToOpen(100)
	s.feed.Append("rule", "", fmt.Sprintf("Silnik reguł przetworzył zaległość: %d dopasowanych z %d otwartych spraw", triaged, scanned), nil)
	writeJSON(w, 200, map[string]interface{}{"triaged": triaged, "scanned": scanned})
}

// getConfig returns the persisted runtime configuration. The AI API key is
// never sent back — only whether one is set.
func (s *server) getConfig(w http.ResponseWriter, r *http.Request) {
	snap := s.settings.snapshot()
	gtEnabled, gtInterval, gtSilent, gtSample := true, 360, 60, 50
	if s.gt != nil {
		var i, sl time.Duration
		gtEnabled, i, sl, gtSample = s.gt.gtConfig()
		gtInterval, gtSilent = int(i/time.Minute), int(sl/time.Minute)
	}
	writeJSON(w, 200, map[string]interface{}{
		"demo_feed":     s.demoFeedOn(),
		"demo_feed_src": srcOf(snap.DemoFeed),
		"ai_operator":   s.aiOperatorOn(),
		"rule_mode":     s.ruleModeOn(),
		"ai_base_url":   snap.AIBaseURL,
		"ai_model":      snap.AIModel,
		"ai_api_key_set": snap.AIAPIKey != "" || firstNonEmpty(snap.AIAPIKey, "") != "" ||
			len(os.Getenv("ASI_AI_API_KEY")) > 0,
		"ai_base_url_effective": firstNonEmpty(snap.AIBaseURL, os.Getenv("ASI_AI_BASE_URL"), "https://api.openai.com/v1"),
		"ai_model_effective":    firstNonEmpty(snap.AIModel, os.Getenv("ASI_AI_MODEL"), "gpt-4o-mini"),
		"gt_enabled":            gtEnabled,
		"gt_interval_min":       gtInterval,
		"gt_silent_min":         gtSilent,
		"gt_sample_size":        gtSample,
		"cve_lookup":            cveLookupEffective(snap.CVELookup),
		"exposure_enabled":      snap.ExposureEnabled != nil && *snap.ExposureEnabled,
		"exposure_provider":     firstNonEmpty(snap.ExposureProvider, "shodan"),
		"exposure_public_ip":    snap.ExposurePublicIP,
		"exposure_interval_min": snap.ExposureIntervalMin,
		"exposure_key_set": snap.ExposureAPIKey != "" ||
			os.Getenv("SHODAN_API_KEY") != "" ||
			(os.Getenv("CENSYS_API_ID") != "" && os.Getenv("CENSYS_API_SECRET") != ""),
		"tls_enabled":      snap.TLSEnabled == nil || *snap.TLSEnabled,
		"tls_interval_min": snap.TLSIntervalMin,
	})
}

// cveLookupEffective resolves the CVE enrichment toggle: default on unless
// explicitly disabled in settings.
func cveLookupEffective(override *bool) bool {
	return override == nil || *override
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
	wasDemoFeed := s.demoFeedOn()
	wasAIOperator := s.aiOperatorOn()
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
			msg := "WYŁĄCZONO tryb demo — konsola w trybie live (tylko prawdziwe zdarzenia z edge)"
			// Live mode also clears the synthetic content, so the dashboard
			// shows only what the edge actually reported.
			if wasDemoFeed {
				if cn, sn := s.store.PurgeDemo(isDemoSensorID); cn+sn > 0 {
					msg += fmt.Sprintf("; usunięto %d spraw i %d sensorów demo", cn, sn)
				}
			}
			changes = append(changes, msg)
		}
	}
	if p.AIOperator != nil && (before.AIOperator == nil || *before.AIOperator != *p.AIOperator) {
		if *p.AIOperator {
			changes = append(changes, "włączono autonomicznego operatora AI")
		} else {
			changes = append(changes, "wyłączono autonomicznego operatora AI")
		}
	}
	if p.RuleMode != nil && (before.RuleMode == nil || *before.RuleMode != *p.RuleMode) {
		if *p.RuleMode {
			changes = append(changes, "włączono tryb regułowy — modele decyzyjne (Bayes, drzewo decyzyjne, basal/laya/kev, operator AI) są pomijane przy triażu")
		} else {
			changes = append(changes, "wyłączono tryb regułowy — triaż wraca do modeli decyzyjnych")
		}
	}
	if p.GTEnabled != nil && (before.GTEnabled == nil || *before.GTEnabled != *p.GTEnabled) {
		if *p.GTEnabled {
			changes = append(changes, "włączono okresowe aktywne skany kontrolne (ground truth dla cichych hostów)")
		} else {
			changes = append(changes, "WYŁĄCZONO skany kontrolne — luka obserwowalności cichych hostów (silent_stealth) nie będzie weryfikowana")
		}
	}
	if p.GTIntervalMin != nil || p.GTSilentMin != nil || p.GTSampleSize != nil {
		changes = append(changes, "zmieniono politykę skanów kontrolnych")
	}
	if p.CVELookup != nil && (before.CVELookup == nil || *before.CVELookup != *p.CVELookup) {
		if *p.CVELookup {
			changes = append(changes, "włączono wyszukiwanie CVE (NVD + EPSS)")
		} else {
			changes = append(changes, "wyłączono wyszukiwanie CVE (NVD + EPSS)")
		}
	}
	if p.ExposureEnabled != nil && (before.ExposureEnabled == nil || *before.ExposureEnabled != *p.ExposureEnabled) {
		if *p.ExposureEnabled {
			changes = append(changes, "włączono korelację z widokiem zewnętrznym (Shodan/Censys) — konsola odpytuje zewnętrzne API o publiczne IP")
		} else {
			changes = append(changes, "wyłączono korelację z widokiem zewnętrznym (Shodan/Censys)")
		}
	}
	if p.ExposureProvider != nil && *p.ExposureProvider != before.ExposureProvider {
		changes = append(changes, "zmieniono dostawcę widoku zewnętrznego na "+*p.ExposureProvider)
	}
	if p.ExposureAPIKey != nil && *p.ExposureAPIKey != "" && *p.ExposureAPIKey != before.ExposureAPIKey {
		changes = append(changes, "zaktualizowano klucz API widoku zewnętrznego")
	}
	if p.ExposurePublicIP != nil && *p.ExposurePublicIP != before.ExposurePublicIP {
		changes = append(changes, "zmieniono publiczne IP korelacji")
	}
	if p.ExposureIntervalMin != nil {
		changes = append(changes, "zmieniono interwał kontroli ekspozycji")
	}
	if p.TLSEnabled != nil && (before.TLSEnabled == nil || *before.TLSEnabled != *p.TLSEnabled) {
		if *p.TLSEnabled {
			changes = append(changes, "włączono monitoring certyfikatów TLS")
		} else {
			changes = append(changes, "wyłączono monitoring certyfikatów TLS — wygasające certyfikaty i słaba kryptografia nie będą zgłaszane")
		}
	}
	if p.TLSIntervalMin != nil {
		changes = append(changes, "zmieniono interwał kontroli TLS")
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
	// Enabling operator mode takes over the open backlog right away.
	if p.AIOperator != nil && *p.AIOperator && !wasAIOperator {
		go s.backfillAIOperator(10)
	}
	// Enabling rule mode triages the open backlog instantly, in-band — the
	// deterministic engine needs no provider round-trips.
	if p.RuleMode != nil && *p.RuleMode {
		if triaged, scanned := s.applyRulesToOpen(100); scanned > 0 {
			s.feed.Append("rule", "", fmt.Sprintf("Silnik reguł przetworzył zaległość: %d dopasowanych z %d otwartych spraw", triaged, scanned), nil)
		}
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

// operatorRun lets a human dispatch the AI operator onto one case on demand
// — the same autonomous triage the operator applies to fresh escalations.
func (s *server) operatorRun(w http.ResponseWriter, r *http.Request) {
	if s.aiClient() == nil {
		http.Error(w, "operator AI nie jest skonfigurowany (ustaw dostawcę w Ustawieniach)", 503)
		return
	}
	if !s.aiOperatorOn() {
		http.Error(w, "tryb operatora AI jest wyłączony — włącz go w Ustawieniach", 409)
		return
	}
	c, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	s.runAIOperator(r.Context(), c)
	writeJSON(w, 200, map[string]string{"ok": "true"})
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
		// "demo" means synthetic content may be on screen right now; the
		// badge disappears as soon as the live switch purges it.
		"demo": s.demoData && s.demoFeedOn(),
		"live": !s.demoFeedOn(),
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
