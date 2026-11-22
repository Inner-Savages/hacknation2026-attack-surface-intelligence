package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
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
	store *Store
	token string
	demo  bool
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/summary", s.summary)
	mux.HandleFunc("GET /api/alerts", s.alerts)
	mux.HandleFunc("GET /api/alerts/{id}", s.alert)
	mux.HandleFunc("POST /api/alerts/{id}/status", s.setStatus)
	mux.HandleFunc("POST /api/alerts/{id}/assign", s.assign)
	mux.HandleFunc("POST /api/alerts/{id}/notes", s.addNote)
	mux.HandleFunc("POST /api/alerts/{id}/actions", s.action)
	mux.HandleFunc("GET /api/sensors", s.sensors)
	mux.HandleFunc("POST /events", s.intake)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	return mux
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
	w.WriteHeader(http.StatusAccepted)
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
		"demo":    s.demo,
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

func actor(r *http.Request, body map[string]string) string {
	if a := strings.TrimSpace(body["actor"]); a != "" {
		return a
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
	a := actor(r, m)
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
	a := actor(r, m)
	err := s.store.mutate(r.PathValue("id"), func(c *Case) (HistoryEntry, error) {
		c.Assignee = who
		return HistoryEntry{At: time.Now(), Kind: "assign", Actor: "system", Text: "Przypisano do " + who}, nil
	})
	_ = a
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
	a := actor(r, m)
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
	a := actor(r, m)
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
		if s.demo {
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
	writeJSON(w, 200, map[string]interface{}{"state": "executed", "demo": s.demo})
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
