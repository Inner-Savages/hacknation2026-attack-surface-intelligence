package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Case statuses used by the operator workflow.
const (
	StatusNew        = "nowe"
	StatusVerify     = "do_weryfikacji"
	StatusConfirmed  = "potwierdzony"
	StatusFalseAlarm = "falszywy_alarm"
	StatusClosed     = "zamkniety"
)

var caseStatuses = []string{StatusNew, StatusVerify, StatusConfirmed, StatusFalseAlarm, StatusClosed}

func validStatus(s string) bool {
	for _, v := range caseStatuses {
		if v == s {
			return true
		}
	}
	return false
}

type Note struct {
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	Text  string    `json:"text"`
}

type HistoryEntry struct {
	At    time.Time `json:"at"`
	Kind  string    `json:"kind"` // alert, status, assign, note, action
	Text  string    `json:"text"`
	Actor string    `json:"actor"`
}

type ActionRecord struct {
	At       time.Time `json:"at"`
	Action   string    `json:"action"` // observe, scan, reanalyze, isolate
	Actor    string    `json:"actor"`
	Executed bool      `json:"executed"` // false while waiting for the second confirmation step
}

// Case is one escalation envelope plus the operator's working state.
type Case struct {
	EventID    string          `json:"event_id"`
	Received   time.Time       `json:"received"`
	Envelope   json.RawMessage `json:"envelope"`
	SensorID   string          `json:"sensor_id"`
	EventType  string          `json:"event_type"`
	EventTime  string          `json:"event_time"`
	Source     string          `json:"source"` // host IP
	Target     string          `json:"target"` // destination or "—"
	Score      float64         `json:"score"`
	Unresolved bool            `json:"unresolved"`
	Reason     string          `json:"reason"`
	Status     string          `json:"status"`
	Assignee   string          `json:"assignee,omitempty"`
	Notes      []Note          `json:"notes,omitempty"`
	History    []HistoryEntry  `json:"history"`
	Actions    []ActionRecord  `json:"actions,omitempty"`

	// PendingAction is set when a two-step action awaits confirmation.
	PendingAction string `json:"pending_action,omitempty"`
}

// Sensor aggregates fleet health derived from received escalations and
// optional heartbeat files written by the ingestion side.
type Sensor struct {
	ID        string         `json:"id"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Online    bool           `json:"online"`
	Counts    map[string]int `json:"counts"`
}

// Store is a durable, JSON-file backed case store. Every mutation is written
// atomically (tmp file + rename) and mirrored to an append-only audit log.
type Store struct {
	dir     string
	logPath string
	mu      sync.Mutex
	cases   map[string]*Case
	sensors map[string]*Sensor

	// OnAudit, when set, is invoked for every audit entry (case creation,
	// status changes, notes, actions, AI analyses). It runs while the store
	// lock is held, so it must not call back into the store.
	OnAudit func(entry HistoryEntry, eventID string)
}

func openStore(dir string) (*Store, error) {
	s := &Store{dir: dir, logPath: filepath.Join(dir, "audit.jsonl"), cases: map[string]*Case{}, sensors: map[string]*Sensor{}}
	if err := os.MkdirAll(filepath.Join(dir, "cases"), 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "cases"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := rest.ReadFile(filepath.Join(dir, "cases", e.Name()))
		if err != nil {
			return nil, err
		}
		var c Case
		if json.Unmarshal(b, &c) != nil {
			continue // skip a torn write instead of failing the fleet view
		}
		s.cases[c.EventID] = &c
		s.touchSensor(&c)
	}
	return s, nil
}

func (s *Store) touchSensor(c *Case) {
	sen, ok := s.sensors[c.SensorID]
	if !ok {
		sen = &Sensor{ID: c.SensorID, FirstSeen: c.Received, LastSeen: c.Received, Counts: map[string]int{}}
		s.sensors[c.SensorID] = sen
	}
	if c.Received.After(sen.LastSeen) {
		sen.LastSeen = c.Received
	}
	if c.Received.Before(sen.FirstSeen) {
		sen.FirstSeen = c.Received
	}
	sen.Counts[c.Status]++
}

func (s *Store) recountSensors() {
	for _, sen := range s.sensors {
		sen.Counts = map[string]int{}
	}
	for _, c := range s.cases {
		sen, ok := s.sensors[c.SensorID]
		if !ok {
			sen = &Sensor{ID: c.SensorID, FirstSeen: c.Received, LastSeen: c.Received, Counts: map[string]int{}}
			s.sensors[c.SensorID] = sen
		}
		sen.Counts[c.Status]++
	}
}

// PurgeDemo removes the synthetic demo content when the console switches to
// live mode: seeded cases (event IDs carry the "demo-" prefix) are deleted
// from memory and disk, and seeded fleet sensors are dropped from the
// registry. Real cases and sensors (anything that arrived over the wire)
// are untouched; the append-only audit log keeps the full history.
func (s *Store) PurgeDemo(isDemoSensor func(string) bool) (casesRemoved, sensorsRemoved int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.cases {
		if strings.HasPrefix(id, "demo-") {
			delete(s.cases, id)
			os.Remove(filepath.Join(s.dir, "cases", id+".json"))
			casesRemoved++
		}
	}
	for id := range s.sensors {
		if isDemoSensor(id) {
			delete(s.sensors, id)
			sensorsRemoved++
		}
	}
	s.recountSensors()
	return casesRemoved, sensorsRemoved
}

// Heartbeat refreshes liveness for sensors currently marked online. The demo
// fleet uses it to simulate live sensors; real deployments get liveness from
// incoming escalations or heartbeat files.
func (s *Store) Heartbeat() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, sen := range s.sensors {
		if sen.Online {
			sen.LastSeen = now
		}
	}
}

// markOffline flips the online flag for sensors silent longer than the TTL.
func (s *Store) markOffline(ttl time.Duration) {
	now := time.Now()
	for _, sen := range s.sensors {
		sen.Online = now.Sub(sen.LastSeen) <= ttl
	}
}

// TouchSensor records a sign of life from a sensor (a log line or any other
// heartbeat) and marks it online.
func (s *Store) TouchSensor(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sen, ok := s.sensors[id]
	if !ok {
		now := time.Now()
		sen = &Sensor{ID: id, FirstSeen: now, Counts: map[string]int{}}
		s.sensors[id] = sen
	}
	sen.LastSeen = time.Now()
	sen.Online = true
}

// RegisterSensor records a sensor that has not escalated anything yet.
func (s *Store) RegisterSensor(id string, seen time.Time, online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sensors[id]; !ok {
		s.sensors[id] = &Sensor{ID: id, FirstSeen: seen, LastSeen: seen, Online: online, Counts: map[string]int{}}
	}
}

func (s *Store) persistLocked(c *Case) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	final := filepath.Join(s.dir, "cases", c.EventID+".json")
	return rest.WriteFile(final, b, 0o600)
}

func (s *Store) auditLocked(e HistoryEntry, id string) {
	f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(map[string]interface{}{"event_id": id, "entry": e})
	if line, err := rest.SealLine(b, "audit.jsonl"); err == nil {
		b = line
	}
	f.Write(append(b, '\n'))
	f.Sync()
	if s.OnAudit != nil {
		s.OnAudit(e, id)
	}
}

// AddEscalation stores a new escalation envelope; duplicate event IDs are
// acknowledged without creating a second case (delivery is at least once).
func (s *Store) AddEscalation(c *Case) (created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.cases[c.EventID]; dup {
		return false, nil
	}
	if c.Status == "" {
		c.Status = StatusNew
	}
	if c.Received.IsZero() {
		c.Received = time.Now()
	}
	entry := HistoryEntry{At: c.Received, Kind: "alert", Actor: "system", Text: "Alert utworzony, eskalacja z powodu " + c.Reason}
	c.History = append([]HistoryEntry{entry}, c.History...)
	if err := s.persistLocked(c); err != nil {
		return false, err
	}
	s.cases[c.EventID] = c
	s.touchSensor(c)
	s.auditLocked(entry, c.EventID)
	return true, nil
}

// Get returns a deep copy of the case, so readers never race with mutations
// applied through mutate (e.g. the background AI operator).
func (s *Store) Get(id string) (*Case, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cases[id]
	if !ok {
		return nil, false
	}
	cp := copyCase(c)
	return cp, true
}

func copyCase(c *Case) *Case {
	cp := *c
	cp.Notes = append([]Note{}, c.Notes...)
	cp.History = append([]HistoryEntry{}, c.History...)
	cp.Actions = append([]ActionRecord{}, c.Actions...)
	cp.Envelope = append(json.RawMessage{}, c.Envelope...)
	return &cp
}

func (s *Store) mutate(id string, fn func(c *Case) (HistoryEntry, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cases[id]
	if !ok {
		return fmt.Errorf("unknown event id")
	}
	entry, err := fn(c)
	if err != nil {
		return err
	}
	c.History = append(c.History, entry)
	if err := s.persistLocked(c); err != nil {
		return err
	}
	s.recountSensors()
	s.auditLocked(entry, id)
	return nil
}

func (s *Store) ListSensors() []*Sensor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Sensor, 0, len(s.sensors))
	for _, v := range s.sensors {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) ListCases() []*Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Case, 0, len(s.cases))
	for _, v := range s.cases {
		out = append(out, copyCase(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Received.After(out[j].Received) })
	return out
}
