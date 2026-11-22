package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// LogEntry is one line in the live feed shown on the dashboard. Sensor
// entries carry the raw payload exactly as the sensor shipped it; console
// entries (escalations, operator actions, AI analyses) carry a text summary.
type LogEntry struct {
	Seq    int64           `json:"seq"`
	At     time.Time       `json:"at"`
	Kind   string          `json:"kind"` // sensor, escalation, status, assign, note, action, ai
	Sensor string          `json:"sensor,omitempty"`
	Text   string          `json:"text"`
	Raw    json.RawMessage `json:"raw,omitempty"`
}

// LiveFeed is a bounded, in-memory ring of recent log lines. Clients poll
// with the last sequence they saw, so the feed survives restarts of the UI
// without any durable storage of its own.
type LiveFeed struct {
	mu    sync.Mutex
	seq   int64
	items []LogEntry
	cap   int
}

func newLiveFeed(capacity int) *LiveFeed {
	if capacity < 64 {
		capacity = 64
	}
	return &LiveFeed{cap: capacity, items: make([]LogEntry, 0, capacity)}
}

// Append adds an entry and returns its sequence number.
func (f *LiveFeed) Append(kind, sensor, text string, raw json.RawMessage) LogEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	e := LogEntry{Seq: f.seq, At: time.Now(), Kind: kind, Sensor: sensor, Text: text, Raw: raw}
	f.items = append(f.items, e)
	if len(f.items) > f.cap {
		f.items = append([]LogEntry{}, f.items[len(f.items)-f.cap:]...)
	}
	return e
}

// Since returns up to limit entries with Seq > after, plus the current high
// watermark (so a client that fell behind the ring can resync).
func (f *LiveFeed) Since(after int64, limit int) (items []LogEntry, last int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	items = []LogEntry{}
	for _, e := range f.items {
		if e.Seq > after {
			items = append(items, e)
			if len(items) == limit {
				break
			}
		}
	}
	return items, f.seq
}

// matching returns up to limit recent sensor log lines relevant to a case:
// reported by the same sensor or mentioning the case's source host.
func (f *LiveFeed) matching(c *Case, limit int) []LogEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []LogEntry{}
	for i := len(f.items) - 1; i >= 0 && len(out) < limit; i-- {
		e := f.items[i]
		if e.Kind != "sensor" {
			continue
		}
		if e.Sensor == c.SensorID || strings.Contains(e.Text, c.Source) {
			out = append(out, e)
		}
	}
	// restore chronological order
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// sensorLog mirrors the passive sensor's NDJSON log lines:
//
//	{"time":"…","type":"service_silent","ip":"172.28.0.30","port":80,"proto":"tcp","source":"passive"}
type sensorLog struct {
	Time   string `json:"time"`
	Type   string `json:"type"`
	IP     string `json:"ip"`
	Port   int    `json:"port,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Source string `json:"source,omitempty"`
	// New carries the MAC address on host_new events (the sensor reports the
	// observed source MAC there) and fingerprints on service changes.
	New string `json:"new,omitempty"`
}

func (l sensorLog) line() string {
	s := l.Type + " " + l.IP
	if l.Port > 0 {
		s += fmt.Sprintf(":%d", l.Port)
		if l.Proto != "" {
			s += "/" + l.Proto
		}
	}
	return s
}

// parseSensorLogs accepts one JSON object, a JSON array, or NDJSON lines and
// returns every well-formed sensor log line together with its raw bytes.
func parseSensorLogs(body []byte) ([]sensorLog, []json.RawMessage, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, nil, fmt.Errorf("empty body")
	}
	if body[0] == '[' {
		var raws []json.RawMessage
		if err := json.Unmarshal(body, &raws); err != nil {
			return nil, nil, fmt.Errorf("invalid JSON array")
		}
		return decodeSensorLogs(raws)
	}
	// Single object or NDJSON.
	var raws []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) > 0 {
			raws = append(raws, json.RawMessage(append([]byte{}, line...)))
		}
	}
	return decodeSensorLogs(raws)
}

func decodeSensorLogs(raws []json.RawMessage) ([]sensorLog, []json.RawMessage, error) {
	logs, kept := []sensorLog{}, []json.RawMessage{}
	for _, raw := range raws {
		var l sensorLog
		if json.Unmarshal(raw, &l) != nil || l.Type == "" || l.IP == "" {
			return nil, nil, fmt.Errorf("expected sensor log lines with at least type and ip")
		}
		logs = append(logs, l)
		kept = append(kept, raw)
	}
	if len(logs) == 0 {
		return nil, nil, fmt.Errorf("no log lines")
	}
	return logs, kept, nil
}
