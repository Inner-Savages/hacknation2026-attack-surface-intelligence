// Package aiml implements a dependency-free, stream-compatible event risk gate.
package aiml

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Time   string          `json:"time"`
	Type   string          `json:"type"`
	IP     string          `json:"ip"`
	Port   int             `json:"port,omitempty"`
	Proto  string          `json:"proto,omitempty"`
	Old    string          `json:"old,omitempty"`
	New    string          `json:"new,omitempty"`
	Banner json.RawMessage `json:"banner,omitempty"`
	Source string          `json:"source,omitempty"`
	Sensor string          `json:"sensor,omitempty"` // set by sensors run with -name; not a model feature
}

var EventTypes = []string{"host_new", "host_silent", "host_back", "service_new", "service_changed", "service_closed", "service_silent", "service_back"}
var FeatureNames = []string{
	"host_new", "host_silent", "host_back", "service_new", "service_changed", "service_closed", "service_silent", "service_back",
	"risky_port", "management_port", "wellknown_port", "has_banner", "unusual_banner", "changed_fingerprint", "old_closed",
	"gap_log_seconds", "recent_count", "recent_new_services", "recent_changes", "recent_silent", "recent_returns", "recent_distinct_ports",
	"host_seen_before", "service_event", "hour_sin", "hour_cos", "repeated_port", "previous_silent",
}

const Dimension = 28

type state struct {
	last     time.Time
	lastType string
	seen     int
	recent   []history
	ports    map[int]bool
}
type history struct {
	t    time.Time
	typ  string
	port int
}
type Extractor struct {
	mu    sync.Mutex // checkpointing runs off the event worker
	hosts map[string]*state

	// Memory bounding. ttl <= 0 keeps every host forever (the historical
	// default, used by one-shot tools); a positive TTL evicts hosts that
	// have been silent — in stream time — for longer than the window, so a
	// long-running sensor watching 10k+ IPs stays flat. Staleness is
	// measured against the newest event timestamp seen (stream time), not
	// the wall clock, which keeps replays deterministic.
	ttl     time.Duration
	now     time.Time
	sweeps  int // events processed since the last eviction sweep
	evicted int64
}

const (
	// sweepEvery amortizes eviction: the staleness scan runs once per this
	// many events instead of on every event.
	sweepEvery = 512
	// maxPortsPerHost bounds the per-host port set. A scanner touching
	// thousands of ports on one host must not grow memory without limit;
	// past the cap the set is reset (the repeated_port feature simply
	// re-learns the active ones).
	maxPortsPerHost = 512
)

func NewExtractor() *Extractor { return &Extractor{hosts: make(map[string]*state)} }

// NewExtractorWithTTL returns an extractor that evicts hosts idle for
// longer than ttl (stream time). A host that returns after eviction is
// learned again from scratch — host_seen_before flips back to 0, which is
// the honest signal for a host absent longer than the baseline window.
func NewExtractorWithTTL(ttl time.Duration) *Extractor {
	x := NewExtractor()
	x.ttl = ttl
	return x
}

// Hosts reports how many host states are currently tracked.
func (x *Extractor) Hosts() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.hosts)
}

// Evicted reports how many stale host states the TTL sweeps have removed.
func (x *Extractor) Evicted() int64 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.evicted
}

// sweepLocked drops hosts whose last event is older than ttl relative to
// the newest event seen. Called amortized from Features.
func (x *Extractor) sweepLocked() {
	if x.ttl <= 0 || x.now.IsZero() {
		return
	}
	cutoff := x.now.Add(-x.ttl)
	for ip, h := range x.hosts {
		last := h.last
		if last.IsZero() {
			// Events without a parseable timestamp never age in stream
			// time; use the first-seen recency via recent[] as a hint.
			if len(h.recent) > 0 {
				last = h.recent[len(h.recent)-1].t
			}
		}
		if !last.IsZero() && last.Before(cutoff) {
			delete(x.hosts, ip)
			x.evicted++
		}
	}
}

func (x *Extractor) Features(e Event) []float64 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.featuresLocked(e)
}

func (x *Extractor) featuresLocked(e Event) []float64 {
	f := make([]float64, Dimension)
	for i, t := range EventTypes {
		if e.Type == t {
			f[i] = 1
		}
	}
	risky := map[int]bool{21: true, 22: true, 23: true, 445: true, 3389: true, 5900: true, 5985: true, 2375: true, 4444: true, 1337: true, 6667: true, 8080: true, 8443: true, 8888: true}
	management := map[int]bool{22: true, 23: true, 445: true, 3389: true, 5900: true, 5985: true, 2375: true}
	if risky[e.Port] {
		f[8] = 1
	}
	if management[e.Port] {
		f[9] = 1
	}
	if e.Port > 0 && e.Port < 1024 {
		f[10] = 1
	}
	if len(e.Banner) > 0 {
		f[11] = 1
	}
	s := strings.ToLower(e.New + " " + string(e.Banner))
	if strings.Contains(s, "python") || strings.Contains(s, "debug") || strings.Contains(s, "admin") || strings.Contains(s, "test") {
		f[12] = 1
	}
	if e.Type == "service_changed" && e.Old != "" && e.New != "" && e.Old != e.New {
		f[13] = 1
	}
	if e.Old == "closed" {
		f[14] = 1
	}
	if strings.HasPrefix(e.Type, "service_") {
		f[23] = 1
	}
	t, err := time.Parse(time.RFC3339Nano, e.Time)
	if err != nil {
		t = time.Time{}
	}
	h := x.hosts[e.IP]
	if h == nil {
		h = &state{ports: make(map[int]bool)}
		x.hosts[e.IP] = h
	}
	if h.seen > 0 {
		f[22] = 1
	}
	if h.ports[e.Port] && e.Port != 0 {
		f[26] = 1
	}
	if !h.last.IsZero() && !t.IsZero() {
		delta := t.Sub(h.last).Seconds()
		if delta < 0 {
			delta = 0
		}
		f[15] = math.Log1p(math.Min(delta, 86400)) / 10
	}
	cutoff := t.Add(-5 * time.Minute)
	keep := h.recent[:0]
	p := make(map[int]bool)
	for _, r := range h.recent {
		if !t.IsZero() && r.t.Before(cutoff) {
			continue
		}
		keep = append(keep, r)
		if r.typ == "service_new" {
			f[17]++
		}
		if r.typ == "service_changed" {
			f[18]++
		}
		if strings.HasSuffix(r.typ, "silent") {
			f[19]++
		}
		if strings.HasSuffix(r.typ, "back") {
			f[20]++
		}
		if r.port > 0 {
			p[r.port] = true
		}
	}
	h.recent = keep
	f[16] = float64(len(keep))
	f[21] = float64(len(p))
	if h.lastType == "service_silent" || h.lastType == "host_silent" {
		f[27] = 1
	}
	if !t.IsZero() {
		hfrac := float64(t.Hour()) + float64(t.Minute())/60
		f[24] = math.Sin(hfrac * 2 * math.Pi / 24)
		f[25] = math.Cos(hfrac * 2 * math.Pi / 24)
	}
	if !t.IsZero() {
		h.recent = append(h.recent, history{t, e.Type, e.Port})
	}
	if len(h.recent) > 64 {
		h.recent = h.recent[len(h.recent)-64:]
	}
	h.seen++
	if !t.IsZero() {
		h.last = t
		if t.After(x.now) {
			x.now = t
		}
	}
	h.lastType = e.Type
	if e.Port > 0 {
		if len(h.ports) >= maxPortsPerHost {
			h.ports = make(map[int]bool, maxPortsPerHost)
		}
		h.ports[e.Port] = true
	}
	// Amortized TTL eviction: bounded memory for long-running sensors.
	if x.ttl > 0 {
		x.sweeps++
		if x.sweeps >= sweepEvery {
			x.sweeps = 0
			x.sweepLocked()
		}
	}
	return f
}

// --- host-state checkpoint -------------------------------------------------

// CheckpointEvent is the durable form of one entry in a host's recent
// history.
type CheckpointEvent struct {
	T    string `json:"t"`
	Type string `json:"type"`
	Port int    `json:"port,omitempty"`
}

// CheckpointHost is the durable form of one host's learned state.
type CheckpointHost struct {
	Last     string            `json:"last,omitempty"`
	LastType string            `json:"last_type,omitempty"`
	Seen     int               `json:"seen"`
	Recent   []CheckpointEvent `json:"recent,omitempty"`
	Ports    []int             `json:"ports,omitempty"`
}

// ExtractorCheckpoint snapshots the whole host table so a gate restart does
// not lose its baseline memory: hosts it has seen, their recent event
// windows and per-host port sets.
type ExtractorCheckpoint struct {
	Version int                       `json:"version"`
	SavedAt string                    `json:"saved_at"`
	Now     string                    `json:"now,omitempty"` // stream time at save
	Hosts   map[string]CheckpointHost `json:"hosts"`
}

const checkpointVersion = 1

// SaveCheckpoint writes the current host table. The write is a consistent
// snapshot: it holds the extractor lock for the duration of the encode.
func (x *Extractor) SaveCheckpoint(w io.Writer) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	cp := ExtractorCheckpoint{
		Version: checkpointVersion,
		SavedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Hosts:   make(map[string]CheckpointHost, len(x.hosts)),
	}
	if !x.now.IsZero() {
		cp.Now = x.now.UTC().Format(time.RFC3339Nano)
	}
	for ip, h := range x.hosts {
		ch := CheckpointHost{LastType: h.lastType, Seen: h.seen}
		if !h.last.IsZero() {
			ch.Last = h.last.UTC().Format(time.RFC3339Nano)
		}
		for _, r := range h.recent {
			ch.Recent = append(ch.Recent, CheckpointEvent{T: r.t.UTC().Format(time.RFC3339Nano), Type: r.typ, Port: r.port})
		}
		for p := range h.ports {
			ch.Ports = append(ch.Ports, p)
		}
		sort.Ints(ch.Ports)
		cp.Hosts[ip] = ch
	}
	return json.NewEncoder(w).Encode(cp)
}

// LoadCheckpoint restores a host table saved by SaveCheckpoint and returns
// the number of hosts loaded. Hosts already stale at save time (older than
// the TTL relative to the checkpoint's stream time) are skipped, so a
// restart does not resurrect entries the sweeps would have evicted anyway.
// Unknown versions are rejected; corrupt timestamps skip only their entry.
func (x *Extractor) LoadCheckpoint(r io.Reader) (int, error) {
	var cp ExtractorCheckpoint
	if err := json.NewDecoder(r).Decode(&cp); err != nil {
		return 0, fmt.Errorf("decode checkpoint: %w", err)
	}
	if cp.Version != checkpointVersion {
		return 0, fmt.Errorf("unsupported checkpoint version %d", cp.Version)
	}
	var cutoff time.Time
	if x.ttl > 0 && cp.Now != "" {
		if now, err := time.Parse(time.RFC3339Nano, cp.Now); err == nil {
			cutoff = now.Add(-x.ttl)
		}
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	loaded := 0
	for ip, ch := range cp.Hosts {
		h := &state{lastType: ch.LastType, seen: ch.Seen, ports: make(map[int]bool, len(ch.Ports))}
		if ch.Last != "" {
			if t, err := time.Parse(time.RFC3339Nano, ch.Last); err == nil {
				h.last = t
			}
		}
		if !cutoff.IsZero() && !h.last.IsZero() && h.last.Before(cutoff) {
			continue // stale at save time; the sweep would have evicted it
		}
		for _, ce := range ch.Recent {
			t, err := time.Parse(time.RFC3339Nano, ce.T)
			if err != nil {
				continue
			}
			h.recent = append(h.recent, history{t, ce.Type, ce.Port})
		}
		if len(h.recent) > 64 {
			h.recent = h.recent[len(h.recent)-64:]
		}
		for _, p := range ch.Ports {
			if len(h.ports) >= maxPortsPerHost {
				break
			}
			h.ports[p] = true
		}
		x.hosts[ip] = h
		loaded++
		if !h.last.IsZero() && h.last.After(x.now) {
			x.now = h.last
		}
	}
	return loaded, nil
}

func Sigmoid(z float64) float64 {
	if z > 35 {
		return 1 - 1e-15
	}
	if z < -35 {
		return 1e-15
	}
	return 1 / (1 + math.Exp(-z))
}
func Clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

type Node struct {
	Feature int     `json:"feature,omitempty"`
	Cut     float64 `json:"cut,omitempty"`
	P       float64 `json:"p"`
	Left    *Node   `json:"left,omitempty"`
	Right   *Node   `json:"right,omitempty"`
}
type Model struct {
	Kind         string       `json:"kind"`
	FeatureNames []string     `json:"features"`
	Threshold    float64      `json:"threshold"`
	Mean         [2][]float64 `json:"mean,omitempty"`
	Var          [2][]float64 `json:"var,omitempty"`
	Prior        [2]float64   `json:"prior,omitempty"`
	Tree         *Node        `json:"tree,omitempty"`
}

func (m Model) Score(f []float64) float64 {
	switch m.Kind {
	case "gnb":
		l := [2]float64{}
		for c := 0; c < 2; c++ {
			l[c] = math.Log(math.Max(m.Prior[c], 1e-9))
			for i, v := range f {
				variance := math.Max(m.Var[c][i], .015)
				d := v - m.Mean[c][i]
				l[c] -= .5 * (math.Log(variance) + d*d/variance)
			}
		}
		return Sigmoid(l[1] - l[0])
	case "tree":
		n := m.Tree
		for n != nil && n.Left != nil && n.Right != nil {
			if f[n.Feature] <= n.Cut {
				n = n.Left
			} else {
				n = n.Right
			}
		}
		if n != nil {
			return n.P
		}
		return .5
	}
	return .5
}
func ValidateEvent(e Event) error {
	if e.IP == "" || e.Time == "" {
		return fmt.Errorf("missing ip/time")
	}
	known := false
	for _, v := range EventTypes {
		if e.Type == v {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("unknown event type: %s", strconv.Quote(e.Type))
	}
	return nil
}
