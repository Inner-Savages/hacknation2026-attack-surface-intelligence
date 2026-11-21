// Package aiml implements a dependency-free, stream-compatible event risk gate.
package aiml

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
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
type Extractor struct{ hosts map[string]*state }

func NewExtractor() *Extractor { return &Extractor{hosts: make(map[string]*state)} }
func (x *Extractor) Features(e Event) []float64 {
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
	}
	h.lastType = e.Type
	if e.Port > 0 {
		h.ports[e.Port] = true
	}
	// Avoid unlimited memory growth in a long-running sensor; pruning old hosts is controlled by caller's lifecycle.
	return f
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
