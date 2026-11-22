// Package sensor implements a passive network sensor: it turns observed
// packets into observations (host seen, port open/closed, HTTP banner) and
// reports changes relative to previously observed traffic.
package sensor

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Signal says what a single packet told us about a host or service.
type Signal string

const (
	SignalSeen   Signal = "seen"   // host sent a packet
	SignalOpen   Signal = "open"   // SYN-ACK or application response from the port
	SignalClosed Signal = "closed" // RST answering a SYN: port closed right now
)

// State is the tracker's current belief about a host or service.
type State string

const (
	StateActive State = "active"
	StateClosed State = "closed" // services only
	StateSilent State = "silent" // nothing seen for longer than SilentAfter
)

// EventType names a change the sensor reports.
type EventType string

const (
	HostNew        EventType = "host_new"
	HostSilent     EventType = "host_silent"
	HostBack       EventType = "host_back"
	ServiceNew     EventType = "service_new"
	ServiceChanged EventType = "service_changed"
	ServiceClosed  EventType = "service_closed"
	ServiceSilent  EventType = "service_silent"
	ServiceBack    EventType = "service_back"
)

// Observation is one fact extracted from a packet.
type Observation struct {
	Time   time.Time
	IP     netip.Addr
	MAC    string
	Port   uint16 // 0 for host-level observations
	Proto  string // "tcp"; empty for host-level observations
	Signal Signal
	Banner *Banner
}

// ServiceKey identifies a service endpoint.
type ServiceKey struct {
	IP    netip.Addr `json:"ip"`
	Port  uint16     `json:"port"`
	Proto string     `json:"proto"`
}

// Event is a reported change. Old/New carry banner fingerprints for
// service_changed and the previous state for *_back.
type Event struct {
	Time   time.Time  `json:"time"`
	Type   EventType  `json:"type"`
	IP     netip.Addr `json:"ip"`
	Port   uint16     `json:"port,omitempty"`
	Proto  string     `json:"proto,omitempty"`
	Old    string     `json:"old,omitempty"`
	New    string     `json:"new,omitempty"`
	Banner *Banner    `json:"banner,omitempty"`
	Source string     `json:"source"`
	Sensor string     `json:"sensor,omitempty"` // which sensor saw it, when several report to one place
	// Score and Reason are set by an optional stage between the sensor and
	// the trigger (edgegate): 0..1, higher = more interesting. The sensor
	// itself never sets them; absent means "not rated".
	Score  float64 `json:"score,omitempty"`
	Reason string  `json:"reason,omitempty"`
}

// Record is the persisted view of a host or service.
type Record struct {
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	State       State     `json:"state"`
	MAC         string    `json:"mac,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Banner      *Banner   `json:"banner,omitempty"`
}

// Config tunes the tracker.
type Config struct {
	// SilentAfter: no packets for this long marks a host/service silent.
	SilentAfter time.Duration
	// LearnUntil: observations before this time build the baseline silently.
	LearnUntil time.Time
	// Start: when this run started; silence is measured from
	// max(LastSeen, Start) so a loaded baseline gets a grace period.
	Start time.Time
	// Scope: what the sensor can report on. A loaded baseline may hold
	// addresses outside it (a network excluded since): those records stay
	// as they are but are never reported silent, because not watching an
	// address says nothing about it.
	Scope Scope
}

// Tracker holds the baseline and emits events on changes. Safe for
// concurrent use (capture loop + periodic sweep).
type Tracker struct {
	mu       sync.Mutex
	cfg      Config
	hosts    map[netip.Addr]*Record
	services map[ServiceKey]*Record
	emit     func(Event)
}

// NewTracker creates a tracker; emit receives every change event.
func NewTracker(cfg Config, emit func(Event)) *Tracker {
	return &Tracker{
		cfg:      cfg,
		hosts:    map[netip.Addr]*Record{},
		services: map[ServiceKey]*Record{},
		emit:     emit,
	}
}

func (t *Tracker) report(now time.Time, e Event) {
	if now.Before(t.cfg.LearnUntil) {
		return
	}
	e.Time = now
	e.Source = "passive"
	t.emit(e)
}

// Observe folds one observation into the state, emitting change events.
func (t *Tracker) Observe(o Observation) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.observeHost(o)
	if o.Port != 0 {
		t.observeService(o)
	}
}

func (t *Tracker) observeHost(o Observation) {
	h, ok := t.hosts[o.IP]
	if !ok {
		t.hosts[o.IP] = &Record{FirstSeen: o.Time, LastSeen: o.Time, State: StateActive, MAC: o.MAC}
		t.report(o.Time, Event{Type: HostNew, IP: o.IP, New: o.MAC})
		return
	}
	if o.Time.After(h.LastSeen) {
		h.LastSeen = o.Time
	}
	if o.MAC != "" {
		h.MAC = o.MAC
	}
	if h.State == StateSilent {
		h.State = StateActive
		t.report(o.Time, Event{Type: HostBack, IP: o.IP, Old: string(StateSilent)})
	}
}

func (t *Tracker) observeService(o Observation) {
	key := ServiceKey{IP: o.IP, Port: o.Port, Proto: o.Proto}
	base := Event{IP: o.IP, Port: o.Port, Proto: o.Proto}
	s, ok := t.services[key]

	if o.Signal == SignalClosed {
		// A closed port we never saw open is not a service; ignore it.
		if ok && s.State != StateClosed {
			old := s.State
			s.State, s.LastSeen = StateClosed, maxTime(s.LastSeen, o.Time)
			e := base
			e.Type, e.Old = ServiceClosed, string(old)
			t.report(o.Time, e)
		}
		return
	}

	fp := o.Banner.Fingerprint()
	if !ok {
		t.services[key] = &Record{FirstSeen: o.Time, LastSeen: o.Time, State: StateActive, Fingerprint: fp, Banner: o.Banner}
		e := base
		e.Type, e.New, e.Banner = ServiceNew, fp, o.Banner
		t.report(o.Time, e)
		return
	}

	s.LastSeen = maxTime(s.LastSeen, o.Time)
	if s.State != StateActive {
		old := s.State
		s.State = StateActive
		e := base
		e.Type, e.Old = ServiceBack, string(old)
		t.report(o.Time, e)
	}
	if fp == "" {
		return // SYN-ACK carries no banner; nothing to compare
	}
	if s.Fingerprint != fp {
		old := s.Fingerprint
		s.Fingerprint, s.Banner = fp, o.Banner
		if old != "" { // first banner for a known port is enrichment, not a change
			e := base
			e.Type, e.Old, e.New, e.Banner = ServiceChanged, old, fp, o.Banner
			t.report(o.Time, e)
		}
	}
}

// Sweep marks hosts and services silent when nothing was seen for
// SilentAfter. Call it periodically with the current (or packet) time.
func (t *Tracker) Sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, ip := range sortedAddrs(t.hosts) {
		h := t.hosts[ip]
		if h.State != StateSilent && t.cfg.Scope.Contains(ip) && t.expired(h, now) {
			h.State = StateSilent
			t.report(now, Event{Type: HostSilent, IP: ip})
		}
	}
	for _, k := range sortedKeys(t.services) {
		s := t.services[k]
		// A closed port stays closed until we see it open again.
		if s.State == StateActive && t.cfg.Scope.Contains(k.IP) && t.expired(s, now) {
			s.State = StateSilent
			t.report(now, Event{Type: ServiceSilent, IP: k.IP, Port: k.Port, Proto: k.Proto})
		}
	}
}

func (t *Tracker) expired(r *Record, now time.Time) bool {
	return t.cfg.SilentAfter > 0 && now.Sub(maxTime(r.LastSeen, t.cfg.Start)) > t.cfg.SilentAfter
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func sortedAddrs(m map[netip.Addr]*Record) []netip.Addr {
	out := make([]netip.Addr, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func sortedKeys(m map[ServiceKey]*Record) []ServiceKey {
	out := make([]ServiceKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP.Less(out[j].IP)
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}
