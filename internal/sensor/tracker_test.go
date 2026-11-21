package sensor

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var (
	t0  = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	web = netip.MustParseAddr("172.28.0.10")
)

type recorder struct{ events []Event }

func (r *recorder) emit(e Event) { r.events = append(r.events, e) }

func (r *recorder) types() []EventType {
	out := []EventType{}
	for _, e := range r.events {
		out = append(out, e.Type)
	}
	return out
}

func (r *recorder) reset() { r.events = nil }

func newTracker(cfg Config) (*Tracker, *recorder) {
	r := &recorder{}
	if cfg.Start.IsZero() {
		cfg.Start = t0
	}
	return NewTracker(cfg, r.emit), r
}

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func open(s int, port uint16, b *Banner) Observation {
	return Observation{Time: at(s), IP: web, Port: port, Proto: "tcp", Signal: SignalOpen, Banner: b}
}

func closed(s int, port uint16) Observation {
	return Observation{Time: at(s), IP: web, Port: port, Proto: "tcp", Signal: SignalClosed}
}

func expect(t *testing.T, r *recorder, want ...EventType) {
	t.Helper()
	if want == nil {
		want = []EventType{}
	}
	if got := r.types(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	r.reset()
}

func TestNewHostAndServiceAreReportedOnce(t *testing.T) {
	tr, r := newTracker(Config{})
	tr.Observe(open(0, 80, nil))
	expect(t, r, HostNew, ServiceNew)
	tr.Observe(open(1, 80, nil))
	tr.Observe(Observation{Time: at(2), IP: web, Signal: SignalSeen})
	expect(t, r)
}

func TestFirstBannerIsEnrichmentThenChangeIsReported(t *testing.T) {
	tr, r := newTracker(Config{})
	tr.Observe(open(0, 80, nil)) // SYN-ACK
	tr.Observe(open(1, 80, &Banner{Protocol: "http", Server: "nginx/1.25"}))
	expect(t, r, HostNew, ServiceNew)

	tr.Observe(open(2, 80, &Banner{Protocol: "http", Server: "nginx/1.25"}))
	expect(t, r)

	tr.Observe(open(3, 80, &Banner{Protocol: "http", Server: "Apache/2.4"}))
	if len(r.events) != 1 || r.events[0].Type != ServiceChanged ||
		r.events[0].Old != "http; server=nginx/1.25" || r.events[0].New != "http; server=Apache/2.4" {
		t.Fatalf("unexpected events: %+v", r.events)
	}
}

func TestClosedThenBack(t *testing.T) {
	tr, r := newTracker(Config{})
	tr.Observe(closed(0, 22)) // never seen open: not a service
	tr.Observe(open(1, 80, nil))
	r.reset()

	tr.Observe(closed(2, 80))
	tr.Observe(closed(3, 80)) // repeated RST: still one event
	expect(t, r, ServiceClosed)

	tr.Observe(open(4, 80, nil))
	if len(r.events) != 1 || r.events[0].Type != ServiceBack || r.events[0].Old != "closed" {
		t.Fatalf("unexpected events: %+v", r.events)
	}
}

func TestSilentAfterTimeoutThenBack(t *testing.T) {
	tr, r := newTracker(Config{SilentAfter: time.Minute})
	tr.Observe(open(0, 80, nil))
	r.reset()

	tr.Sweep(at(60)) // exactly SilentAfter: not yet
	expect(t, r)
	tr.Sweep(at(61))
	expect(t, r, HostSilent, ServiceSilent)
	tr.Sweep(at(120)) // already silent: no repeat
	expect(t, r)

	tr.Observe(open(130, 80, nil))
	expect(t, r, HostBack, ServiceBack)
}

func TestClosedServiceDoesNotGoSilent(t *testing.T) {
	tr, r := newTracker(Config{SilentAfter: time.Minute})
	tr.Observe(open(0, 80, nil))
	tr.Observe(closed(1, 80))
	r.reset()
	tr.Sweep(at(100))
	expect(t, r, HostSilent) // host silent, service keeps "closed"
}

func TestLearningSuppressesEventsButBuildsBaseline(t *testing.T) {
	tr, r := newTracker(Config{LearnUntil: at(10)})
	tr.Observe(open(0, 80, nil))
	expect(t, r)
	tr.Observe(open(11, 80, nil)) // already in baseline
	expect(t, r)
	tr.Observe(open(12, 443, nil))
	expect(t, r, ServiceNew)
}

func TestRestoredBaselineGetsGracePeriodAndKnownServicesAreNotNew(t *testing.T) {
	tr, _ := newTracker(Config{})
	tr.Observe(open(0, 80, &Banner{Protocol: "http", Server: "nginx"}))
	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveFile(path, tr.Snapshot()); err != nil {
		t.Fatal(err)
	}

	// Restart one hour later.
	snap, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tr2, r := newTracker(Config{SilentAfter: time.Minute, Start: at(3600)})
	tr2.Restore(snap)

	tr2.Sweep(at(3630)) // inside grace period
	expect(t, r)
	tr2.Observe(open(3631, 80, &Banner{Protocol: "http", Server: "nginx"}))
	expect(t, r)
	tr2.Observe(open(3632, 8080, nil))
	expect(t, r, ServiceNew)
}

func TestLoadMissingFileIsEmptyBaseline(t *testing.T) {
	s, err := LoadFile(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || len(s.Hosts) != 0 {
		t.Fatalf("got %+v, %v", s, err)
	}
}
