package aiml

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func evAt(t time.Time, typ, ip string, port int) Event {
	return Event{Time: t.UTC().Format(time.RFC3339Nano), Type: typ, IP: ip, Port: port, Proto: "tcp", Source: "passive"}
}

// pump feeds n events for ip, one per second starting at t0, and returns the
// feature vector of the last one.
func pump(x *Extractor, t0 time.Time, ip string, n int) []float64 {
	var f []float64
	for i := 0; i < n; i++ {
		f = x.Features(evAt(t0.Add(time.Duration(i)*time.Second), "service_new", ip, 80))
	}
	return f
}

// A host idle longer than the TTL (in stream time) is evicted, and a sensor
// watching many IPs keeps bounded memory instead of growing forever.
func TestExtractorTTLEviction(t *testing.T) {
	ttl := time.Hour
	x := NewExtractorWithTTL(ttl)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	pump(x, t0, "10.0.0.1", 3)
	if x.Hosts() != 1 {
		t.Fatalf("expected 1 tracked host, got %d", x.Hosts())
	}
	// Move stream time well past the TTL with traffic from other hosts; the
	// amortized sweep runs every sweepEvery events.
	pump(x, t0.Add(2*ttl), "10.0.0.2", sweepEvery+10)
	if x.Hosts() != 1 {
		t.Fatalf("stale host was not evicted: %d hosts", x.Hosts())
	}
	if x.Evicted() != 1 {
		t.Fatalf("expected 1 eviction, got %d", x.Evicted())
	}
	// The evicted host is relearned from scratch: host_seen_before (f[22])
	// flips back to 0, the honest signal after a full baseline window away.
	f := x.Features(evAt(t0.Add(2*ttl+time.Minute), "host_back", "10.0.0.1", 0))
	if f[22] != 0 {
		t.Fatalf("evicted host should look new again, f[22]=%v", f[22])
	}
}

// Without a TTL (one-shot tools, replay-compatible default) nothing is
// evicted, however long the silence.
func TestExtractorNoTTLKeepsHosts(t *testing.T) {
	x := NewExtractor()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pump(x, t0, "10.0.0.1", 3)
	pump(x, t0.Add(720*time.Hour), "10.0.0.2", sweepEvery+10)
	if x.Hosts() != 2 {
		t.Fatalf("host evicted without TTL: %d hosts", x.Hosts())
	}
	f := x.Features(evAt(t0.Add(721*time.Hour), "host_back", "10.0.0.1", 0))
	if f[22] != 1 {
		t.Fatalf("long-absent host must be remembered without TTL, f[22]=%v", f[22])
	}
}

// A checkpoint round-trips the host table: after save + load the same next
// event yields the identical feature vector.
func TestCheckpointRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	x1 := NewExtractor()
	pump(x1, t0, "10.0.0.1", 30)
	pump(x1, t0, "10.0.0.2", 10)
	x1.Features(evAt(t0.Add(time.Minute), "service_changed", "10.0.0.1", 22))

	var buf bytes.Buffer
	if err := x1.SaveCheckpoint(&buf); err != nil {
		t.Fatal(err)
	}
	x2 := NewExtractor()
	n, err := x2.LoadCheckpoint(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || x2.Hosts() != 2 {
		t.Fatalf("loaded %d hosts, tracked %d", n, x2.Hosts())
	}
	next := evAt(t0.Add(2*time.Minute), "service_new", "10.0.0.1", 3389)
	f1, f2 := x1.Features(next), x2.Features(next)
	if !reflect.DeepEqual(f1, f2) {
		t.Fatalf("feature mismatch after restore:\norig:    %v\nrestored:%v", f1, f2)
	}
}

// Hosts already stale at save time are not resurrected by a load.
func TestCheckpointLoadSkipsStaleHosts(t *testing.T) {
	ttl := time.Hour
	t0 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	x1 := NewExtractor() // no TTL: stale hosts survive in the file
	pump(x1, t0, "10.0.0.1", 3)
	pump(x1, t0.Add(5*ttl), "10.0.0.2", 3)

	var buf bytes.Buffer
	if err := x1.SaveCheckpoint(&buf); err != nil {
		t.Fatal(err)
	}
	x2 := NewExtractorWithTTL(ttl)
	n, err := x2.LoadCheckpoint(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("stale host was resurrected: loaded %d hosts", n)
	}
	f := x2.Features(evAt(t0.Add(5*ttl+time.Minute), "host_back", "10.0.0.1", 0))
	if f[22] != 0 {
		t.Fatalf("stale host should be unknown after load, f[22]=%v", f[22])
	}
}

func TestCheckpointRejectsUnknownVersion(t *testing.T) {
	x := NewExtractor()
	if _, err := x.LoadCheckpoint(strings.NewReader(`{"version":999,"hosts":{}}`)); err == nil {
		t.Fatal("unsupported checkpoint version accepted")
	}
	if _, err := x.LoadCheckpoint(strings.NewReader(`not json`)); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
}

// A scanner cycling thousands of ports on one host must not grow the
// per-host port set without limit.
func TestPortSetIsBounded(t *testing.T) {
	x := NewExtractor()
	t0 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	for p := 1; p <= 3*maxPortsPerHost; p++ {
		x.Features(evAt(t0.Add(time.Duration(p)*time.Second), "service_new", "10.0.0.9", p))
	}
	var buf bytes.Buffer
	if err := x.SaveCheckpoint(&buf); err != nil {
		t.Fatal(err)
	}
	var cp ExtractorCheckpoint
	if err := json.Unmarshal(buf.Bytes(), &cp); err != nil {
		t.Fatal(err)
	}
	if got := len(cp.Hosts["10.0.0.9"].Ports); got > maxPortsPerHost {
		t.Fatalf("port set grew past the cap: %d", got)
	}
}
