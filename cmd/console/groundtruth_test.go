package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDial answers TCP connects from a map of "ip:port" -> banner; missing
// addresses refuse the connection, like a closed port would.
func fakeDial(open map[string]string) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		banner, ok := open[address]
		if !ok {
			return nil, &net.OpError{Op: "dial", Net: network, Err: errClosed{}}
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if banner != "" {
				_, _ = server.Write([]byte(banner))
			}
			// Keep the connection open briefly, like a real service would.
			time.Sleep(50 * time.Millisecond)
		}()
		return client, nil
	}
}

type errClosed struct{}

func (errClosed) Error() string   { return "connection refused" }
func (errClosed) Timeout() bool   { return false }
func (errClosed) Temporary() bool { return true }

func TestRegistryObserveAndSilentSelection(t *testing.T) {
	r := &hostRegistry{hosts: map[string]*HostRecord{}}
	now := time.Now()

	r.Observe(sensorLog{Type: "service_new", IP: "10.0.0.5", Port: 80, Proto: "tcp"}, "edge-1", now)
	h := r.hosts["10.0.0.5"]
	if h == nil || len(h.Services) != 1 {
		t.Fatalf("service_new should register the service: %+v", h)
	}
	if h.SilentSince != nil {
		t.Fatal("active host must not be silent")
	}

	silentAt := now.Add(-2 * time.Hour)
	r.Observe(sensorLog{Type: "host_silent", IP: "10.0.0.5"}, "edge-1", silentAt)
	if h.SilentSince == nil || !h.SilentSince.Equal(silentAt) {
		t.Fatalf("host_silent should start the silent clock: %+v", h.SilentSince)
	}
	// A repeated silent event keeps the original start.
	r.Observe(sensorLog{Type: "host_silent", IP: "10.0.0.5"}, "edge-1", now)
	if !h.SilentSince.Equal(silentAt) {
		t.Fatal("repeated host_silent must not reset the silent clock")
	}

	got := r.silentHosts(time.Hour, now)
	if len(got) != 1 || got[0].IP != "10.0.0.5" {
		t.Fatalf("silentHosts = %v", got)
	}

	// Any sign of life clears the silence.
	r.Observe(sensorLog{Type: "service_new", IP: "10.0.0.5", Port: 443, Proto: "tcp"}, "edge-1", now)
	if h.SilentSince != nil {
		t.Fatal("sign of life should clear silence")
	}
	if len(r.silentHosts(0, now)) != 0 {
		t.Fatal("host should no longer qualify for a control scan")
	}
}

func TestProbeFirstScanEstablishesBaseline(t *testing.T) {
	h := &HostRecord{IP: "10.0.0.7"}
	open := map[string]string{"10.0.0.7:22": "SSH-2.0-OpenSSH_9.6"}
	probe := probeHost(context.Background(), h, fakeDial(open), 100*time.Millisecond)

	if !probe.First {
		t.Fatal("first scan of a host must be marked as baseline-establishing")
	}
	if len(probe.Changes) != 0 {
		t.Fatalf("first scan must not report changes, got %v", probe.Changes)
	}
	if got := probe.Open["22/tcp"]; got != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("banner = %q", got)
	}
	if classify(probe) != verdictQuiet {
		t.Fatalf("first contact verdict = %q, want quiet", classify(probe))
	}
}

func TestProbeDetectsDriftAgainstBaseline(t *testing.T) {
	h := &HostRecord{
		IP: "10.0.0.9",
		Baseline: map[string]string{
			"22/tcp": "SSH-2.0-OpenSSH_9.6",
			"80/tcp": "",
		},
	}
	open := map[string]string{
		"10.0.0.9:22":   "SSH-2.0-OpenSSH_10.0", // banner drift
		"10.0.0.9:8080": "rogue",                // new service
		// :80 gone — drift by disappearance
	}
	probe := probeHost(context.Background(), h, fakeDial(open), 100*time.Millisecond)

	if probe.First {
		t.Fatal("host with a baseline is not first contact")
	}
	if classify(probe) != verdictChanged {
		t.Fatalf("verdict = %q, want changed (%v)", classify(probe), probe.Changes)
	}
	joined := strings.Join(probe.Changes, "\n")
	for _, want := range []string{"zmieniony banner", "nowa usługa", "nie odpowiada"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("changes missing %q:\n%s", want, joined)
		}
	}
}

func TestProbeUnreachabilityKeepsBaseline(t *testing.T) {
	h := &HostRecord{IP: "10.0.0.11", Baseline: map[string]string{"22/tcp": "x"}}
	probe := probeHost(context.Background(), h, fakeDial(map[string]string{}), 50*time.Millisecond)
	if classify(probe) != verdictUnreachable {
		t.Fatalf("verdict = %q, want unreachable", classify(probe))
	}
}

func newTestGroundTruth(t *testing.T, dial dialFunc) (*groundTruth, *Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	feed := newLiveFeed(100)
	cfg, err := openSettings(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gt, err := newGroundTruth(dir, store, feed, cfg, "tester")
	if err != nil {
		t.Fatal(err)
	}
	gt.dial = dial
	return gt, store
}

func TestRunEscalatesSilentStealthSuspect(t *testing.T) {
	open := map[string]string{"10.0.0.30:8080": "rogue-http"}
	gt, store := newTestGroundTruth(t, fakeDial(open))

	now := time.Now()
	silentAt := now.Add(-3 * time.Hour)
	gt.registry.Observe(sensorLog{Type: "host_silent", IP: "10.0.0.30"}, "edge-9", silentAt)

	gt.run("test")

	// First run establishes the baseline, including the rogue service —
	// ground truth starts from what is actually there.
	if cases := store.ListCases(); len(cases) != 0 {
		t.Fatalf("first run must not escalate, got %d cases", len(cases))
	}
	h := gt.registry.hosts["10.0.0.30"]
	if h.Baseline["8080/tcp"] != "rogue-http" {
		t.Fatalf("baseline = %v", h.Baseline)
	}

	// The attacker adds another quiet service on a commonly probed port:
	// the second run must escalate.
	open["10.0.0.30:6379"] = "rogue-redis"
	gt.run("test")

	cases := store.ListCases()
	if len(cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(cases))
	}
	c := cases[0]
	if c.EventType != "ground_truth_change" || c.Source != "10.0.0.30" || c.SensorID != "edge-9" {
		t.Fatalf("case = %+v", c)
	}
	if !strings.Contains(c.Reason, "silent_stealth") || !strings.Contains(c.Reason, "6379") {
		t.Fatalf("reason should explain the gap and list the change: %s", c.Reason)
	}

	// The drift became the new baseline: a third run must stay quiet.
	gt.run("test")
	if cases := store.ListCases(); len(cases) != 1 {
		t.Fatalf("repeat run must not re-escalate the same drift, got %d cases", len(cases))
	}
}

func TestRunSkipsHostsBelowSilenceThreshold(t *testing.T) {
	gt, store := newTestGroundTruth(t, fakeDial(map[string]string{}))

	now := time.Now()
	// Silent for only a minute — below the default one-hour threshold.
	gt.registry.Observe(sensorLog{Type: "host_silent", IP: "10.0.0.40"}, "edge-1", now.Add(-time.Minute))

	gt.run("test")
	gt.mu.Lock()
	sum := gt.lastSum
	gt.mu.Unlock()
	if !strings.Contains(sum, "brak hostów") {
		t.Fatalf("summary = %q", sum)
	}
	if cases := store.ListCases(); len(cases) != 0 {
		t.Fatalf("no cases expected, got %d", len(cases))
	}
}
