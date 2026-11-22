package trigger

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/sensor"
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func ev(typ sensor.EventType, ip string, port uint16) sensor.Event {
	return sensor.Event{Type: typ, IP: netip.MustParseAddr(ip), Port: port}
}

func policy() *Policy {
	return &Policy{
		Allow: []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")},
		Self:  []netip.Addr{netip.MustParseAddr("172.20.0.1")},
	}
}

func TestEventKinds(t *testing.T) {
	cases := map[sensor.EventType]Kind{
		sensor.ServiceNew: ScanService, sensor.ServiceChanged: ScanService, sensor.ServiceBack: ScanService,
		sensor.HostNew: ScanHost, sensor.HostBack: ScanHost,
		sensor.ServiceSilent: VerifyService, sensor.ServiceClosed: VerifyService, sensor.HostSilent: VerifyHost,
	}
	for typ, want := range cases {
		p := policy()
		if ok, why := p.Offer(ev(typ, "172.20.0.5", 80), at(0)); !ok {
			t.Fatalf("%s rejected: %s", typ, why)
		}
		jobs := p.Take(at(60), 10)
		if len(jobs) != 1 || jobs[0].Kind != want {
			t.Errorf("%s -> %+v, want %s", typ, jobs, want)
		}
		if want == ScanHost || want == VerifyHost {
			if jobs[0].Target.Port != 0 {
				t.Errorf("%s: host job must not carry a port", typ)
			}
		}
	}
}

func TestAllowListAndSelf(t *testing.T) {
	p := policy()
	if ok, why := p.Offer(ev(sensor.HostNew, "10.9.9.9", 0), at(0)); ok || why != "outside allow list" {
		t.Errorf("outside: %v %q", ok, why)
	}
	if ok, why := p.Offer(ev(sensor.HostBack, "172.20.0.1", 0), at(0)); ok || why != "scanner's own address" {
		t.Errorf("self: %v %q", ok, why)
	}
	if p.Counters["dropped: outside allow list"] != 1 || p.Pending() != 0 {
		t.Errorf("counters %v pending %d", p.Counters, p.Pending())
	}
}

func TestDebounceCoalescesEvents(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.ServiceSilent, "172.20.0.5", 80), at(0))
	p.Offer(ev(sensor.ServiceBack, "172.20.0.5", 80), at(2))
	p.Offer(ev(sensor.ServiceChanged, "172.20.0.5", 80), at(3))
	if jobs := p.Take(at(7), 10); len(jobs) != 0 {
		t.Fatalf("not due yet (last event at 3s + 5s): %+v", jobs)
	}
	jobs := p.Take(at(8), 10)
	if len(jobs) != 1 || len(jobs[0].Events) != 3 || jobs[0].Kind != ScanService {
		t.Fatalf("want one scan for three events: %+v", jobs)
	}
}

func TestQuietWindowDropsSelfInflictedEvents(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.HostNew, "172.20.0.8", 0), at(0))
	job := p.Take(at(5), 10)[0]

	// The host scan reveals ports the sensor never saw before.
	if ok, why := p.Offer(ev(sensor.ServiceNew, "172.20.0.8", 22), at(10)); ok || why != "quiet: address is being scanned" {
		t.Fatalf("during scan: %v %q", ok, why)
	}
	p.Done(job.Target, at(20), false)
	if ok, why := p.Offer(ev(sensor.ServiceNew, "172.20.0.8", 3306), at(30)); ok || why != "quiet: address just scanned" {
		t.Fatalf("right after: %v %q", ok, why)
	}
	if ok, _ := p.Offer(ev(sensor.ServiceClosed, "172.20.0.8", 22), at(40)); !ok {
		t.Fatal("after the quiet window events count again")
	}
}

func TestQuietIsPerAddressAcrossPortsAndHost(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.ServiceSilent, "172.20.0.3", 80), at(0))
	p.Take(at(5), 10)
	// Scanning the port makes the silent host talk again.
	if ok, _ := p.Offer(ev(sensor.HostBack, "172.20.0.3", 0), at(6)); ok {
		t.Fatal("host_back caused by the port scan must be dropped")
	}
	if ok, _ := p.Offer(ev(sensor.HostBack, "172.20.0.4", 0), at(6)); !ok {
		t.Fatal("other addresses are not affected")
	}
}

func TestCooldownPostponesInsteadOfDropping(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.ServiceChanged, "172.20.0.5", 80), at(0))
	j := p.Take(at(5), 10)[0]
	p.Done(j.Target, at(10), false)

	p.Offer(ev(sensor.ServiceChanged, "172.20.0.5", 80), at(30)) // after quiet (15s), within cooldown (60s)
	if jobs := p.Take(at(69), 10); len(jobs) != 0 {
		t.Fatalf("cooldown ends at 70s: %+v", jobs)
	}
	if jobs := p.Take(at(70), 10); len(jobs) != 1 {
		t.Fatalf("want the postponed scan at 70s: %+v", jobs)
	}
}

func TestClosedOnlyGetsLongerCooldown(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.ServiceClosed, "172.20.0.4", 80), at(0)) // flapper
	j := p.Take(at(5), 10)[0]
	p.Done(j.Target, at(10), false)
	p.Offer(ev(sensor.ServiceClosed, "172.20.0.4", 80), at(100))
	if jobs := p.Take(at(200), 10); len(jobs) != 0 {
		t.Fatalf("closed-only cooldown is 5m: %+v", jobs)
	}
	if jobs := p.Take(at(310), 10); len(jobs) != 1 {
		t.Fatal("due after 5m")
	}

	// A service_back in the mix turns it back into a normal cooldown.
	p2 := policy()
	p2.Offer(ev(sensor.ServiceClosed, "172.20.0.4", 80), at(0))
	p2.Done(p2.Take(at(5), 10)[0].Target, at(10), false)
	p2.Offer(ev(sensor.ServiceClosed, "172.20.0.4", 80), at(30))
	p2.Offer(ev(sensor.ServiceBack, "172.20.0.4", 80), at(31))
	if jobs := p2.Take(at(70), 10); len(jobs) != 1 || jobs[0].Kind != ScanService {
		t.Fatalf("mixed events: %+v", jobs)
	}
}

func TestRateLimitAndFreeSlots(t *testing.T) {
	p := policy()
	p.MaxPerMinute = 10
	for i := 0; i < 15; i++ {
		p.Offer(ev(sensor.HostNew, fmt.Sprintf("172.20.1.%d", i), 0), at(0))
	}
	if jobs := p.Take(at(10), 3); len(jobs) != 3 {
		t.Fatalf("free slots: %d", len(jobs))
	}
	if jobs := p.Take(at(11), 100); len(jobs) != 7 {
		t.Fatalf("rate limit leaves 7 more this minute, got %d", len(jobs))
	}
	if jobs := p.Take(at(30), 100); len(jobs) != 0 {
		t.Fatalf("still within the minute: %d", len(jobs))
	}
	if jobs := p.Take(at(71), 100); len(jobs) != 5 {
		t.Fatalf("next minute: %d", len(jobs))
	}
}

func TestPendingCap(t *testing.T) {
	p := policy()
	p.MaxPending = 2
	p.Offer(ev(sensor.HostNew, "172.20.0.10", 0), at(0))
	p.Offer(ev(sensor.HostNew, "172.20.0.11", 0), at(0))
	if ok, why := p.Offer(ev(sensor.HostNew, "172.20.0.12", 0), at(0)); ok || why != "too many pending jobs" {
		t.Fatalf("%v %q", ok, why)
	}
	if ok, _ := p.Offer(ev(sensor.HostBack, "172.20.0.10", 0), at(1)); !ok {
		t.Fatal("events for an already pending target still merge")
	}
}

func TestServiceEventsJoinPendingHostScan(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.HostNew, "172.20.0.40", 0), at(0))
	p.Offer(ev(sensor.ServiceNew, "172.20.0.40", 80), at(1)) // same burst: the host scan covers it
	jobs := p.Take(at(10), 10)
	if len(jobs) != 1 || jobs[0].Kind != ScanHost || len(jobs[0].Events) != 2 {
		t.Fatalf("want one host scan carrying both events: %+v", jobs)
	}
	// A host verification does not absorb a new service: that is a change to scan.
	p2 := policy()
	p2.Offer(ev(sensor.HostSilent, "172.20.0.41", 0), at(0))
	p2.Offer(ev(sensor.ServiceNew, "172.20.0.41", 80), at(1))
	if jobs := p2.Take(at(10), 10); len(jobs) != 2 {
		t.Fatalf("verify-host + scan-service: %+v", jobs)
	}
}

// A host nobody talks to goes silent again a minute after every scan that
// woke it up: once verified alive, stop re-verifying it.
func TestVerifiedAliveStopsSilenceLoop(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.HostSilent, "172.20.0.33", 0), at(0))
	j := p.Take(at(5), 10)[0]
	p.Done(j.Target, at(10), true) // still-up
	if ok, why := p.Offer(ev(sensor.HostSilent, "172.20.0.33", 0), at(90)); ok || why != "verified alive recently" {
		t.Fatalf("re-verification: %v %q", ok, why)
	}
	if ok, _ := p.Offer(ev(sensor.ServiceNew, "172.20.0.33", 8080), at(91)); !ok {
		t.Fatal("real changes still get scanned")
	}
	if ok, _ := p.Offer(ev(sensor.HostSilent, "172.20.0.33", 0), at(10+31*60)); !ok {
		t.Fatal("after the backoff silence is checked again")
	}
}

func scored(typ sensor.EventType, ip string, port uint16, score float64, reason string) sensor.Event {
	e := ev(typ, ip, port)
	e.Score, e.Reason = score, reason
	return e
}

// edgegate contract: "score"/"reason" are optional extra fields of the event.
func TestScoreFieldsDecodeAndAreOptional(t *testing.T) {
	var events []sensor.Event
	body := `[{"type":"host_new","ip":"172.20.0.8","source":"passive","score":0.87,"reason":"cascade escalation"},
	          {"type":"host_silent","ip":"172.20.0.9","source":"passive"}]`
	if err := json.Unmarshal([]byte(body), &events); err != nil {
		t.Fatal(err)
	}
	if events[0].Score != 0.87 || events[0].Reason != "cascade escalation" || events[1].Score != 0 || events[1].Reason != "" {
		t.Fatalf("decoded: %+v", events)
	}
	out, _ := json.Marshal(ev(sensor.HostNew, "172.20.0.8", 0))
	if strings.Contains(string(out), "score") || strings.Contains(string(out), "reason") {
		t.Fatalf("unrated events must not carry the fields: %s", out)
	}
}

func TestJobKeepsHighestScore(t *testing.T) {
	p := policy()
	p.Offer(scored(sensor.ServiceSilent, "172.20.0.5", 80, 0.3, "verification passthrough"), at(0))
	p.Offer(scored(sensor.ServiceBack, "172.20.0.5", 80, 0.9, "cascade escalation"), at(1))
	p.Offer(scored(sensor.ServiceChanged, "172.20.0.5", 80, 0.5, "banner"), at(2))
	j := p.Take(at(10), 10)[0]
	if j.Score != 0.9 || j.Reason != "cascade escalation" {
		t.Fatalf("score %v reason %q", j.Score, j.Reason)
	}
	// Events joining a pending host scan are rated too.
	p.Offer(ev(sensor.HostNew, "172.20.0.40", 0), at(20))
	p.Offer(scored(sensor.ServiceNew, "172.20.0.40", 80, 0.7, "new web service"), at(21))
	if hj := p.Take(at(30), 10)[0]; hj.Score != 0.7 || hj.Kind != ScanHost {
		t.Fatalf("host job: %+v", hj)
	}
}

func TestTakePrefersHigherScoreWhenBudgetIsLimited(t *testing.T) {
	p := policy()
	p.Offer(ev(sensor.HostNew, "172.20.1.1", 0), at(0))                          // unrated, oldest
	p.Offer(scored(sensor.HostNew, "172.20.1.2", 0, 0.2, "low"), at(1))          // rated low
	p.Offer(scored(sensor.HostNew, "172.20.1.3", 0, 0.95, "interesting"), at(2)) // rated high, newest
	got := p.Take(at(10), 2)
	if len(got) != 2 || got[0].Target.IP.String() != "172.20.1.3" || got[1].Target.IP.String() != "172.20.1.2" {
		t.Fatalf("order: %+v", got)
	}
	// Without scores the order stays by due time, as before.
	q := policy()
	q.Offer(ev(sensor.HostNew, "172.20.2.9", 0), at(0))
	q.Offer(ev(sensor.HostNew, "172.20.2.1", 0), at(1))
	if got := q.Take(at(10), 1); got[0].Target.IP.String() != "172.20.2.9" {
		t.Fatalf("unrated order: %+v", got)
	}
}

func TestIgnoredNetworksAreNeverScanned(t *testing.T) {
	p := policy()
	p.Ignore = []netip.Prefix{netip.MustParsePrefix("172.20.8.0/24"), netip.MustParsePrefix("172.20.0.9/32")}
	for _, ip := range []string{"172.20.8.4", "172.20.0.9"} {
		for _, typ := range []sensor.EventType{sensor.HostNew, sensor.ServiceChanged, sensor.HostSilent} {
			if ok, why := p.Offer(ev(typ, ip, 80), at(0)); ok || why != "ignored network" {
				t.Errorf("%s %s: %v %q", typ, ip, ok, why)
			}
		}
	}
	if ok, why := p.Offer(ev(sensor.HostNew, "172.20.0.10", 0), at(0)); !ok {
		t.Errorf("neighbour must still be scanned: %s", why)
	}
	if p.Counters["dropped: ignored network"] != 6 || p.Pending() != 1 {
		t.Errorf("counters %v pending %d", p.Counters, p.Pending())
	}
	// An IPv4-mapped spelling must not slip past the ignore list.
	p.Allow = append(p.Allow, netip.MustParsePrefix("::/0"))
	if ok, why := p.Offer(ev(sensor.HostNew, "::ffff:172.20.8.4", 0), at(0)); ok || why != "ignored network" {
		t.Errorf("mapped address: %v %q", ok, why)
	}
}
