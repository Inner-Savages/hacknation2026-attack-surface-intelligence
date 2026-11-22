package sensor

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func prefixes(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	ps, err := ParsePrefixes(s)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestParsePrefixes(t *testing.T) {
	got := FormatPrefixes(prefixes(t, " 172.18.0.0/16, 10.0.0.5,,10.1.2.3/8 ,::ffff:10.0.0.6"))
	if want := "172.18.0.0/16,10.0.0.5/32,10.0.0.0/8,10.0.0.6/32"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if ps := prefixes(t, ""); ps != nil {
		t.Errorf("empty list: %v", ps)
	}
	for _, bad := range []string{"172.18.0.0/33", "10.0.0", "web.local", "10.0.0.1-20"} {
		if _, err := ParsePrefixes(bad); err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("%s: error should name the entry, got %v", bad, err)
		}
	}
}

func TestScopeContains(t *testing.T) {
	s := Scope{Watch: prefixes(t, "172.16.0.0/12"), Exclude: prefixes(t, "172.18.0.0/16,172.28.0.5")}
	for a, want := range map[string]bool{
		"172.28.0.4": true, "172.28.0.6": true, "172.17.255.255": true,
		"172.28.0.5": false, "172.18.0.1": false, "10.0.0.1": false, "0.0.0.0": false,
	} {
		if got := s.Contains(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v, want %v", a, got, want)
		}
	}
	if !(Scope{}).Contains(web) {
		t.Error("the zero scope is everything")
	}
	if (Scope{}).Contains(netip.Addr{}) {
		t.Error("an invalid address is never in scope")
	}
}

func TestScopeValidate(t *testing.T) {
	for _, tc := range []struct {
		watch, exclude string
		ok             bool
	}{
		{"172.28.0.0/24", "", true},
		{"172.28.0.0/24", "172.28.0.0/25", true},
		{"172.28.0.0/24,10.0.0.0/8", "172.28.0.0/16", true},
		{"", "172.16.0.0/12", true},
		{"172.28.0.0/24", "172.16.0.0/12", false},
		{"172.28.0.0/24,10.0.0.0/8", "172.28.0.0/24,10.0.0.0/8", false},
		{"", "0.0.0.0/0", false},
	} {
		err := Scope{Watch: prefixes(t, tc.watch), Exclude: prefixes(t, tc.exclude)}.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("watch %q exclude %q: %v", tc.watch, tc.exclude, err)
		}
	}
}

// The excluded side of a conversation is invisible, the other side is not.
func TestDecodeSkipsExcludedAddresses(t *testing.T) {
	d := NewDecoder(Scope{Watch: labNet, Exclude: prefixes(t, "172.28.0.100")})
	synAck := func(c *layers.TCP) { c.SYN, c.ACK = true, true }
	if obs := d.Decode(tcpFrame(t, "172.28.0.100", "172.28.0.10", 8000, 40000, synAck, nil), t0); len(obs) != 0 {
		t.Errorf("excluded server: %+v", obs)
	}
	obs := d.Decode(tcpFrame(t, "172.28.0.10", "172.28.0.100", 80, 40000, synAck, nil), t0)
	if s := serviceObs(obs); s == nil || s.IP != web {
		t.Errorf("service answering an excluded client must still be seen: %+v", obs)
	}
}

// A baseline recorded before the exclusion: its excluded entries are kept
// but must not turn into host_silent/service_silent (and a scan) later on.
func TestExcludedBaselineEntriesAreKeptButNeverGoSilent(t *testing.T) {
	old, _ := newTracker(Config{})
	edge := netip.MustParseAddr("172.18.0.2")
	old.Observe(open(0, 80, nil))
	old.Observe(Observation{Time: at(0), IP: edge, Port: 8000, Proto: "tcp", Signal: SignalOpen})

	tr, r := newTracker(Config{SilentAfter: time.Minute, Scope: Scope{Exclude: prefixes(t, "172.18.0.0/16")}})
	tr.Restore(old.Snapshot())
	tr.Sweep(at(120))
	expect(t, r, HostSilent, ServiceSilent) // only the watched host and its service

	snap := tr.Snapshot()
	if len(snap.Hosts) != 2 || len(snap.Services) != 2 {
		t.Fatalf("excluded entries must survive: %+v", snap)
	}
	for _, h := range snap.Hosts {
		if h.IP == edge && h.State != StateActive {
			t.Errorf("excluded host changed state: %+v", h)
		}
	}
}
