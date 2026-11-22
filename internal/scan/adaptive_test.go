package scan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

func TestPlannerFixed(t *testing.T) {
	p := (&Scanner{ChunkSize: 3}).planner()
	if n, _ := p.next(8, 0, false); n != 3 {
		t.Fatalf("got %d", n)
	}
	p.done(3, time.Hour) // fixed chunking ignores the speed
	if n, _ := p.next(8, 0, false); n != 3 {
		t.Fatalf("got %d", n)
	}
	if n, _ := p.next(2, 0, false); n != 2 {
		t.Fatalf("last chunk: %d", n)
	}
	if n, _ := p.next(0, 0, false); n != 0 {
		t.Fatalf("nothing left: %d", n)
	}
}

func TestPlannerAimsForTargetDuration(t *testing.T) {
	p := (&Scanner{ChunkTarget: time.Minute, ChunkSize: 32, MinChunk: 4, MaxChunk: 500, Parallel: 2}).planner()
	if n, why := p.next(100000, 0, false); n != 32 || !strings.Contains(why, "unknown") {
		t.Fatalf("first: %d %q", n, why)
	}
	if p.eta(100) != 0 {
		t.Fatal("ETA must be unknown before the first chunk")
	}
	p.done(32, 16*time.Second) // 0.5 s/target -> 120 fit a minute
	if n, _ := p.next(100000, 0, false); n != 120 {
		t.Fatalf("want 120, got %d", n)
	}
	if got := p.eta(1000); got != 250*time.Second { // 1000 * 0.5s / 2 workers
		t.Fatalf("eta %v", got)
	}
	// A suspiciously fast chunk may only grow the size maxStep times.
	p.perTarget = 0.0001
	if n, why := p.next(100000, 0, false); n != 32*maxStep || !strings.Contains(why, "limited") {
		t.Fatalf("step: %d %q", n, why)
	}
	p.largest = 10000
	if n, _ := p.next(100000, 0, false); n != 500 {
		t.Fatalf("max: %d", n)
	}
	p.perTarget = 600
	if n, _ := p.next(100000, 0, false); n != 4 {
		t.Fatalf("min: %d", n)
	}
	// Tail: 20 targets for two workers.
	p.perTarget = 0.5
	if n, why := p.next(20, 0, false); n != 10 || !strings.Contains(why, "tail") {
		t.Fatalf("tail: %d %q", n, why)
	}
	if n, _ := p.next(2, 0, false); n != 2 {
		t.Fatalf("rest: %d", n)
	}
}

func TestPlannerRespectsDeadline(t *testing.T) {
	p := (&Scanner{ChunkTarget: time.Minute, MinChunk: 4}).planner()
	p.done(100, 50*time.Second) // 0.5 s/target
	if n, why := p.next(10000, 10*time.Second, true); n != 20 || !strings.Contains(why, "window") {
		t.Fatalf("got %d %q", n, why)
	}
	if n, _ := p.next(10000, 100*time.Millisecond, true); n != 0 {
		t.Fatalf("nothing fits: %d", n)
	}
	if n, _ := p.next(10000, -time.Second, true); n != 0 {
		t.Fatalf("past deadline: %d", n)
	}
}

func TestPlannerStartsFromEstimateOrEarlierSpeed(t *testing.T) {
	// 1000 ports at 200/s without discovery: up to 10 s per target.
	s := Scanner{Options: Options{MaxRate: 200, SkipDiscovery: true}, ChunkTarget: time.Minute}
	if n, why := s.planner().next(1000, 0, false); n != 6 || !strings.Contains(why, "expected") {
		t.Fatalf("%d %q", n, why)
	}
	// Fast estimate: still start small, it is only a guess.
	s.Options.Ports = "22,80,8000-8009"
	if n, _ := s.planner().next(1000, 0, false); n != firstChunk {
		t.Fatalf("%d", n)
	}
	s.Speed = 20 * time.Second
	if n, _ := s.planner().next(1000, 0, false); n != 3 {
		t.Fatalf("%d", n)
	}
	// Slower than the whole window: one target is tried, then no more.
	p := s.planner()
	if n, _ := p.next(1000, 5*time.Second, true); n != 1 {
		t.Fatalf("%d", n)
	}
	if n, _ := p.next(1000, 5*time.Second, true); n != 0 {
		t.Fatalf("%d", n)
	}
	for shrink, want := range map[int]int{0: 256, 1: 128, 4: 16, 20: 1} {
		f := Scanner{Shrink: shrink}
		if n, _ := f.planner().next(1000, 0, false); n != want {
			t.Errorf("shrink %d: %d, want %d", shrink, n, want)
		}
	}
	if d := (Options{MaxRate: 100, Ports: "T:22,80,100-197"}).estimate(); d != time.Second {
		t.Fatalf("estimate %v", d)
	}
}

// 10k+ targets against the fake nmap: every target scanned exactly once,
// and the chunks settle near the requested duration.
func TestScale10kTargetsAdaptive(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	t.Setenv("FAKE_NMAP_US", "2000")
	t.Setenv("FAKE_NMAP_LOG", log)
	var tg Targets
	_ = tg.Add("10.0.0.0/18") // 16384
	s := Scanner{
		Options:     Options{Binary: "testdata/fake-nmap.sh", VersionMode: VersionFull},
		Parallel:    8,
		ChunkTarget: 500 * time.Millisecond,
	}
	var last Progress
	var sawETA bool
	s.Progress = func(p Progress) {
		last = p
		sawETA = sawETA || p.ETA > 0
	}
	res, err := s.Scan(context.Background(), &tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 16384 || last.Done != 16384 || last.Total != 16384 || last.ETA != 0 || !sawETA {
		t.Fatalf("hosts %d, progress %+v", len(res.Hosts), last)
	}
	data, _ := os.ReadFile(log)
	seen := map[string]int{}
	for _, f := range strings.Fields(string(data)) {
		seen[f]++
	}
	if len(seen) != 16384 {
		t.Fatalf("nmap saw %d distinct targets", len(seen))
	}
	for a, n := range seen {
		if n != 1 {
			t.Fatalf("%s scanned %d times", a, n)
		}
	}
	if res.Chunks[0].Targets != firstChunk {
		t.Fatalf("first chunk %+v", res.Chunks[0])
	}
	var adapted int
	for _, c := range res.Chunks {
		if c.Reason == "" || c.StartedAt.IsZero() {
			t.Fatalf("chunk without a decision: %+v", c)
		}
		if strings.Contains(c.Reason, "aiming for") && !strings.Contains(c.Reason, "limited") {
			adapted++
			if d := time.Duration(c.Duration); d < 150*time.Millisecond || d > 3*time.Second {
				t.Errorf("chunk of %d took %v", c.Targets, d)
			}
		}
	}
	if adapted == 0 {
		t.Fatalf("no chunk was sized by speed: %+v", res.Chunks)
	}
	var sizes []int
	for _, c := range res.Chunks {
		sizes = append(sizes, c.Targets)
	}
	t.Logf("%d targets in %v, %d chunks: %v", len(res.Targets), time.Duration(res.Duration).Round(time.Millisecond), len(sizes), sizes)
	if set := res.Settings; set.ChunkTarget == 0 || set.ChunkMin != DefaultMinChunk || set.ChunkMax != DefaultMaxChunk {
		t.Fatalf("settings %+v", set)
	}
}

func TestScanStopsAtDeadline(t *testing.T) {
	t.Setenv("FAKE_NMAP_US", "20000")
	var tg Targets
	_ = tg.Add("10.0.0.0/24")
	s := Scanner{Options: Options{Binary: "testdata/fake-nmap.sh"}, ChunkSize: 10, Parallel: 2,
		Deadline: time.Now().Add(300 * time.Millisecond)}
	res, err := s.Scan(context.Background(), &tg)
	if !errors.Is(err, ErrDeadline) {
		t.Fatalf("err %v", err)
	}
	if n := len(res.Hosts); n == 0 || n == 256 || n != 10*len(res.Chunks) {
		t.Fatalf("%d hosts, %d chunks", n, len(res.Chunks))
	}
}

func TestScanCancelDropsUnfinishedChunks(t *testing.T) {
	t.Setenv("FAKE_NMAP_US", "1000000")
	var tg Targets
	_ = tg.Add("10.0.0.0/28")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	s := Scanner{Options: Options{Binary: "testdata/fake-nmap.sh"}, ChunkSize: 8}
	res, err := s.Scan(ctx, &tg)
	if !errors.Is(err, context.DeadlineExceeded) || len(res.Chunks) != 0 || len(res.Hosts) != 0 {
		t.Fatalf("%v: %+v", err, res)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v: nmap was not stopped", d)
	}
}

func TestPostRunsBeforeAChunkCounts(t *testing.T) {
	var tg Targets
	_ = tg.Add("10.0.0.0/29")
	s := Scanner{Options: Options{Binary: "testdata/fake-nmap.sh"}, ChunkSize: 4,
		Post: func(_ context.Context, hosts []result.Host) {
			for i := range hosts {
				hosts[i].Hostnames = []string{"posted"}
			}
		}}
	s.Progress = func(p Progress) {
		if len(p.Targets) != 4 || len(p.Hosts) != 4 || p.Hosts[0].Hostnames == nil {
			t.Errorf("progress %+v", p)
		}
	}
	res, err := s.Scan(context.Background(), &tg)
	if err != nil || len(res.Hosts) != 8 || res.Hosts[7].Hostnames == nil {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestBalancedModeRetriesUnidentifiedServices(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NMAPDIR", dir)
	t.Setenv("FAKE_NMAP_VAGUE", "1")
	db := "Probe TCP NULL q||\ntotalwaitms 6000\n"
	if err := os.WriteFile(filepath.Join(dir, "nmap-service-probes"), []byte(db), 0o600); err != nil {
		t.Fatal(err)
	}
	for mode, product := range map[VersionMode]string{"": "nginx", VersionBalanced: "nginx", VersionFast: "", VersionFull: "nginx"} {
		var tg Targets
		_ = tg.Add("10.0.0.0/30")
		res, err := (&Scanner{Options: Options{Binary: "testdata/fake-nmap.sh", VersionMode: mode}}).Scan(context.Background(), &tg)
		if err != nil {
			t.Fatal(err)
		}
		svc := res.Hosts[0].Services[0]
		if svc.Product != product || svc.Guessed != (product == "") {
			t.Errorf("mode %q: %+v", mode, svc)
		}
		want := 0
		if mode == "" || mode == VersionBalanced {
			want = 4
		}
		if res.Chunks[0].Retried != want {
			t.Errorf("mode %q: retried %d, want %d", mode, res.Chunks[0].Retried, want)
		}
	}
}

func TestTuneProbes(t *testing.T) {
	in := `# comment
Probe TCP NULL q||
totalwaitms 6000
tcpwrappedms 3000
match ssh m|^SSH| p/ssh/
softmatch http m|^HTTP| p/Golang/
Probe TCP SSLSessionReq q|x|
rarity 1
match http m|^HTTP/1.1 400|
softmatch http m|^HTTP|
match ssl m|^\x16|
Probe UDP Help q|help|
totalwaitms 7500
match http m|^HTTP|
`
	want := `# comment
Probe TCP NULL q||
totalwaitms 1500
tcpwrappedms 3000
match ssh m|^SSH| p/ssh/
softmatch http m|^HTTP| p/Golang/
Probe TCP SSLSessionReq q|x|
totalwaitms 1500
rarity 1
match ssl m|^\x16|
Probe UDP Help q|help|
totalwaitms 7500
match http m|^HTTP|
`
	var out bytes.Buffer
	if err := TuneProbes(&out, strings.NewReader(in), 1500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("got:\n%s", out.String())
	}
	if err := TuneProbes(&out, strings.NewReader("nothing here"), time.Second); err == nil {
		t.Fatal("junk accepted")
	}
}
