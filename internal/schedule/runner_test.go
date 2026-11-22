package schedule

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// shifted is the injected clock: the time of the synctest bubble, moved so
// that it starts at base. Sleeping costs no real time.
type shifted struct{ offset time.Duration }

func clockAt(base time.Time) shifted                   { return shifted{base.Sub(time.Now())} }
func (c shifted) Now() time.Time                       { return time.Now().Add(c.offset).UTC() }
func (shifted) After(d time.Duration) <-chan time.Time { return time.After(d) }
func night(clock string) time.Time                     { return at(time.UTC, "2026-11-22 "+clock) }
func targetList(n int) (out []string) {
	for i := range n {
		out = append(out, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	return out
}

// slowEngine takes perChunk for every chunk of size targets.
type slowEngine struct {
	clock    Clock
	size     int
	perChunk time.Duration
	polite   bool // respects the deadline instead of being cut
	fail     map[string]int
	scanned  map[string]int
	calls    [][]string
	started  []time.Time
	jobs     []Job
	err      error
}

func (e *slowEngine) Scan(ctx context.Context, j Job, report func(Update)) error {
	targets, deadline := j.Targets, j.Deadline
	e.jobs = append(e.jobs, j)
	size := max(1, e.size>>j.Fruitless)
	e.calls = append(e.calls, targets)
	e.started = append(e.started, e.clock.Now())
	if e.err != nil {
		return e.err
	}
	if e.scanned == nil {
		e.scanned = map[string]int{}
	}
	for len(targets) > 0 {
		if e.polite && !deadline.IsZero() && e.clock.Now().Add(e.perChunk).After(deadline) {
			return nil
		}
		chunk := targets[:min(size, len(targets))]
		targets = targets[len(chunk):]
		start := e.clock.Now()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.perChunk * time.Duration(size) / time.Duration(e.size)):
		}
		rec := Record{Targets: chunk, Chunk: result.Chunk{Targets: len(chunk), StartedAt: start, Duration: result.Duration(e.perChunk)}}
		for _, t := range chunk {
			if e.fail[t] > 0 {
				e.fail[t]--
				rec.Chunk.Error = "boom"
			}
		}
		if rec.Chunk.Error == "" {
			for _, t := range chunk {
				e.scanned[t]++
				rec.Hosts = append(rec.Hosts, result.Host{Address: t, State: "up"})
			}
		}
		report(Update{Record: rec, ETA: time.Duration(len(targets)/e.size) * e.perChunk})
	}
	return nil
}

type fixture struct {
	*Runner
	engine  *slowEngine
	results []*result.Scan
	runs    []Run
}

func newFixture(t *testing.T, path, start, window, every string, targets int) *fixture {
	t.Helper()
	clock := clockAt(night(start))
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	freq, err := ParseFrequency(every, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{engine: &slowEngine{clock: clock, size: 10, perChunk: 10 * time.Minute}}
	f.Runner = &Runner{Targets: targetList(targets), Windows: windows(t, window, time.UTC), Frequency: freq,
		Engine: f.engine, Store: store, Clock: clock, Logf: t.Logf,
		OnResult: func(r Run, s *result.Scan) error {
			f.runs = append(f.runs, r)
			f.results = append(f.results, s)
			return nil
		}}
	return f
}

func checkpointPath(t *testing.T) string { return filepath.Join(t.TempDir(), "state.jsonl") }

func (f *fixture) onlyOnce(t *testing.T) {
	t.Helper()
	for _, a := range f.Targets {
		if f.engine.scanned[a] != 1 {
			t.Errorf("%s scanned %d times", a, f.engine.scanned[a])
		}
	}
}

func stopped(s *result.Scan) (out []string) {
	for _, x := range s.Sessions {
		out = append(out, x.Stopped)
	}
	return out
}

func TestLongScanResumesInNextWindow(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		// 100 targets = 10 chunks of 10 min; 45 min of window fit 4.
		f := newFixture(t, path, "20:00", "22:00-22:45", "", 100)
		if err := f.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.onlyOnce(t)
		res := f.results[0]
		if got := stopped(res); !reflect.DeepEqual(got, []string{"window closed", "window closed", "completed"}) {
			t.Fatalf("sessions %v", got)
		}
		if len(f.engine.calls) != 3 || len(f.engine.calls[1]) != 60 || len(f.engine.calls[2]) != 20 {
			t.Fatalf("engine calls: %d", len(f.engine.calls))
		}
		for i, want := range []time.Time{night("22:00"), night("22:00").AddDate(0, 0, 1), night("22:00").AddDate(0, 0, 2)} {
			if !f.engine.started[i].Equal(want) {
				t.Errorf("session %d started %v, want %v", i, f.engine.started[i], want)
			}
		}
		if len(res.Hosts) != 100 || len(res.Chunks) != 10 || res.Chunks[9].Index != 9 {
			t.Fatalf("%d hosts, %d chunks", len(res.Hosts), len(res.Chunks))
		}
		if d := time.Duration(res.Duration); d != 45*time.Minute+45*time.Minute+20*time.Minute {
			t.Fatalf("scanning time %v", d)
		}
		if !res.StartedAt.Equal(night("22:00")) || !res.FinishedAt.Equal(night("22:20").AddDate(0, 0, 2)) {
			t.Fatalf("%v - %v", res.StartedAt, res.FinishedAt)
		}
	})
}

func TestEngineThatStopsBeforeTheWindowWaitsForTheNext(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "22:00", "22:00-22:45", "", 50)
		f.engine.polite = true
		if err := f.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.onlyOnce(t)
		if got := stopped(f.results[0]); len(got) != 2 || !strings.HasPrefix(got[0], "window closing") {
			t.Fatalf("sessions %v", got)
		}
		if !f.engine.started[1].Equal(night("22:00").AddDate(0, 0, 1)) {
			t.Fatalf("resumed at %v", f.engine.started[1])
		}
	})
}

func TestNewProcessResumes(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "12:00", "", "", 100)
		ctx, cancel := context.WithTimeout(t.Context(), 35*time.Minute)
		defer cancel()
		if err := f.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err %v", err)
		}
		first := f.engine.scanned
		if len(first) != 30 || len(f.results) != 0 {
			t.Fatalf("%d scanned", len(first))
		}
		f.Store.(*FileStore).Close()

		g := newFixture(t, path, "15:00", "", "", 100)
		if err := g.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		for a := range first {
			if g.engine.scanned[a] != 0 {
				t.Errorf("%s scanned again", a)
			}
		}
		if len(g.engine.scanned) != 70 || len(g.results[0].Hosts) != 100 {
			t.Fatalf("%d scanned, %d hosts", len(g.engine.scanned), len(g.results[0].Hosts))
		}
		if got := stopped(g.results[0]); !reflect.DeepEqual(got, []string{"interrupted", "completed"}) {
			t.Fatalf("sessions %v", got)
		}
		g.Store.(*FileStore).Close()

		// The finished run is not repeated ...
		h := newFixture(t, path, "20:00", "", "", 100)
		if err := h.Run(t.Context()); err != nil || len(h.engine.calls) != 0 {
			t.Fatalf("%v, %d calls", err, len(h.engine.calls))
		}
		// ... unless something else is to be scanned.
		h.Config = "other ports"
		if err := h.Run(t.Context()); err != nil || len(h.engine.calls) != 1 {
			t.Fatalf("%v, %d calls", err, len(h.engine.calls))
		}
	})
}

func TestChangedTargetsDropUnfinishedRun(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "12:00", "", "", 40)
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
		defer cancel()
		f.Run(ctx)
		f.Store.(*FileStore).Close()
		g := newFixture(t, path, "13:00", "", "", 41)
		if err := g.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		g.onlyOnce(t)
	})
	if RunKey([]string{"a", "b"}, "x") != RunKey([]string{"b", "a"}, "x") {
		t.Error("target order must not matter")
	}
	if RunKey([]string{"a"}, "x") == RunKey([]string{"a"}, "y") {
		t.Error("config must matter")
	}
}

func TestFrequencyAndWindowTogether(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "20:00", "22:00-23:00", "24h", 20)
		ctx, cancel := context.WithTimeout(t.Context(), 76*time.Hour)
		defer cancel()
		if err := f.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if len(f.runs) != 4 { // the nights of 22, 23, 24 and 25 November
			t.Fatalf("%d runs", len(f.runs))
		}
		for i, r := range f.runs {
			if want := night("22:00").AddDate(0, 0, i); !r.StartedAt.Equal(want) {
				t.Errorf("run %d at %v, want %v", i, r.StartedAt, want)
			}
		}
		if s := f.Status(); s.State != "waiting" || !s.NextAt.Equal(night("22:00").AddDate(0, 0, 4)) {
			t.Fatalf("status %+v", s)
		}
	})
}

// A window too short for a single chunk must not be repeated forever.
func TestFruitlessWindowsShrinkChunks(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "22:00", "22:00-22:45", "", 40)
		f.engine.size, f.engine.perChunk = 40, 2*time.Hour            // 3 min per target
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Hour) // three windows
		defer cancel()
		f.Run(ctx)
		// 40 and 20 targets do not fit 45 min, 10 (30 min) do.
		var got []int
		for _, j := range f.engine.jobs {
			got = append(got, j.Fruitless)
		}
		if !reflect.DeepEqual(got, []int{0, 1, 2}) || len(f.engine.scanned) != 10 {
			t.Fatalf("%v, %d scanned", got, len(f.engine.scanned))
		}
		cp, err := f.Store.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if j := f.job(cp, nil, time.Time{}); j.Fruitless != 0 || j.Speed == 0 {
			t.Fatalf("next job %+v", j)
		}
	})
}

func TestStatusWhileScanning(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "22:00", "22:00-22:45", "", 100)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { f.Run(ctx); close(done) }()
		time.Sleep(25 * time.Minute)
		s := f.Status()
		// 8 chunks (80 min) left after the 2nd: 25 min tonight, 45 tomorrow, 10 the day after.
		if s.State != "scanning" || s.Done != 20 || s.Total != 100 || !s.Closes.Equal(night("22:45")) ||
			!s.Expects.Equal(night("22:10").AddDate(0, 0, 2)) {
			t.Errorf("status %+v", s)
		}
		cancel()
		<-done
	})
}

func TestFailedChunksAreRetriedOnceThenGivenUp(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "12:00", "", "", 30)
		f.engine.fail = map[string]int{"10.0.0.5": 1, "10.0.0.25": 99}
		if err := f.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		res := f.results[0]
		if got := stopped(res); !reflect.DeepEqual(got, []string{"retrying failed chunks", "completed"}) {
			t.Fatalf("sessions %v", got)
		}
		if len(res.Hosts) != 20 || f.engine.fail["10.0.0.25"] != 97 {
			t.Fatalf("%d hosts", len(res.Hosts))
		}
		var failed int
		for _, c := range res.Chunks {
			if c.Error != "" {
				failed++
			}
		}
		if failed != 3 {
			t.Fatalf("%d failed chunks recorded", failed)
		}
	})
}

func TestEngineErrorStopsTheRunner(t *testing.T) {
	path := checkpointPath(t)
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, path, "12:00", "", "24h", 10)
		f.engine.err = errors.New("no nmap")
		if err := f.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "no nmap") {
			t.Fatal(err)
		}
	})
}

func TestFileStoreSurvivesTornLineAndCrash(t *testing.T) {
	path := checkpointPath(t)
	ctx := context.Background()
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if cp, err := s.Load(ctx); cp != nil || err != nil {
		t.Fatalf("%v %v", cp, err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("second scheduler must be refused")
	}
	start := night("22:00")
	targets := targetList(30)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	rec := func(i int) Record {
		return Record{Targets: targets[i*10 : i*10+10], Chunk: result.Chunk{Index: i, Targets: 10,
			StartedAt: start.Add(time.Duration(i) * time.Minute), Duration: result.Duration(time.Minute)}}
	}
	must(s.Begin(ctx, Run{ID: "x", Key: RunKey(targets, ""), StartedAt: start, Targets: 30}))
	must(s.SaveRecord(ctx, rec(0)))
	must(s.SaveRecord(ctx, rec(1)))
	s.Close() // killed: no session saved, last line half written
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"record":{"chunk":{"index":2,"targ`)
	f.Close()

	synctest.Test(t, func(t *testing.T) {
		g := newFixture(t, path, "23:00", "", "", 30)
		if err := g.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(g.engine.scanned) != 10 || g.engine.scanned["10.0.0.25"] != 1 {
			t.Fatalf("scanned %v", g.engine.scanned)
		}
		res := g.results[0]
		if got := stopped(res); !reflect.DeepEqual(got, []string{"process died", "completed"}) {
			t.Fatalf("sessions %v", got)
		}
		if x := res.Sessions[0]; time.Duration(x.Duration) != 2*time.Minute || x.Targets != 20 {
			t.Fatalf("recovered session %+v", x)
		}
		cp, err := g.Store.Load(ctx)
		if err != nil || len(cp.Records) != 3 || cp.FinishedAt.IsZero() {
			t.Fatalf("%+v %v", cp, err)
		}
	})
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestFileStoreRefusesOtherFiles(t *testing.T) {
	for _, content := range []string{"", "{}", `{"started_at":"x"}`, "{\n  \"hosts\": []\n}\n", `{"finished":"2026-11-22T22:00:00Z"}` + "\n"} {
		path := checkpointPath(t)
		os.WriteFile(path, []byte(content), 0o600)
		s, err := OpenFileStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(context.Background()); err == nil {
			t.Errorf("%q accepted", content)
		}
		if data, _ := os.ReadFile(path); string(data) != content {
			t.Errorf("%q was modified", content)
		}
		s.Close()
	}
}
