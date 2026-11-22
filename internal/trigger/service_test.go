package trigger

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/sensor"
)

// fakeScanner answers from a table: target -> open ports.
type fakeScanner struct {
	mu         sync.Mutex
	open       map[string][]int
	jobs       []Job
	closedHost map[string]bool // host answers with RSTs but nothing open
}

func (f *fakeScanner) Scan(_ context.Context, j Job) (*result.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, j)
	ip := j.Target.IP.String()
	h := result.Host{Address: ip, State: "up"}
	for _, p := range f.open[ip] {
		h.Services = append(h.Services, result.Service{Port: p, Proto: "tcp", State: "open", Name: "http",
			Tech: []result.Tech{{Name: "nginx", Version: "1.31.9"}}})
	}
	if len(h.Services) == 0 {
		state := "filtered"
		if f.closedHost[ip] {
			state = "closed"
		}
		h.ExtraPorts = []result.ExtraPorts{{State: state, Count: 100}}
	}
	return &result.Scan{StartedAt: time.Now(), Targets: []string{ip}, Hosts: []result.Host{h}}, nil
}

func newService(t *testing.T, f *fakeScanner) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	p := policy()
	p.Debounce, p.Quiet, p.Cooldown = 10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond
	return &Service{Policy: p, Scanner: f, StateDir: dir, Token: "tok"}, dir
}

func post(t *testing.T, h http.Handler, token string, events ...sensor.Event) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(events)
	req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func readFindings(t *testing.T, dir string, want int) []Finding {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var out []Finding
		if fh, err := os.Open(filepath.Join(dir, "findings.jsonl")); err == nil {
			sc := bufio.NewScanner(fh)
			for sc.Scan() {
				var f Finding
				if json.Unmarshal(sc.Bytes(), &f) == nil {
					out = append(out, f)
				}
			}
			fh.Close()
		}
		if len(out) >= want || time.Now().After(deadline) {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestEventsEndpointAuthAndValidation(t *testing.T) {
	s, _ := newService(t, &fakeScanner{})
	h := s.Handler()
	if rec := post(t, h, "", ev(sensor.HostNew, "172.20.0.8", 0)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := post(t, h, "wrong", ev(sensor.HostNew, "172.20.0.8", 0)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", rec.Code)
	}
	rec = post(t, h, "tok", ev(sensor.HostNew, "172.20.0.8", 0), ev(sensor.HostNew, "10.0.0.1", 0))
	var resp map[string]int
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusAccepted || resp["received"] != 2 || resp["accepted"] != 1 {
		t.Fatalf("accept: %d %v", rec.Code, resp)
	}
	health := httptest.NewRecorder()
	h.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !bytes.Contains(health.Body.Bytes(), []byte(`"pending":1`)) || !bytes.Contains(health.Body.Bytes(), []byte("outside allow list")) {
		t.Fatalf("healthz: %s", health.Body)
	}
}

func TestTriggeredScansProduceFindings(t *testing.T) {
	f := &fakeScanner{open: map[string][]int{"172.20.0.8": {80}, "172.20.0.3": {80}}, closedHost: map[string]bool{"172.20.0.4": true}}
	s, dir := newService(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	h := s.Handler()
	post(t, h, "tok",
		ev(sensor.HostNew, "172.20.0.8", 0),        // new intruder: host scan
		ev(sensor.ServiceSilent, "172.20.0.3", 80), // still there
		ev(sensor.ServiceSilent, "172.20.0.9", 80), // really gone
		ev(sensor.HostSilent, "172.20.0.4", 0),     // up, nothing open
		ev(sensor.HostSilent, "172.20.0.5", 0),     // down
	)
	got := map[string]Finding{}
	for _, fd := range readFindings(t, dir, 5) {
		got[fd.Target.String()] = fd
	}
	want := map[string]string{
		"172.20.0.8": VerdictScanned, "172.20.0.3:80": VerdictStillOpen, "172.20.0.9:80": VerdictGone,
		"172.20.0.4": VerdictStillUp, "172.20.0.5": VerdictDown,
	}
	for target, v := range want {
		if got[target].Verdict != v {
			t.Errorf("%s: verdict %q, want %q", target, got[target].Verdict, v)
		}
	}
	intr := got["172.20.0.8"]
	if len(intr.Services) != 1 || intr.Services[0].Tech[0] != "nginx 1.31.9" || len(intr.Events) != 1 {
		t.Errorf("intruder finding: %+v", intr)
	}
	if _, err := os.Stat(filepath.Join(dir, "targets", "172.20.0.8.json")); err != nil {
		t.Errorf("state file: %v", err)
	}

	// The intruder opens another port: the next scan carries a diff.
	f.mu.Lock()
	f.open["172.20.0.8"] = []int{80, 8080}
	f.mu.Unlock()
	time.Sleep(50 * time.Millisecond) // past quiet and cooldown
	post(t, h, "tok", ev(sensor.HostBack, "172.20.0.8", 0))
	all := readFindings(t, dir, 6)
	last := all[len(all)-1]
	if last.Changes == nil || last.Changes.Summary.NewServices != 1 {
		t.Fatalf("second scan should report +1 service: %+v", last.Changes)
	}
}

type failingScanner struct{}

func (failingScanner) Scan(ctx context.Context, j Job) (*result.Scan, error) {
	// A partial result (no ports answered) plus an error, like a cancelled nmap.
	return &result.Scan{Hosts: []result.Host{{Address: j.Target.IP.String(), State: "up"}}}, context.Canceled
}

func TestInterruptedScanConfirmsNothing(t *testing.T) {
	dir := t.TempDir()
	p := policy()
	p.Debounce = 10 * time.Millisecond
	s := &Service{Policy: p, Scanner: failingScanner{}, StateDir: dir}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	post(t, s.Handler(), "", ev(sensor.HostSilent, "172.20.0.5", 0))
	f := readFindings(t, dir, 1)
	cancel()
	<-done
	if len(f) != 1 || f[0].Verdict != VerdictError || f[0].Error == "" {
		t.Fatalf("interrupted scan: %+v", f)
	}
}
