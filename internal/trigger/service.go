package trigger

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/diff"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/sensor"
)

// Scanner runs the scan a job asks for.
type Scanner interface {
	Scan(ctx context.Context, job Job) (*result.Scan, error)
}

// Finding is what a triggered scan concluded, written as one JSON line.
type Finding struct {
	Time     time.Time        `json:"time"`
	Target   Target           `json:"target"`
	Kind     Kind             `json:"kind"`
	Verdict  string           `json:"verdict"`
	Events   []sensor.Event   `json:"events"`
	Duration result.Duration  `json:"duration"`
	Services []ServiceSummary `json:"services,omitempty"`
	Changes  *diff.Diff       `json:"changes,omitempty"` // against the previous scan of this target
	Error    string           `json:"error,omitempty"`
}

// ServiceSummary is a compact view of an open service in a finding.
type ServiceSummary struct {
	Port    int      `json:"port"`
	Name    string   `json:"name,omitempty"`
	Product string   `json:"product,omitempty"`
	Version string   `json:"version,omitempty"`
	Title   string   `json:"title,omitempty"`
	Tech    []string `json:"tech,omitempty"`
}

// Verdicts.
const (
	VerdictScanned   = "scanned"        // scan-service/scan-host done
	VerdictStillOpen = "still-open"     // verify-service: the port answers
	VerdictGone      = "gone-confirmed" // verify-service: the port does not answer
	VerdictStillUp   = "still-up"       // verify-host: the host answers on some port
	VerdictDown      = "down-confirmed" // verify-host: every probe timed out
	VerdictError     = "error"
)

// Service accepts sensor events over HTTP and runs triggered scans.
type Service struct {
	Policy    *Policy
	Scanner   Scanner
	StateDir  string        // last result per target and findings.jsonl
	Parallel  int           // concurrent scans; default 2
	Timeout   time.Duration // per scan; default 5m
	Token     string        // required bearer token when set
	Logf      func(format string, args ...any)
	OnFinding func(Finding) // optional, e.g. print to stdout

	mu    sync.Mutex
	wg    sync.WaitGroup
	scans int
}

func (s *Service) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Handler serves POST /events and GET /healthz.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", s.handleEvents)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

func (s *Service) authorized(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) == 1
}

func (s *Service) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var events []sensor.Event
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&events); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	accepted := 0
	now := time.Now()
	s.mu.Lock()
	for _, e := range events {
		if ok, _ := s.Policy.Offer(e, now); ok {
			accepted++
		}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]int{"received": len(events), "accepted": accepted})
}

func (s *Service) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	counters := make(map[string]int, len(s.Policy.Counters))
	for k, v := range s.Policy.Counters {
		counters[k] = v
	}
	body := map[string]any{"pending": s.Policy.Pending(), "running": s.Policy.Running(), "scans": s.scans, "events": counters}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// Run starts due jobs until ctx ends, then waits for running scans.
func (s *Service) Run(ctx context.Context) {
	par := s.Parallel
	if par <= 0 {
		par = 2
	}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return
		case <-tick.C:
		}
		s.mu.Lock()
		jobs := s.Policy.Take(time.Now(), par-s.Policy.Running())
		s.mu.Unlock()
		for _, j := range jobs {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.run(ctx, j)
			}()
		}
	}
}

func (s *Service) run(ctx context.Context, j Job) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	s.logf("scan %s (%s, %d events)", j.Target, j.Kind, len(j.Events))
	start := time.Now()
	res, err := s.Scanner.Scan(sctx, j)
	f := Finding{Time: time.Now(), Target: j.Target, Kind: j.Kind, Events: j.Events, Duration: result.Duration(time.Since(start))}
	switch {
	case err != nil:
		// An interrupted or failed scan must not confirm anything: a
		// cancelled host scan looks exactly like a host that is down.
		f.Verdict, f.Error = VerdictError, err.Error()
	default:
		f.Verdict = verdict(j, res)
		f.Services = compact(res)
		if prev := s.loadPrevious(j.Target); prev != nil {
			if d := diff.Compare(prev, res); !d.Summary.Empty() {
				f.Changes = d
			}
		}
		s.saveResult(j.Target, res)
	}
	s.record(f)

	s.mu.Lock()
	s.Policy.Done(j.Target, time.Now(), f.Verdict == VerdictStillUp || f.Verdict == VerdictStillOpen)
	s.scans++
	s.mu.Unlock()
}

// verdict interprets a scan in the light of why it was run.
func verdict(j Job, res *result.Scan) string {
	var host *result.Host
	for i := range res.Hosts {
		if res.Hosts[i].Address == j.Target.IP.String() {
			host = &res.Hosts[i]
		}
	}
	switch j.Kind {
	case VerifyService:
		if host != nil {
			for _, svc := range host.Services {
				if svc.Port == int(j.Target.Port) && svc.State == "open" {
					return VerdictStillOpen
				}
			}
		}
		return VerdictGone
	case VerifyHost:
		if host != nil && host.Responded() {
			return VerdictStillUp
		}
		return VerdictDown
	}
	return VerdictScanned
}

func compact(res *result.Scan) []ServiceSummary {
	var out []ServiceSummary
	for _, h := range res.Hosts {
		for _, svc := range h.Services {
			if svc.State != "open" {
				continue
			}
			c := ServiceSummary{Port: svc.Port, Name: svc.Name, Product: svc.Product, Version: svc.Version}
			if svc.HTTP != nil {
				c.Title = svc.HTTP.Title
			}
			for _, t := range svc.Tech {
				name := t.Name
				if t.Version != "" {
					name += " " + t.Version
				}
				c.Tech = append(c.Tech, name)
			}
			out = append(out, c)
		}
	}
	return out
}

func (s *Service) path(t Target) string {
	name := strings.NewReplacer(":", "_", "/", "_").Replace(t.String())
	return filepath.Join(s.StateDir, "targets", name+".json")
}

func (s *Service) loadPrevious(t Target) *result.Scan {
	data, err := os.ReadFile(s.path(t))
	if err != nil {
		return nil
	}
	var prev result.Scan
	if json.Unmarshal(data, &prev) != nil {
		return nil
	}
	return &prev
}

func (s *Service) saveResult(t Target, res *result.Scan) {
	p := s.path(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		s.logf("state: %v", err)
		return
	}
	data, _ := json.MarshalIndent(res, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		err = os.Rename(tmp, p)
		if err != nil {
			s.logf("state: %v", err)
		}
	}
}

func (s *Service) record(f Finding) {
	line, _ := json.Marshal(f)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.StateDir != "" {
		if err := os.MkdirAll(s.StateDir, 0o700); err == nil {
			fh, err := os.OpenFile(filepath.Join(s.StateDir, "findings.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err == nil {
				_, _ = fh.Write(append(line, '\n'))
				fh.Close()
			}
		}
	}
	if s.OnFinding != nil {
		s.OnFinding(f)
	}
	s.logf("finding %s %s: %s%s", f.Target, f.Kind, f.Verdict, summary(f))
}

func summary(f Finding) string {
	var parts []string
	for _, svc := range f.Services {
		label := fmt.Sprintf("%d/%s", svc.Port, svc.Name)
		if len(svc.Tech) > 0 {
			label += " [" + strings.Join(svc.Tech, ", ") + "]"
		}
		parts = append(parts, label)
	}
	out := ""
	if len(parts) > 0 {
		out = " " + strings.Join(parts, "; ")
	}
	if f.Changes != nil {
		c := f.Changes.Summary
		out += fmt.Sprintf(" (changes: +%d -%d ~%d services)", c.NewServices, c.GoneServices, c.ChangedServices)
	}
	if f.Error != "" {
		out += " error: " + f.Error
	}
	return out
}

// ErrNoAllowList is returned when the policy would scan nothing.
var ErrNoAllowList = errors.New("an allow list is required")
