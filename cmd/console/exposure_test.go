package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/exposure"
)

// fakeProvider serves a canned outside view.
type fakeProvider struct {
	view *exposure.ExternalView
}

func (f *fakeProvider) Name() string { return "shodan" }
func (f *fakeProvider) Host(ctx context.Context, ip string) (*exposure.ExternalView, error) {
	v := *f.view
	v.IP = ip
	return &v, nil
}
func (f *fakeProvider) FaviconSearch(ctx context.Context, hash int32) ([]string, error) {
	return nil, nil
}

func testView(services ...exposure.ExternalService) *exposure.ExternalView {
	return &exposure.ExternalView{IP: "203.0.113.10", Source: "shodan", FetchedAt: time.Now(), Services: services}
}

func TestDiffFirstRunEstablishesBaseline(t *testing.T) {
	seen := map[string]time.Time{}
	hosts := []*HostRecord{{
		IP:       "10.0.0.5",
		Services: map[string]*HostService{"443/tcp": {Port: 443, Proto: "tcp"}},
	}}
	view := testView(
		exposure.ExternalService{Port: 443, Proto: "tcp", Product: "nginx"},
		exposure.ExternalService{Port: 23, Proto: "tcp", Product: "telnet"},
	)
	findings, esc := diffExposure(view, hosts, nil, seen, time.Now())
	if len(esc) != 0 {
		t.Fatalf("first run must not escalate, got %d escalations", len(esc))
	}
	if len(seen) != 2 {
		t.Fatalf("baseline = %v", seen)
	}
	// Telnet has no internal counterpart: flagged, but not escalated yet.
	var unmatched *ExposureFinding
	for i := range findings {
		if findings[i].Kind == findUnmatchedExternal {
			unmatched = &findings[i]
		}
	}
	if unmatched == nil || unmatched.Service.Port != 23 {
		t.Fatalf("unmatched finding = %+v in %v", unmatched, findings)
	}
}

func TestDiffNewUnmatchedEscalates(t *testing.T) {
	seen := map[string]time.Time{"443/tcp": time.Now().Add(-time.Hour)}
	view := testView(
		exposure.ExternalService{Port: 443, Proto: "tcp"},
		exposure.ExternalService{Port: 23, Proto: "tcp", Product: "telnet"},
	)
	_, esc := diffExposure(view, nil, nil, seen, time.Now())
	if len(esc) != 1 || esc[0].Kind != findUnmatchedExternal || esc[0].Service.Port != 23 {
		t.Fatalf("escalations = %+v", esc)
	}
}

func TestDiffRecentInternalExposedEscalates(t *testing.T) {
	seen := map[string]time.Time{"8080/tcp": time.Now().Add(-time.Hour)}
	hosts := []*HostRecord{{
		IP:       "10.0.0.30",
		Services: map[string]*HostService{"8080/tcp": {Port: 8080, Proto: "tcp"}},
	}}
	recent := map[string]string{"8080/tcp": "10.0.0.30"}
	view := testView(exposure.ExternalService{Port: 8080, Proto: "tcp", Product: "nginx"})
	_, esc := diffExposure(view, hosts, recent, seen, time.Now())
	if len(esc) != 1 || esc[0].Kind != findExposedInternal || esc[0].MatchIP != "10.0.0.30" {
		t.Fatalf("escalations = %+v", esc)
	}
}

func TestDiffGoneExternal(t *testing.T) {
	seen := map[string]time.Time{
		"443/tcp": time.Now().Add(-time.Hour),
		"23/tcp":  time.Now().Add(-time.Hour),
	}
	view := testView(exposure.ExternalService{Port: 443, Proto: "tcp"})
	findings, esc := diffExposure(view, nil, nil, seen, time.Now())
	if len(esc) != 0 {
		t.Fatalf("no escalations expected, got %+v", esc)
	}
	var gone *ExposureFinding
	for i := range findings {
		if findings[i].Kind == "gone_external" {
			gone = &findings[i]
		}
	}
	if gone == nil || gone.Service.Port != 23 {
		t.Fatalf("gone finding = %+v in %+v", gone, findings)
	}
	if _, ok := seen["23/tcp"]; ok {
		t.Fatal("gone service must leave the baseline")
	}
}

func TestExposureRunEndToEnd(t *testing.T) {
	gt, store := newTestGroundTruth(t, fakeDial(map[string]string{}))
	cfg := gt.settings
	on := true
	if err := cfg.update(configPatch{ExposureEnabled: &on}); err != nil {
		t.Fatal(err)
	}
	e, err := newExposureCheck(t.TempDir(), store, newLiveFeed(100), cfg, gt)
	if err != nil {
		t.Fatal(err)
	}
	e.provider = &fakeProvider{view: testView(exposure.ExternalService{Port: 443, Proto: "tcp"})}
	e.myIP = func(ctx context.Context) (string, error) { return "203.0.113.10", nil }

	// First run establishes the external baseline — no cases.
	e.run("test")
	if cases := store.ListCases(); len(cases) != 0 {
		t.Fatalf("first run must not escalate, got %d cases", len(cases))
	}
	st := e.status()
	if st["view"] == nil {
		t.Fatal("status should carry the outside view after a run")
	}

	// The outside view gains a service nothing internal reports: the
	// second run escalates it as a shadow-IT candidate.
	e.provider = &fakeProvider{view: testView(
		exposure.ExternalService{Port: 443, Proto: "tcp"},
		exposure.ExternalService{Port: 23, Proto: "tcp", Product: "telnet"},
	)}
	e.run("test")
	cases := store.ListCases()
	if len(cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(cases))
	}
	c := cases[0]
	if c.EventType != "exposure" || c.Source != "203.0.113.10" || c.Score < 0.9 {
		t.Fatalf("case = %+v", c)
	}
	if !strings.Contains(c.Reason, "shadow IT") || !strings.Contains(c.Reason, "23/tcp") {
		t.Fatalf("reason should explain the diff: %s", c.Reason)
	}

	// State persisted: a fresh checker over the same directory sees the
	// same baseline and findings.
	e2, err := newExposureCheck(e.path[:len(e.path)-len("/exposure.json")], store, newLiveFeed(100), cfg, gt)
	if err != nil {
		t.Fatal(err)
	}
	if len(e2.state.Seen) != 2 || len(e2.state.Findings) == 0 {
		t.Fatalf("state not persisted: %+v", e2.state)
	}

	// The exposure events landed on the topology timeline too.
	var timelineHits int
	for _, ev := range gt.registry.timeline(time.Time{}, time.Time{}) {
		if ev.Type == "exposure_new" {
			timelineHits++
		}
	}
	if timelineHits != 1 {
		t.Fatalf("expected 1 exposure_new timeline event, got %d", timelineHits)
	}
}

func TestExposureConfigDefaultsOff(t *testing.T) {
	cfg, err := openSettings(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gt, store := newTestGroundTruth(t, fakeDial(map[string]string{}))
	_ = gt
	e, err := newExposureCheck(t.TempDir(), store, newLiveFeed(100), cfg, gt)
	if err != nil {
		t.Fatal(err)
	}
	enabled, interval, _ := e.exposureConfig()
	if enabled {
		t.Fatal("exposure must be opt-in (default off)")
	}
	if interval != 6*time.Hour {
		t.Fatalf("default interval = %s", interval)
	}
	if !strings.Contains(e.status()["provider"].(string), "shodan") {
		t.Fatalf("status = %+v", e.status())
	}
}
