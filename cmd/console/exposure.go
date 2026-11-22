package main

// Inside-outside correlation: the passive sensor sees the network from
// within; internet-wide scanners (Shodan, Censys) see what of it faces the
// world. Neither view alone answers "is anything exposed that should not
// be" — the diff does:
//
//   - a service on the public IP that no internal host reports -> shadow
//     IT or an accidental exposure (highest weight);
//   - a service the sensor just discovered internally that is also visible
//     from the internet -> service_new + exposed, the sharpest alert this
//     console raises;
//   - a favicon hash (mmh3, same format the scanner computes) found on
//     other public IPs -> the same app exposed somewhere unexpected.
//
// The first run establishes the external baseline; escalations start with
// the first diff, so turning the feature on does not flood the backlog
// with the whole internet-facing surface at once.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/exposure"
)

// Finding kinds produced by the inside/outside diff.
const (
	findUnmatchedExternal = "unmatched_external" // outside sees it, inside does not
	findExposedInternal   = "exposed_internal"   // new inside service, visible outside
	findNewExternal       = "new_external"       // appeared on the public IP since last check
	findFaviconSpread     = "favicon_spread"     // same favicon on other public IPs
)

// ExposureFinding is one row of the diff report.
type ExposureFinding struct {
	Kind      string                   `json:"kind"`
	Service   exposure.ExternalService `json:"service"`
	MatchIP   string                   `json:"match_ip,omitempty"` // internal host that explains the service
	Detail    string                   `json:"detail,omitempty"`
	FirstSeen time.Time                `json:"first_seen"`
}

// exposureState is the durable snapshot of the outside view.
type exposureState struct {
	View     *exposure.ExternalView `json:"view,omitempty"`
	Findings []ExposureFinding      `json:"findings,omitempty"`
	// seen maps service key -> when the outside view first showed it; the
	// baseline that turns "present" into "new".
	Seen map[string]time.Time `json:"seen,omitempty"`
}

// exposureCheck drives scheduled and on-demand outside-view pulls.
type exposureCheck struct {
	settings *settings
	store    *Store
	feed     *LiveFeed
	gt       *groundTruth
	path     string

	// provider is injectable for tests; nil means "resolve from settings".
	provider exposure.Provider
	// myIP resolves the public egress IP; injectable for tests.
	myIP func(ctx context.Context) (string, error)

	mu      sync.Mutex
	running bool
	lastRun time.Time
	lastSum string
	state   exposureState
}

func newExposureCheck(dir string, st *Store, feed *LiveFeed, cfg *settings, gt *groundTruth) (*exposureCheck, error) {
	e := &exposureCheck{
		settings: cfg, store: st, feed: feed, gt: gt,
		path: filepath.Join(dir, "exposure.json"),
	}
	b, err := rest.ReadFile(e.path)
	if err == nil {
		_ = json.Unmarshal(b, &e.state)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if e.state.Seen == nil {
		e.state.Seen = map[string]time.Time{}
	}
	return e, nil
}

func (e *exposureCheck) saveLocked() error {
	b, err := json.MarshalIndent(e.state, "", "  ")
	if err != nil {
		return err
	}
	return rest.WriteFile(e.path, b, 0o600)
}

// exposureConfig resolves the effective configuration.
func (e *exposureCheck) exposureConfig() (enabled bool, interval time.Duration, publicIP string) {
	snap := e.settings.snapshot()
	enabled = snap.ExposureEnabled != nil && *snap.ExposureEnabled // opt-in
	interval = 6 * time.Hour
	if snap.ExposureIntervalMin > 0 {
		interval = time.Duration(snap.ExposureIntervalMin) * time.Minute
	}
	publicIP = strings.TrimSpace(snap.ExposurePublicIP)
	return
}

// resolveProvider builds the outside-view provider from settings with env
// fallback, or returns the test double when one is installed.
func (e *exposureCheck) resolveProvider() (exposure.Provider, error) {
	if e.provider != nil {
		return e.provider, nil
	}
	snap := e.settings.snapshot()
	provider := snap.ExposureProvider
	key := snap.ExposureAPIKey
	if key == "" {
		switch strings.ToLower(provider) {
		case "censys":
			id, secret := os.Getenv("CENSYS_API_ID"), os.Getenv("CENSYS_API_SECRET")
			if id != "" && secret != "" {
				key = id + ":" + secret
			}
		default:
			key = os.Getenv("SHODAN_API_KEY")
		}
	}
	return exposure.NewProvider(provider, key)
}

// resolveMyIP returns the configured public IP or asks the provider /
// a neutral echo service.
func (e *exposureCheck) resolveMyIP(ctx context.Context, p exposure.Provider) (string, error) {
	if _, _, configured := e.exposureConfig(); configured != "" {
		return configured, nil
	}
	if e.myIP != nil {
		return e.myIP(ctx)
	}
	if sh, ok := p.(*exposure.Shodan); ok {
		return sh.MyIP(ctx)
	}
	// Providers without a my-ip endpoint: neutral fallback.
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// tick runs a scheduled check when due; called every minute.
func (e *exposureCheck) tick() {
	enabled, interval, _ := e.exposureConfig()
	if !enabled {
		return
	}
	e.mu.Lock()
	due := !e.running && (e.lastRun.IsZero() || time.Since(e.lastRun) >= interval)
	e.mu.Unlock()
	if due {
		e.run("harmonogram (co " + interval.String() + ")")
	}
}

// run pulls the outside view and diffs it against the passive registry.
// Fail-soft: a provider or network error is a feed note, never a crash.
func (e *exposureCheck) run(trigger string) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.lastRun = time.Now()
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	p, err := e.resolveProvider()
	if err != nil {
		e.setSummary("pominięto: " + err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ip, err := e.resolveMyIP(ctx, p)
	if err != nil {
		e.setSummary("nie udało się ustalić publicznego IP: " + err.Error())
		return
	}
	if net.ParseIP(ip) == nil {
		e.setSummary("nieprawidłowe publiczne IP: " + ip)
		return
	}
	view, err := p.Host(ctx, ip)
	if err != nil {
		e.setSummary(fmt.Sprintf("%s: %v", p.Name(), err))
		return
	}

	hosts := e.gt.registry.hostsSnapshot()
	recentServices := e.recentInternalServices(24 * time.Hour)

	e.mu.Lock()
	findings, escalations := diffExposure(view, hosts, recentServices, e.state.Seen, time.Now())
	// Favicon cross-match: where else is the same app visible? Only for
	// providers with favicon search; unsupported degrades to a skip.
	var favNotes []string
	for i := range findings {
		svc := &findings[i].Service
		if svc.FaviconMMH3 == nil {
			continue
		}
		addrs, err := p.FaviconSearch(ctx, *svc.FaviconMMH3)
		if err != nil || len(addrs) == 0 {
			continue
		}
		var others []string
		for _, a := range addrs {
			if !strings.HasPrefix(a, ip+":") {
				others = append(others, a)
			}
		}
		if len(others) > 0 {
			findings = append(findings, ExposureFinding{
				Kind: findFaviconSpread, Service: *svc, FirstSeen: time.Now(),
				Detail: fmt.Sprintf("ten sam favicon (mmh3 %d) widać na %d innych publicznych adresach: %s",
					*svc.FaviconMMH3, len(others), strings.Join(others[:min(5, len(others))], ", ")),
			})
			favNotes = append(favNotes, svc.Key())
		}
	}
	e.state.View = view
	e.state.Findings = findings
	if err := e.saveLocked(); err != nil {
		e.feed.Append("alert", "", "Ekspozycja: nie udało się zapisać stanu: "+err.Error(), nil)
	}
	e.mu.Unlock()

	for _, f := range escalations {
		e.escalate(view, f)
	}
	// New external exposures are topology events too: the map shows the
	// public surface drifting next to the internal one.
	e.gt.registry.mu.Lock()
	for _, f := range escalations {
		if f.Kind == findNewExternal || f.Kind == findUnmatchedExternal {
			e.gt.registry.addEvent(topologyEvent{
				Time: time.Now(), Type: "exposure_new", IP: view.IP,
				Port: f.Service.Port, Proto: f.Service.Proto, Detail: f.Detail,
			})
		}
	}
	e.gt.registry.dirty = true
	e.gt.registry.mu.Unlock()

	sum := fmt.Sprintf("kontrola ekspozycji (%s, %s, publiczne IP %s): %d usług widocznych z internetu — %d nowych, %d bez odpowiednika wewnątrz, %d wewnętrznych wystawionych, %d dopasowań favicon",
		trigger, p.Name(), ip, len(view.Services),
		countKind(findings, findNewExternal), countKind(findings, findUnmatchedExternal),
		countKind(findings, findExposedInternal), len(favNotes))
	e.setSummary(sum)
	kind := "status"
	if len(escalations) > 0 {
		kind = "alert"
	}
	e.feed.Append(kind, "", "Ekspozycja: "+sum, nil)
}

func (e *exposureCheck) setSummary(s string) {
	e.mu.Lock()
	e.lastSum = s
	e.mu.Unlock()
}

// recentInternalServices collects service keys that appeared inside during
// the last window, from the topology journal.
func (e *exposureCheck) recentInternalServices(window time.Duration) map[string]string {
	out := map[string]string{}
	from := time.Now().Add(-window)
	for _, ev := range e.gt.registry.timeline(from, time.Time{}) {
		if ev.Type == "service_new" && ev.Port > 0 {
			proto := ev.Proto
			if proto == "" {
				proto = "tcp"
			}
			out[strconv.Itoa(ev.Port)+"/"+proto] = ev.IP
		}
	}
	return out
}

// diffExposure is the pure heart of the feature: outside view vs inside
// record. seen is the external baseline, updated in place; escalations are
// returned only when a baseline existed (first run establishes it).
func diffExposure(view *exposure.ExternalView, hosts []*HostRecord, recentServices map[string]string, seen map[string]time.Time, now time.Time) (findings, escalations []ExposureFinding) {
	hadBaseline := len(seen) > 0
	// Index internal services: port/proto -> host ip, plus product names
	// for a stronger match when both sides name the product.
	type internalSvc struct {
		ip string
	}
	internal := map[string][]internalSvc{}
	for _, h := range hosts {
		for key := range h.Services {
			internal[key] = append(internal[key], internalSvc{ip: h.IP})
		}
	}

	current := map[string]bool{}
	for _, svc := range view.Services {
		key := svc.Key()
		current[key] = true
		firstSeen, known := seen[key]
		if !known {
			firstSeen = now
			seen[key] = now
		}

		matchIP := ""
		if matches, ok := internal[key]; ok && len(matches) > 0 {
			matchIP = matches[0].ip
		}
		recentIP, isRecent := recentServices[key]

		switch {
		case matchIP == "":
			// The internet sees a service no internal host reports: shadow
			// IT or an accidental exposure. Highest-weight finding.
			f := ExposureFinding{
				Kind: findUnmatchedExternal, Service: svc, FirstSeen: firstSeen,
				Detail: "usługa widoczna z internetu nie ma odpowiednika w pasywnym rejestrze wewnętrznym — podejrzenie shadow IT lub przypadkowej ekspozycji",
			}
			findings = append(findings, f)
			if hadBaseline && !known {
				escalations = append(escalations, f)
			}
		case isRecent:
			// The sensor just discovered this service inside AND it is
			// reachable from the world: service_new + exposed.
			f := ExposureFinding{
				Kind: findExposedInternal, Service: svc, MatchIP: matchIP, FirstSeen: firstSeen,
				Detail: fmt.Sprintf("usługa wykryta wewnątrz w ciągu ostatnich 24 h (host %s) jest jednocześnie widoczna z internetu", recentIP),
			}
			findings = append(findings, f)
			escalations = append(escalations, f)
		default:
			if hadBaseline && !known {
				f := ExposureFinding{
					Kind: findNewExternal, Service: svc, MatchIP: matchIP, FirstSeen: firstSeen,
					Detail: "nowa usługa na publicznym IP od ostatniej kontroli (ma odpowiednik wewnętrzny na " + matchIP + ")",
				}
				findings = append(findings, f)
				escalations = append(escalations, f)
			}
		}
	}
	// Services that vanished from the outside view are drift too — good
	// news, so a finding row, not an escalation.
	for key, firstSeen := range seen {
		if current[key] {
			continue
		}
		port, proto, _ := strings.Cut(key, "/")
		p, _ := strconv.Atoi(port)
		findings = append(findings, ExposureFinding{
			Kind: "gone_external", Service: exposure.ExternalService{Port: p, Proto: proto}, FirstSeen: firstSeen,
			Detail: "usługa zniknęła z widoku zewnętrznego od ostatniej kontroli",
		})
		delete(seen, key)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Service.Port < findings[j].Service.Port })
	return findings, escalations
}

func countKind(findings []ExposureFinding, kind string) int {
	n := 0
	for _, f := range findings {
		if f.Kind == kind {
			n++
		}
	}
	return n
}

// escalate opens a case for an exposure finding.
func (e *exposureCheck) escalate(view *exposure.ExternalView, f ExposureFinding) {
	score := 0.9
	kindLabel := "Ekspozycja bez odpowiednika wewnętrznego"
	if f.Kind == findExposedInternal {
		score = 0.95
		kindLabel = "Nowa usługa wewnętrzna widoczna z internetu"
	} else if f.Kind == findNewExternal {
		score = 0.85
		kindLabel = "Nowa usługa na publicznym IP"
	}
	reason := fmt.Sprintf("%s: %s:%d/%s (%s) na publicznym IP %s. %s. "+
		"Sensor widzi sieć od środka, %s od zewnątrz — rozjazd tych widoków to najsilniejszy sygnał shadow IT / przypadkowej ekspozycji.",
		kindLabel, view.IP, f.Service.Port, f.Service.Proto,
		strings.TrimSpace(f.Service.Product+" "+f.Service.Version), view.IP, f.Detail, view.Source)
	eventID := "exposure-" + strings.ReplaceAll(view.IP, ".", "-") + "-" + strings.ReplaceAll(f.Service.Key(), "/", "-")
	envelope, _ := json.Marshal(map[string]interface{}{
		"event": map[string]interface{}{
			"time": time.Now().UTC().Format(time.RFC3339), "type": "exposure",
			"ip": view.IP, "kind": f.Kind, "service": f.Service, "match_ip": f.MatchIP,
		},
		"event_id":  eventID,
		"sensor_id": view.Source, "forward": true, "reason": reason,
	})
	c := &Case{
		EventID:  eventID,
		Received: time.Now(), Envelope: envelope,
		SensorID: view.Source, EventType: "exposure",
		EventTime: time.Now().UTC().Format(time.RFC3339),
		Source:    view.IP, Target: "—", Score: score,
		Reason: reason, Status: StatusNew,
	}
	if _, err := e.store.AddEscalation(c); err != nil {
		e.feed.Append("alert", "", "Ekspozycja: nie udało się zapisać sprawy: "+err.Error(), nil)
	}
}

// status is the operator-facing snapshot for the API.
func (e *exposureCheck) status() map[string]interface{} {
	enabled, interval, publicIP := e.exposureConfig()
	snap := e.settings.snapshot()
	_, keyErr := e.resolveProvider()
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]interface{}{
		"enabled": enabled, "interval": interval.String(), "running": e.running,
		"provider":   firstNonEmpty(snap.ExposureProvider, "shodan"),
		"configured": keyErr == nil,
		"public_ip":  publicIP,
		"exposure_key_set": snap.ExposureAPIKey != "" ||
			os.Getenv("SHODAN_API_KEY") != "" ||
			(os.Getenv("CENSYS_API_ID") != "" && os.Getenv("CENSYS_API_SECRET") != ""),
		"view":     e.state.View,
		"findings": e.state.Findings,
	}
	if !e.lastRun.IsZero() {
		out["last_run"] = e.lastRun
		out["last_summary"] = e.lastSum
	}
	return out
}
