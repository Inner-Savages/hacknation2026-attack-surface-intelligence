package main

// Ground truth: periodic active control scans of hosts that went silent in
// the passive feed. A host that stops speaking is indistinguishable from a
// host that is off — that is exactly the silent_stealth scenario the
// passive sensor cannot resolve on its own. The console therefore keeps a
// registry of everything the sensor reported per host and, on a schedule
// (plus on demand), probes a policy-sized sample of the longest-silent
// hosts with gentle TCP connects. Comparing the answers with the passive
// record turns the observability gap into evidence:
//
//   - services alive and unchanged -> the silence is verified as quiet;
//   - a new service or a changed banner under silence -> escalation,
//     because someone is running things the passive view cannot see;
//   - nothing answers -> the host is gone, which is also ground truth.
//
// Every run and every verdict is mirrored to the live feed; escalations are
// ordinary cases, so the rule engine and the AI operator triage them like
// any other alert.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/vuln"
)

// defaultProbePorts are checked on every control scan in addition to the
// ports the passive sensor reported for the host: a quiet host may be
// serving something it never advertised on the wire.
var defaultProbePorts = []int{22, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200}

// HostService is one service the passive sensor told us about.
type HostService struct {
	Port     int       `json:"port"`
	Proto    string    `json:"proto"`
	LastSeen time.Time `json:"last_seen"`
	Banner   string    `json:"banner,omitempty"` // captured by the control scan, not the sensor
}

// HostRecord is the passive history of one host plus the latest
// ground-truth verdict.
type HostRecord struct {
	IP          string                  `json:"ip"`
	SensorID    string                  `json:"sensor_id"`
	FirstSeen   time.Time               `json:"first_seen"`
	LastSeen    time.Time               `json:"last_seen"`
	LastType    string                  `json:"last_type"`
	SilentSince *time.Time              `json:"silent_since,omitempty"`
	Services    map[string]*HostService `json:"services,omitempty"`

	// Baseline is the ground truth established by the first control scan:
	// port key -> banner. Later scans diff against it; a scan's findings
	// become the new baseline, so every drift escalates exactly once.
	Baseline map[string]string `json:"baseline,omitempty"`

	LastCheck    *time.Time `json:"last_check,omitempty"`
	CheckVerdict string     `json:"check_verdict,omitempty"`
}

func (h *HostRecord) serviceKey(port int, proto string) string {
	if proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(port) + "/" + proto
}

// topologyEvent is one entry of the attack-surface timeline: a host
// appearing, going silent, coming back, a service showing up or a control
// scan verdict. The map view replays these to answer "how does my network
// drift over time".
type topologyEvent struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type"` // host_new, host_silent, host_active, service_new, service_silent, gt_quiet, gt_changed, gt_unreachable
	IP       string    `json:"ip"`
	Port     int       `json:"port,omitempty"`
	Proto    string    `json:"proto,omitempty"`
	SensorID string    `json:"sensor_id,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// Bounds of the persisted timeline: long enough to see drift, small enough
// for hosts.json to stay a file, not a database.
const (
	topologyMaxEvents = 5000
	topologyMaxAge    = 30 * 24 * time.Hour
)

// hostRegistry is the durable, JSON-file backed record of passive
// observations per host plus the topology timeline.
type hostRegistry struct {
	mu     sync.Mutex
	path   string
	hosts  map[string]*HostRecord
	events []topologyEvent
	dirty  bool
}

// registryFile is the on-disk shape of hosts.json. The previous format was
// a bare host map; openHostRegistry accepts both.
type registryFile struct {
	Hosts  map[string]*HostRecord `json:"hosts"`
	Events []topologyEvent        `json:"events,omitempty"`
}

func openHostRegistry(dir string) (*hostRegistry, error) {
	r := &hostRegistry{path: filepath.Join(dir, "hosts.json"), hosts: map[string]*HostRecord{}}
	b, err := rest.ReadFile(r.path)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var wrapped registryFile
	if json.Unmarshal(b, &wrapped) == nil && wrapped.Hosts != nil {
		r.hosts = wrapped.Hosts
		r.events = wrapped.Events
		return r, nil
	}
	var hosts map[string]*HostRecord
	if json.Unmarshal(b, &hosts) == nil {
		r.hosts = hosts
	}
	return r, nil
}

// addEvent appends one timeline entry and enforces the retention bounds
// (oldest first out). Caller must hold r.mu.
func (r *hostRegistry) addEvent(ev topologyEvent) {
	r.events = append(r.events, ev)
	cutoff := time.Now().Add(-topologyMaxAge)
	keep := 0
	for keep < len(r.events) && r.events[keep].Time.Before(cutoff) {
		keep++
	}
	if overflow := len(r.events) - keep - topologyMaxEvents; overflow > 0 {
		keep += overflow
	}
	if keep > 0 {
		r.events = append([]topologyEvent(nil), r.events[keep:]...)
	}
}

// timeline returns the journal, newest last, optionally filtered to
// [from, to].
func (r *hostRegistry) timeline(from, to time.Time) []topologyEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]topologyEvent, 0, len(r.events))
	for _, ev := range r.events {
		if !from.IsZero() && ev.Time.Before(from) {
			continue
		}
		if !to.IsZero() && ev.Time.After(to) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// hostsSnapshot returns a copy of the current per-host records for the API.
func (r *hostRegistry) hostsSnapshot() []*HostRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*HostRecord, 0, len(r.hosts))
	for _, h := range r.hosts {
		cp := *h
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Observe folds one passive sensor log line into the registry. Silent
// events start the silent clock; any sign of life resets it. Every state
// transition is mirrored to the topology timeline, so the map view can
// replay how the network drifted.
func (r *hostRegistry) Observe(l sensorLog, sensorID string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hosts[l.IP]
	if !ok {
		h = &HostRecord{IP: l.IP, SensorID: sensorID, FirstSeen: now}
		r.hosts[l.IP] = h
		r.addEvent(topologyEvent{Time: now, Type: "host_new", IP: l.IP, SensorID: sensorID})
	}
	if sensorID != "" {
		h.SensorID = sensorID
	}
	h.LastSeen = now
	h.LastType = l.Type
	switch l.Type {
	case "host_silent":
		if h.SilentSince == nil {
			h.SilentSince = &now
			r.addEvent(topologyEvent{Time: now, Type: "host_silent", IP: l.IP, SensorID: sensorID})
		}
	case "service_silent", "service_quiet":
		if l.Port > 0 {
			if svc := h.Services[h.serviceKey(l.Port, l.Proto)]; svc != nil {
				svc.LastSeen = now
			}
			r.addEvent(topologyEvent{Time: now, Type: "service_silent", IP: l.IP, Port: l.Port, Proto: l.Proto, SensorID: sensorID})
		}
	default:
		// Any non-silent event is proof the host speaks.
		if h.SilentSince != nil {
			r.addEvent(topologyEvent{Time: now, Type: "host_active", IP: l.IP, SensorID: sensorID})
		}
		h.SilentSince = nil
		if l.Port > 0 && (l.Type == "service_new" || l.Type == "service_up" || strings.HasPrefix(l.Type, "service")) {
			key := h.serviceKey(l.Port, l.Proto)
			if h.Services == nil {
				h.Services = map[string]*HostService{}
			}
			if _, ok := h.Services[key]; !ok {
				h.Services[key] = &HostService{Port: l.Port, Proto: l.Proto, LastSeen: now}
				r.addEvent(topologyEvent{Time: now, Type: "service_new", IP: l.IP, Port: l.Port, Proto: l.Proto, SensorID: sensorID})
			} else {
				h.Services[key].LastSeen = now
			}
		}
	}
	r.dirty = true
}

// silentHosts returns hosts silent for at least minDur, longest silence
// first — the policy sample for the next control scan.
func (r *hostRegistry) silentHosts(minDur time.Duration, now time.Time) []*HostRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*HostRecord
	for _, h := range r.hosts {
		if h.SilentSince != nil && now.Sub(*h.SilentSince) >= minDur {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SilentSince.Before(*out[j].SilentSince) })
	return out
}

func (r *hostRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.hosts)
}

// save persists the registry if anything changed since the last save.
func (r *hostRegistry) save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirty {
		return nil
	}
	b, err := json.MarshalIndent(registryFile{Hosts: r.hosts, Events: r.events}, "", "  ")
	if err != nil {
		return err
	}
	if err := rest.WriteFile(r.path, b, 0o600); err != nil {
		return err
	}
	r.dirty = false
	return nil
}

// Verdicts of a control scan for one host.
const (
	verdictQuiet       = "zweryfikowany_cichy" // passive silence confirmed
	verdictChanged     = "zmieniony"           // something moved under silence
	verdictUnreachable = "nieosiągalny"        // host does not answer at all
)

// hostProbe is the active result for one host.
type hostProbe struct {
	Open    map[string]string // port key "port/proto" -> banner ("" when none read)
	Changes []string          // human-readable differences vs the baseline
	First   bool              // no baseline yet: this scan establishes ground truth
}

// dialFunc opens one TCP connection; injectable for tests.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// probeHost connects to the union of the host's known service ports and the
// default set, reads a short banner where the peer volunteers one, and
// diffs the result against the ground-truth baseline of previous scans.
func probeHost(ctx context.Context, h *HostRecord, dial dialFunc, timeout time.Duration) hostProbe {
	ports := map[int]bool{}
	for _, svc := range h.Services {
		ports[svc.Port] = true
	}
	for key := range h.Baseline {
		if p, _, ok := strings.Cut(key, "/"); ok {
			if n, err := strconv.Atoi(p); err == nil {
				ports[n] = true
			}
		}
	}
	for _, p := range defaultProbePorts {
		ports[p] = true
	}
	list := make([]int, 0, len(ports))
	for p := range ports {
		list = append(list, p)
	}
	sort.Ints(list)

	out := hostProbe{Open: map[string]string{}, First: h.Baseline == nil}
	for _, port := range list {
		if ctx.Err() != nil {
			break
		}
		banner, ok := probePort(ctx, h.IP, port, dial, timeout)
		if !ok {
			continue
		}
		key := h.serviceKey(port, "tcp")
		out.Open[key] = banner
		if h.Baseline == nil {
			continue
		}
		old, known := h.Baseline[key]
		switch {
		case !known:
			out.Changes = append(out.Changes, fmt.Sprintf("nowa usługa na porcie %d (nie było jej w bazie ground truth)", port))
		case old != "" && banner != "" && old != banner:
			out.Changes = append(out.Changes, fmt.Sprintf("zmieniony banner na porcie %d: %q → %q", port, old, banner))
		}
	}
	// A service that answered at the last scan and is gone now is drift too —
	// but only when the host answers at all; a host that is fully silent is
	// unreachable, not "changed on every port".
	if len(out.Open) > 0 {
		for key, old := range h.Baseline {
			if _, open := out.Open[key]; !open {
				port, _, _ := strings.Cut(key, "/")
				out.Changes = append(out.Changes, fmt.Sprintf("usługa na porcie %s nie odpowiada (banner był: %q)", port, old))
			}
		}
	}
	return out
}

// probePort dials one port and tries to read a banner without sending
// anything (a control scan stays as gentle as the passive sensor is quiet).
func probePort(ctx context.Context, ip string, port int, dial dialFunc, timeout time.Duration) (string, bool) {
	conn, err := dial(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf) // a timeout here just means "no banner volunteered"
	return strings.TrimSpace(string(buf[:n])), true
}

// classify turns a probe result into a verdict.
func classify(p hostProbe) string {
	switch {
	case len(p.Changes) > 0:
		return verdictChanged
	case len(p.Open) > 0:
		return verdictQuiet
	default:
		return verdictUnreachable
	}
}

// groundTruth drives scheduled and on-demand control scans.
type groundTruth struct {
	registry *hostRegistry
	store    *Store
	feed     *LiveFeed
	settings *settings
	operator string
	dial     dialFunc
	cveDir   string

	mu      sync.Mutex
	running bool
	lastRun time.Time
	lastSum string

	cveOnce sync.Once
	cve     *vuln.Client
}

func newGroundTruth(dir string, st *Store, feed *LiveFeed, cfg *settings, operator string) (*groundTruth, error) {
	reg, err := openHostRegistry(dir)
	if err != nil {
		return nil, err
	}
	d := (&net.Dialer{Timeout: 2 * time.Second}).DialContext
	return &groundTruth{registry: reg, store: st, feed: feed, settings: cfg, operator: operator, dial: d, cveDir: dir}, nil
}

// cveClient lazily builds the CVE enrichment client. A construction error
// (e.g. an uncreatable cache dir) degrades to no enrichment, never to a
// failed scan.
func (g *groundTruth) cveClient() *vuln.Client {
	g.cveOnce.Do(func() {
		c, err := vuln.NewClient(filepath.Join(g.cveDir, "cve-cache"),
			firstNonEmpty(os.Getenv("NVD_API_KEY"), os.Getenv("ASI_NVD_API_KEY")))
		if err == nil {
			g.cve = c
		}
	})
	return g.cve
}

// gtConfig resolves the effective scan policy.
func (g *groundTruth) gtConfig() (enabled bool, interval, silent time.Duration, sample int) {
	snap := g.settings.snapshot()
	enabled = snap.GTEnabled == nil || *snap.GTEnabled // on unless disabled
	interval = 6 * time.Hour
	if snap.GTIntervalMin > 0 {
		interval = time.Duration(snap.GTIntervalMin) * time.Minute
	}
	silent = time.Hour
	if snap.GTSilentMin > 0 {
		silent = time.Duration(snap.GTSilentMin) * time.Minute
	}
	sample = 50
	if snap.GTSampleSize > 0 {
		sample = snap.GTSampleSize
	}
	return
}

// tick runs a scheduled scan when the interval elapsed; called every minute.
func (g *groundTruth) tick() {
	enabled, interval, _, _ := g.gtConfig()
	if !enabled {
		return
	}
	g.mu.Lock()
	due := g.lastRun.IsZero() || time.Since(g.lastRun) >= interval
	g.mu.Unlock()
	if due {
		g.run("harmonogram (co " + interval.String() + ")")
	}
}

// run executes one control scan; manual runs name their operator.
func (g *groundTruth) run(trigger string) {
	g.mu.Lock()
	if g.running {
		g.mu.Unlock()
		return
	}
	g.running = true
	g.lastRun = time.Now()
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.running = false
		g.mu.Unlock()
	}()

	_, _, silent, sample := g.gtConfig()
	now := time.Now()
	hosts := g.registry.silentHosts(silent, now)
	if len(hosts) > sample {
		hosts = hosts[:sample] // policy: longest-silent first, bounded sample
	}
	if len(hosts) == 0 {
		g.mu.Lock()
		g.lastSum = "brak hostów cichych dłużej niż " + silent.String()
		g.mu.Unlock()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	quiet, changed, unreachable, baselined := 0, 0, 0, 0
	for _, h := range hosts {
		probe := probeHost(ctx, h, g.dial, 2*time.Second)
		verdict := classify(probe)
		checked := time.Now()

		g.registry.mu.Lock()
		h.LastCheck = &checked
		h.CheckVerdict = verdict
		if verdict != verdictUnreachable {
			if probe.First {
				baselined++
			}
			// The current truth becomes the baseline for the next diff:
			// every drift escalates once and is then the new normal.
			h.Baseline = probe.Open
		}
		// Control scan verdicts are topology events too: on the timeline
		// they are the ground-truth anchors between passive observations.
		gtType := map[string]string{
			verdictQuiet: "gt_quiet", verdictChanged: "gt_changed", verdictUnreachable: "gt_unreachable",
		}[verdict]
		detail := verdict
		if verdict == verdictChanged {
			detail = strings.Join(probe.Changes, "; ")
		}
		g.registry.addEvent(topologyEvent{Time: checked, Type: gtType, IP: h.IP, SensorID: h.SensorID, Detail: detail})
		g.registry.dirty = true
		g.registry.mu.Unlock()

		switch {
		case probe.First && verdict != verdictUnreachable:
			quiet++ // first contact establishes ground truth, no verdict yet
		case verdict == verdictChanged:
			changed++
			g.escalate(h, probe)
		case verdict == verdictQuiet:
			quiet++
		default:
			unreachable++
		}
	}
	_ = g.registry.save()

	sum := fmt.Sprintf("skan kontrolny (%s): %d hostów cichych >%s — %d zweryfikowanych (w tym %d pierwszych baz), %d ZMIENIONYCH, %d nieosiągalnych",
		trigger, len(hosts), silent, quiet, baselined, changed, unreachable)
	g.mu.Lock()
	g.lastSum = sum
	g.mu.Unlock()
	kind := "status"
	if changed > 0 {
		kind = "alert"
	}
	g.feed.Append(kind, "", "Ground truth: "+sum, nil)
}

// escalate opens a case for a host that changed while passively silent.
func (g *groundTruth) escalate(h *HostRecord, probe hostProbe) {
	silentFor := time.Since(*h.SilentSince).Round(time.Minute)
	reason := fmt.Sprintf("Aktywny skan kontrolny wykrył zmianę u hosta cichego pasywnie od %s: %s. "+
		"Pasywna telemetria nie rozróżnia „host wyłączony” od „działa po cichu” (scenariusz silent_stealth) — dlatego skan był potrzebny jako ground truth.",
		silentFor, strings.Join(probe.Changes, "; "))
	eventID := "gt-" + strings.ReplaceAll(h.IP, ".", "-") + "-" + strconv.FormatInt(time.Now().Unix(), 36)
	event := map[string]interface{}{
		"time": time.Now().UTC().Format(time.RFC3339), "type": "ground_truth_change",
		"ip": h.IP, "changes": probe.Changes, "silent_for": silentFor.String(),
	}
	// CVE enrichment: banners captured by the control scan already name
	// products and versions; look them up in NVD and rank by EPSS so the
	// case says "this instance has CVE-XXXX with EPSS 0.94" instead of
	// just "something changed". Fail-soft: no network, no enrichment.
	if vulns := g.enrichCVE(probe); len(vulns) > 0 {
		event["vulns"] = vulns
		top := vulns[0]
		extra := fmt.Sprintf(" Najgroźniejsza znana podatność: %s (EPSS %.2f", top.CVE, top.EPSS)
		if top.KEV {
			extra += ", na liście CISA KEV — aktywnie eksploitowana"
		}
		reason += extra + ")."
	}
	envelope, _ := json.Marshal(map[string]interface{}{
		"event":     event,
		"event_id":  eventID,
		"sensor_id": h.SensorID, "forward": true, "reason": reason,
	})
	c := &Case{
		EventID:  eventID,
		Received: time.Now(), Envelope: envelope,
		SensorID: h.SensorID, EventType: "ground_truth_change",
		EventTime: time.Now().UTC().Format(time.RFC3339),
		Source:    h.IP, Target: "—", Score: 0.75,
		Reason: reason, Status: StatusNew,
	}
	if _, err := g.store.AddEscalation(c); err != nil {
		g.feed.Append("alert", h.SensorID, "Ground truth: nie udało się zapisać sprawy dla "+h.IP+": "+err.Error(), nil)
	}
}

// enrichCVE looks up the banners captured by the control scan in NVD and
// ranks the findings by EPSS. Disabled in settings, missing client or
// lookup errors all degrade to nil — a case without CVEs is still a case.
func (g *groundTruth) enrichCVE(probe hostProbe) []result.Vuln {
	snap := g.settings.snapshot()
	if !cveLookupEffective(snap.CVELookup) {
		return nil
	}
	client := g.cveClient()
	if client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seen := map[string]bool{}
	var out []result.Vuln
	for _, banner := range probe.Open {
		if banner == "" {
			continue
		}
		vs, err := client.EnrichBanner(ctx, banner)
		if err != nil {
			continue
		}
		for _, v := range vs {
			if !seen[v.CVE] {
				seen[v.CVE] = true
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EPSS != out[j].EPSS {
			return out[i].EPSS > out[j].EPSS
		}
		return out[i].CVSS > out[j].CVSS
	})
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// status is the operator-facing snapshot for the API.
func (g *groundTruth) status() map[string]interface{} {
	enabled, interval, silent, sample := g.gtConfig()
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]interface{}{
		"enabled": enabled, "interval": interval.String(), "silent_threshold": silent.String(),
		"sample": sample, "registry_hosts": g.registry.size(),
		"running": g.running,
	}
	if !g.lastRun.IsZero() {
		out["last_run"] = g.lastRun
		out["last_summary"] = g.lastSum
	}
	return out
}

// flush persists the registry; called on shutdown paths and periodically.
func (g *groundTruth) flush() { _ = g.registry.save() }
