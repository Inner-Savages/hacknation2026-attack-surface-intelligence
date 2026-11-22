package main

// TLS certificate monitoring. Control scans already capture the peer
// certificate on TLS ports (ground truth probes); this engine ages those
// records and applies the tlspolicy rules: certificates expiring within
// 30/14/7 days, self-signed certs, issuer (CA) changes against the
// previous observation, and weak negotiated cryptography. It is the
// cheapest high-quality alert in attack-surface management — pure
// arithmetic over data the console already holds.
//
// Escalation discipline: one case per (host, port, cert, kind) — the store
// dedupes on the deterministic event ID. Expiry re-escalates only when a
// tighter threshold (30 -> 14 -> 7) is crossed; a renewed certificate has
// a new fingerprint, so it starts its own escalation lifecycle. Findings
// that stop applying close out of the inventory on the next run.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/tlspolicy"
)

// tlsIssue is one open finding in the TLS inventory.
type tlsIssue struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Proto       string    `json:"proto"`
	Kind        string    `json:"kind"`
	Severity    string    `json:"severity"`
	Threshold   int       `json:"threshold,omitempty"`
	Message     string    `json:"message"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
	SHA256      string    `json:"sha256"`
	FirstRaised time.Time `json:"first_raised"`
	LastSeen    time.Time `json:"last_seen"`
}

// prevCert remembers the last certificate seen on host:port, so a CA
// change is detected against the previous observation.
type prevCert struct {
	Issuer string `json:"issuer"`
	SHA256 string `json:"sha256"`
}

// tlsState is the durable inventory and escalation memory.
type tlsState struct {
	Issues []*tlsIssue         `json:"issues,omitempty"`
	Prev   map[string]prevCert `json:"prev,omitempty"`
	// expiryEscalated maps ip|port|sha -> tightest expiry threshold already
	// escalated (30 -> 14 -> 7 only tightens).
	ExpiryEscalated map[string]int `json:"expiry_escalated,omitempty"`
	// escalated maps deterministic event IDs already raised (self-signed,
	// CA change, weak crypto, expired) so a restart cannot re-raise them.
	Escalated map[string]bool `json:"escalated,omitempty"`
}

// tlsMonitor drives scheduled and on-demand policy runs.
type tlsMonitor struct {
	settings *settings
	store    *Store
	feed     *LiveFeed
	gt       *groundTruth
	path     string

	mu      sync.Mutex
	running bool
	lastRun time.Time
	lastSum string
	state   tlsState
}

func newTLSMonitor(dir string, st *Store, feed *LiveFeed, cfg *settings, gt *groundTruth) (*tlsMonitor, error) {
	m := &tlsMonitor{
		settings: cfg, store: st, feed: feed, gt: gt,
		path: filepath.Join(dir, "tls.json"),
	}
	b, err := os.ReadFile(m.path)
	if err == nil {
		_ = json.Unmarshal(b, &m.state)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if m.state.Prev == nil {
		m.state.Prev = map[string]prevCert{}
	}
	if m.state.ExpiryEscalated == nil {
		m.state.ExpiryEscalated = map[string]int{}
	}
	if m.state.Escalated == nil {
		m.state.Escalated = map[string]bool{}
	}
	return m, nil
}

func (m *tlsMonitor) saveLocked() error {
	b, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// tlsConfig resolves the effective policy: on by default (pure arithmetic
// over data the console already holds), hourly.
func (m *tlsMonitor) tlsConfig() (enabled bool, interval time.Duration) {
	snap := m.settings.snapshot()
	enabled = snap.TLSEnabled == nil || *snap.TLSEnabled
	interval = time.Hour
	if snap.TLSIntervalMin > 0 {
		interval = time.Duration(snap.TLSIntervalMin) * time.Minute
	}
	return
}

// tick runs a scheduled pass when due; called every minute.
func (m *tlsMonitor) tick() {
	enabled, interval := m.tlsConfig()
	if !enabled {
		return
	}
	m.mu.Lock()
	due := !m.running && (m.lastRun.IsZero() || time.Since(m.lastRun) >= interval)
	m.mu.Unlock()
	if due {
		m.run("harmonogram (co " + interval.String() + ")")
	}
}

// run evaluates every TLS record the ground-truth registry holds.
func (m *tlsMonitor) run(trigger string) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.lastRun = time.Now()
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	now := time.Now()
	hosts := m.gt.registry.hostsSnapshot()

	type escalation struct {
		issue *tlsIssue
		score float64
	}
	var escalations []escalation
	var openIssues []*tlsIssue
	certs := 0

	m.mu.Lock()
	for _, h := range hosts {
		for key, rec := range h.TLS {
			certs++
			port, proto, _ := strings.Cut(key, "/")
			p, _ := strconv.Atoi(port)
			if proto == "" {
				proto = "tcp"
			}
			prev, hasPrev := m.state.Prev[h.IP+"|"+key]
			var prevRec *tlspolicy.Record
			if hasPrev && prev.SHA256 != rec.SHA256 {
				// A different certificate than last time: issuer changes
				// are checked against it.
				prevRec = &tlspolicy.Record{Issuer: prev.Issuer}
			}
			findings := tlspolicy.Evaluate(tlspolicy.Record{
				Subject: rec.Subject, Issuer: rec.Issuer, NotAfter: rec.NotAfter,
				SelfSigned: rec.SelfSigned, Version: rec.Version, Cipher: rec.Cipher,
			}, prevRec, now)
			m.state.Prev[h.IP+"|"+key] = prevCert{Issuer: rec.Issuer, SHA256: rec.SHA256}

			for _, f := range findings {
				issue := &tlsIssue{
					IP: h.IP, Port: p, Proto: proto, Kind: f.Kind, Severity: f.Severity,
					Threshold: f.Threshold, Message: f.Message,
					Subject: rec.Subject, Issuer: rec.Issuer, NotAfter: rec.NotAfter,
					SHA256: rec.SHA256, FirstRaised: now, LastSeen: now,
				}
				// Already tracked? Refresh it instead of duplicating.
				for _, old := range m.state.Issues {
					if old.IP == issue.IP && old.Port == issue.Port && old.Kind == issue.Kind && old.SHA256 == issue.SHA256 {
						old.Severity, old.Threshold, old.Message, old.LastSeen = issue.Severity, issue.Threshold, issue.Message, now
						issue = old
						break
					}
				}
				// Everything still applying stays in the open inventory;
				// findings that stopped applying close out with this run.
				openIssues = append(openIssues, issue)

				// Escalation memory: expiry tightens 30 -> 14 -> 7, other
				// kinds escalate exactly once per certificate.
				sha := rec.SHA256
				if len(sha) > 12 {
					sha = sha[:12]
				}
				memKey := h.IP + "|" + key + "|" + sha
				switch f.Kind {
				case tlspolicy.KindExpiring:
					if last, ok := m.state.ExpiryEscalated[memKey]; !ok || f.Threshold < last {
						m.state.ExpiryEscalated[memKey] = f.Threshold
						escalations = append(escalations, escalation{issue, tlsScore(f.Severity)})
					}
				default:
					eventKey := memKey + "|" + f.Kind
					if !m.state.Escalated[eventKey] {
						m.state.Escalated[eventKey] = true
						escalations = append(escalations, escalation{issue, tlsScore(f.Severity)})
					}
				}
			}
		}
	}
	m.state.Issues = openIssues
	if err := m.saveLocked(); err != nil {
		m.feed.Append("alert", "", "TLS: nie udało się zapisać stanu: "+err.Error(), nil)
	}
	escCopy := escalations
	critN := countSeverity(openIssues, tlspolicy.SevCrit)
	highN := countSeverity(openIssues, tlspolicy.SevHigh)
	openN := len(openIssues)
	m.mu.Unlock()

	for _, esc := range escCopy {
		m.escalate(esc.issue, esc.score)
		// TLS findings are topology events too: the map timeline shows the
		// certificate surface aging next to services and exposures.
		m.gt.registry.mu.Lock()
		m.gt.registry.addEvent(topologyEvent{
			Time: now, Type: "tls_finding", IP: esc.issue.IP,
			Port: esc.issue.Port, Proto: esc.issue.Proto, Detail: esc.issue.Message,
		})
		m.gt.registry.dirty = true
		m.gt.registry.mu.Unlock()
	}

	sum := fmt.Sprintf("kontrola TLS (%s): %d certyfikatów — %d otwartych znalezień (%d krytycznych, %d wysokich), %d nowych eskalacji",
		trigger, certs, openN, critN, highN, len(escCopy))
	m.mu.Lock()
	m.lastSum = sum
	m.mu.Unlock()
	kind := "status"
	if len(escCopy) > 0 {
		kind = "alert"
	}
	m.feed.Append(kind, "", "TLS: "+sum, nil)
}

func tlsScore(severity string) float64 {
	switch severity {
	case tlspolicy.SevCrit:
		return 0.85
	case tlspolicy.SevHigh:
		return 0.7
	default:
		return 0.5
	}
}

func countSeverity(issues []*tlsIssue, sev string) int {
	n := 0
	for _, i := range issues {
		if i.Severity == sev {
			n++
		}
	}
	return n
}

// escalate opens a case for one TLS finding.
func (m *tlsMonitor) escalate(issue *tlsIssue, score float64) {
	sha := issue.SHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	eventID := fmt.Sprintf("tls-%s-%d-%s-%s", strings.ReplaceAll(issue.IP, ".", "-"), issue.Port, sha, issue.Kind)
	if issue.Threshold > 0 {
		eventID += "-" + strconv.Itoa(issue.Threshold)
	}
	reason := fmt.Sprintf("Monitoring TLS: %s:%d — %s. Certyfikat: %s (wystawca: %s, ważny do %s). "+
		"Rekord pochodzi ze skanów kontrolnych ground truth — to najtańszy alert wysokiej jakości w macierzy attack surface management.",
		issue.IP, issue.Port, issue.Message, issue.Subject, issue.Issuer, issue.NotAfter.Format("2006-01-02"))
	envelope, _ := json.Marshal(map[string]interface{}{
		"event": map[string]interface{}{
			"time": time.Now().UTC().Format(time.RFC3339), "type": "tls",
			"ip": issue.IP, "port": issue.Port, "proto": issue.Proto,
			"kind": issue.Kind, "severity": issue.Severity,
			"subject": issue.Subject, "issuer": issue.Issuer, "not_after": issue.NotAfter,
		},
		"event_id":  eventID,
		"sensor_id": "tls-monitor", "forward": true, "reason": reason,
	})
	c := &Case{
		EventID:  eventID,
		Received: time.Now(), Envelope: envelope,
		SensorID: "tls-monitor", EventType: "tls",
		EventTime: time.Now().UTC().Format(time.RFC3339),
		Source:    issue.IP, Target: "—", Score: score,
		Reason: reason, Status: StatusNew,
	}
	if _, err := m.store.AddEscalation(c); err != nil {
		m.feed.Append("alert", "", "TLS: nie udało się zapisać sprawy: "+err.Error(), nil)
	}
}

// status is the operator-facing snapshot for the API.
func (m *tlsMonitor) status() map[string]interface{} {
	enabled, interval := m.tlsConfig()
	m.mu.Lock()
	defer m.mu.Unlock()
	issues := make([]*tlsIssue, len(m.state.Issues))
	copy(issues, m.state.Issues)
	sort.Slice(issues, func(i, j int) bool {
		rank := map[string]int{tlspolicy.SevCrit: 0, tlspolicy.SevHigh: 1, tlspolicy.SevWarn: 2, tlspolicy.SevInfo: 3}
		if rank[issues[i].Severity] != rank[issues[j].Severity] {
			return rank[issues[i].Severity] < rank[issues[j].Severity]
		}
		return issues[i].NotAfter.Before(issues[j].NotAfter)
	})
	out := map[string]interface{}{
		"enabled": enabled, "interval": interval.String(), "running": m.running,
		"issues": issues,
	}
	if !m.lastRun.IsZero() {
		out["last_run"] = m.lastRun
		out["last_summary"] = m.lastSum
	}
	return out
}
