package main

// Host risk scoring: the "what do I fix first" view. Every module of the
// console already produces its own signals — the ML cascade scores cases,
// ground truth catches silent drift, the TLS monitor ages certificates,
// the exposure check diffs inside vs outside, the asset classifier labels
// devices. This module folds all of them through the pure riskscore
// package into one 0..100 score per host with a fully auditable factor
// breakdown, and serves the ranked Top-N listing.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	devclass "github.com/Inner-Savages/silence-on-the-wire/internal/classify"
	"github.com/Inner-Savages/silence-on-the-wire/internal/riskscore"
	"github.com/Inner-Savages/silence-on-the-wire/internal/tlspolicy"
)

// adminPorts are management-plane services whose presence on a host moves
// the risk score (aligned with the rule engine's seeded heuristics). SSH is
// ubiquitous and deliberately not counted.
var adminPorts = map[int]bool{
	23: true, 3389: true, 5900: true, 5985: true, 5986: true,
	2375: true, 111: true, 161: true,
}

// plainHTTPPorts are cleartext web ports; with TLS monitoring in place a
// service here never gets a certificate record.
var plainHTTPPorts = map[int]bool{80: true, 8080: true, 8000: true, 8888: true}

// newServiceWindow is how fresh a service must be to count as "new".
const newServiceWindow = 48 * time.Hour

// expectedBanner maps a well-known port to a substring its banner should
// contain; a captured banner that does not match is an odd signal.
var expectedBanner = map[int]string{
	22: "ssh", 25: "smtp", 587: "smtp", 21: "ftp",
	3306: "mysql", 5432: "postgres", 6379: "redis",
}

// hostRisk is one ranked row of the risk listing.
type hostRisk struct {
	IP           string             `json:"ip"`
	Class        string             `json:"class,omitempty"`
	Vendor       string             `json:"vendor,omitempty"`
	Score        float64            `json:"score"`
	Grade        string             `json:"grade"`
	Factors      []riskscore.Factor `json:"factors"`
	OpenCases    int                `json:"open_cases"`
	LastSeen     time.Time          `json:"last_seen"`
	CheckVerdict string             `json:"check_verdict,omitempty"`
}

// buildRiskInputs derives the riskscore input for every host in the
// registry from all console modules. It is read-only against every store.
func (s *server) buildRiskInputs(now time.Time) map[string]riskscore.Input {
	inputs := map[string]riskscore.Input{}

	// Registry: service surface, TLS coverage, drift, asset class.
	reg := s.gt.registry
	reg.mu.Lock()
	hosts := make(map[string]*HostRecord, len(reg.hosts))
	for ip, h := range reg.hosts {
		hosts[ip] = h
	}
	// New services per host from the topology timeline.
	for _, ev := range reg.events {
		if ev.Type == "service_new" && now.Sub(ev.Time) <= newServiceWindow {
			in := inputs[ev.IP]
			in.NewServices++
			inputs[ev.IP] = in
		}
	}
	reg.mu.Unlock()

	for ip, h := range hosts {
		in := inputs[ip]
		for _, svc := range h.Services {
			if adminPorts[svc.Port] {
				in.AdminPorts = append(in.AdminPorts, svc.Port)
			}
			if plainHTTPPorts[svc.Port] {
				in.PlainHTTP = append(in.PlainHTTP, svc.Port)
			}
			if tlsCandidate(svc.Port, svc.Banner) && h.TLS[h.serviceKey(svc.Port, svc.Proto)] == nil {
				in.MissingTLS = append(in.MissingTLS, svc.Port)
			}
			if want, ok := expectedBanner[svc.Port]; ok && svc.Banner != "" &&
				!strings.Contains(strings.ToLower(svc.Banner), want) {
				in.OddBanners = append(in.OddBanners, strconv.Itoa(svc.Port)+": "+svc.Banner)
			}
		}
		sort.Ints(in.AdminPorts)
		sort.Ints(in.PlainHTTP)
		sort.Ints(in.MissingTLS)
		if h.CheckVerdict == verdictChanged {
			in.ChangedWhileSilent = true
		}
		if h.SilentSince != nil {
			in.Silent = true
		}
		switch h.Class {
		case devclass.Camera, devclass.Printer, devclass.Phone, devclass.IoT:
			in.AlertClass = h.Class
		}
		inputs[ip] = in
	}

	// Cases: model scores, open/unresolved pressure, CVE/EPSS from the
	// ground-truth envelopes.
	for _, c := range s.store.ListCases() {
		if c.Source == "" || c.Source == "—" {
			continue
		}
		in, known := inputs[c.Source]
		if !known && !looksLikeIP(c.Source) {
			continue
		}
		if c.Score > in.MaxModelScore {
			in.MaxModelScore = c.Score
		}
		if c.Status == StatusNew || c.Status == StatusVerify {
			in.OpenCases++
		}
		if c.Unresolved {
			in.Unresolved++
		}
		if epss, kev, n := envelopeVulns(c.Envelope); n > 0 {
			in.CVECount += n
			if epss > in.MaxEPSS {
				in.MaxEPSS = epss
			}
			in.KEV = in.KEV || kev
		}
		inputs[c.Source] = in
	}

	// TLS findings by severity.
	if s.tlsMon != nil {
		s.tlsMon.mu.Lock()
		for _, issue := range s.tlsMon.state.Issues {
			in, known := inputs[issue.IP]
			if !known {
				continue
			}
			switch issue.Severity {
			case tlspolicy.SevCrit:
				in.TLSCrit++
			case tlspolicy.SevHigh:
				in.TLSHigh++
			case tlspolicy.SevWarn:
				in.TLSWarn++
			}
			inputs[issue.IP] = in
		}
		s.tlsMon.mu.Unlock()
	}

	// Exposure: an internal service confirmed on the public IP.
	if s.exposure != nil {
		s.exposure.mu.Lock()
		for _, f := range s.exposure.state.Findings {
			if f.Kind != findExposedInternal || f.MatchIP == "" {
				continue
			}
			in, known := inputs[f.MatchIP]
			if !known {
				continue
			}
			in.Exposed = true
			inputs[f.MatchIP] = in
		}
		s.exposure.mu.Unlock()
	}
	return inputs
}

// risk serves the ranked host listing: every host with its score, grade and
// factor breakdown, highest risk first. ?limit= bounds the listing
// (default 10 — the "Top 10" view).
func (s *server) risk(w http.ResponseWriter, r *http.Request) {
	if s.gt == nil {
		writeJSON(w, 200, map[string]interface{}{"hosts": []interface{}{}, "total": 0})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 10
	}
	inputs := s.buildRiskInputs(time.Now())
	rows := make([]hostRisk, 0, len(inputs))
	reg := s.gt.registry
	reg.mu.Lock()
	for ip, in := range inputs {
		out := riskscore.Score(in)
		row := hostRisk{IP: ip, Score: out.Score, Grade: out.Grade, Factors: out.Factors, OpenCases: in.OpenCases}
		if h := reg.hosts[ip]; h != nil {
			row.Class, row.Vendor = h.Class, h.ClassVendor
			row.LastSeen, row.CheckVerdict = h.LastSeen, h.CheckVerdict
		}
		rows = append(rows, row)
	}
	reg.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].IP < rows[j].IP
	})
	total := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	writeJSON(w, 200, map[string]interface{}{"hosts": rows, "total": total})
}

// envelopeVulns extracts the best EPSS and KEV flag from the vulns array a
// ground-truth case envelope may carry. Anything malformed degrades to
// "no vulnerability data", never to an error.
func envelopeVulns(env []byte) (maxEPSS float64, kev bool, count int) {
	var parsed struct {
		Event struct {
			Vulns []struct {
				EPSS float64 `json:"epss"`
				KEV  bool    `json:"kev"`
			} `json:"vulns"`
		} `json:"event"`
	}
	if json.Unmarshal(env, &parsed) != nil {
		return 0, false, 0
	}
	for _, v := range parsed.Event.Vulns {
		count++
		if v.EPSS > maxEPSS {
			maxEPSS = v.EPSS
		}
		kev = kev || v.KEV
	}
	return maxEPSS, kev, count
}

// looksLikeIP is a cheap guard against attributing cases to non-host
// sources (targets, labels).
func looksLikeIP(s string) bool {
	return strings.Count(s, ".") == 3 || strings.Contains(s, ":")
}
