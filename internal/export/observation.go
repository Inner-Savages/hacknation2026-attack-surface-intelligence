package export

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/sensor"
	"github.com/Inner-Savages/silence-on-the-wire/internal/trigger"
)

// Observation is something about one service worth a person's attention,
// with the evidence for it.
type Observation struct {
	// ID is stable across scans: it depends on the rule, the service and,
	// for per-component rules, the component, never on versions, titles or
	// times. The same observation in the next scan has the same ID.
	ID        string
	Rule      string // admin-panel, cert-expired, category:database, ...
	Title     string // what it is, without the address
	Why       string // why it matters
	Action    string // what to check
	Address   string
	Hostnames []string
	Service   result.Service
	// Confidence is the highest confidence among Matched, 1 for facts read
	// straight from the service (certificates).
	Confidence float64
	Matched    []result.Tech // what made the rule match; empty for certificates
	Component  string        // product an outdated version or a CVE belongs to
	Version    string
	VulnIDs    []string // CVE ids, for rules that know them
	FirstSeen  time.Time
	LastSeen   time.Time
	Events     []Event // sensor events and verdicts for this service, oldest first
}

// Event is what the sensor and the trigger noticed about a service.
type Event struct {
	Time   time.Time
	Text   string
	Reason string
}

// HostPort is the service's address, usable in URLs.
func (o *Observation) HostPort() string {
	return net.JoinHostPort(o.Address, strconv.Itoa(o.Service.Port))
}

// URL of the service; the scheme is the transport for non-web services.
func (o *Observation) URL() string {
	scheme := o.Service.Proto
	if h := o.Service.HTTP; h != nil {
		scheme = "http"
		if u, err := url.Parse(h.URL); err == nil && u.Scheme != "" {
			scheme = u.Scheme
		}
	}
	return scheme + "://" + o.HostPort()
}

// Match is one hit of a rule on a service.
type Match struct {
	Tech       []result.Tech
	Confidence float64
	// Component distinguishes several hits of one rule on one service and
	// becomes part of the observation's ID.
	Component string
	Version   string
	Title     string // overrides the rule's title
	Why       string // overrides the rule's explanation
	VulnIDs   []string
}

// Rule recognizes one kind of observation on an open service. New kinds
// (known vulnerabilities of the detected version, for one) are added by
// passing more rules in Selection.Rules; nothing else has to change.
type Rule struct {
	Name   string // selects the rule and is part of observation IDs
	Title  string
	Why    string
	Action string
	// Match returns the hits; at is when the service was seen.
	Match func(s *result.Service, at time.Time) []Match
}

// DefaultRules are what a security team usually wants to know about first.
func DefaultRules() []Rule {
	return []Rule{
		tagRule("admin-panel", "Administration panel reachable",
			"Administration interfaces are a preferred target for password guessing and for exploits of the product itself.",
			"Confirm the panel is meant to be reachable from where it was scanned; otherwise restrict it to a management network."),
		tagRule("setup-page", "Unfinished installation",
			"An installer left open lets the first visitor configure the application and become its administrator.",
			"Finish or remove the installation."),
		tagRule("default-page", "Default web server page",
			"A default page usually means a forgotten or half-configured server nobody maintains.",
			"Find the owner; decommission the server or put the intended site on it."),
		tagRule("staging", "Staging or test environment",
			"Test copies tend to run with weaker configuration, debug output and real data.",
			"Confirm it should be reachable from where it was scanned."),
		tagRule("intentionally-vulnerable", "Intentionally vulnerable application",
			"Training targets such as DVWA give whoever reaches them code execution on the host by design.",
			"Isolate it from any real network or remove it."),
		{
			Name: "cert-self-signed", Title: "Self-signed certificate",
			Why:    "Clients cannot tell the real service from an impostor, and users learn to click through warnings.",
			Action: "Replace the certificate with one issued by a trusted (possibly internal) CA.",
			Match: func(s *result.Service, _ time.Time) []Match {
				if t := tlsOf(s); t != nil && t.SelfSigned {
					return []Match{{Confidence: 1}}
				}
				return nil
			},
		},
		{
			Name: "cert-expired", Title: "Expired certificate",
			Why:    "An expired certificate breaks strict clients and often marks a service nobody looks after.",
			Action: "Renew the certificate and find out why renewal did not happen.",
			Match: func(s *result.Service, at time.Time) []Match {
				if t := tlsOf(s); t != nil && (t.Expired || t.NotAfter.Before(at)) {
					return []Match{{Confidence: 1}}
				}
				return nil
			},
		},
		{
			Name:   "outdated-component",
			Action: "Verify the version on the host (distributions backport fixes) and plan an upgrade.",
			Match:  matchOutdated,
		},
	}
}

func tagRule(tag, title, why, action string) Rule {
	return Rule{Name: tag, Title: title, Why: why, Action: action, Match: matchTech(func(t result.Tech) bool {
		return slices.Contains(t.Tags, tag)
	})}
}

func matchTech(want func(result.Tech) bool) func(*result.Service, time.Time) []Match {
	return func(s *result.Service, _ time.Time) []Match {
		var m Match
		for _, t := range s.Tech {
			if want(t) {
				m.Tech = append(m.Tech, t)
				m.Confidence = max(m.Confidence, t.Confidence)
			}
		}
		if len(m.Tech) == 0 {
			return nil
		}
		return []Match{m}
	}
}

func matchOutdated(s *result.Service, _ time.Time) []Match {
	var out []Match
	for _, t := range s.Tech {
		number, oldest, ok := outdated(t.Name, t.Version)
		if !ok {
			continue
		}
		out = append(out, Match{
			Tech: []result.Tech{t}, Confidence: t.Confidence, Component: t.Name, Version: t.Version,
			Title: "Outdated " + t.Name,
			Why:   fmt.Sprintf("%s reports version %s; releases older than %s no longer get security fixes upstream.", t.Name, number, oldest),
		})
	}
	return out
}

func tlsOf(s *result.Service) *result.TLS {
	if s.HTTP == nil {
		return nil
	}
	return s.HTTP.TLS
}

// Selection says which observations to export.
type Selection struct {
	// Names of rules, or category:<c>, tag:<t>, tech:<name>; "default"
	// stands for all default rules. Empty means "default".
	Names         []string
	MinConfidence float64
	// Rules in addition to the default ones, always applied.
	Rules []Rule
}

// ParseSelection parses a comma separated list, e.g. "default,category:database".
func ParseSelection(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func (sel Selection) rules() ([]Rule, error) {
	defaults := DefaultRules()
	names := sel.Names
	if len(names) == 0 {
		names = []string{"default"}
	}
	var out []Rule
	have := map[string]bool{}
	add := func(r Rule) {
		if !have[r.Name] {
			have[r.Name] = true
			out = append(out, r)
		}
	}
	for _, name := range names {
		kind, value, prefixed := strings.Cut(name, ":")
		switch {
		case name == "default":
			for _, r := range defaults {
				add(r)
			}
		case prefixed && value != "" && kind == "category":
			add(genericRule(name, "Reachable "+value+" service", func(t result.Tech) bool { return strings.EqualFold(t.Category, value) }))
		case prefixed && value != "" && kind == "tag":
			add(genericRule(name, "Service tagged "+value, func(t result.Tech) bool { return slices.Contains(t.Tags, value) }))
		case prefixed && value != "" && kind == "tech":
			add(genericRule(name, value+" detected", func(t result.Tech) bool { return strings.EqualFold(t.Name, value) }))
		default:
			i := slices.IndexFunc(defaults, func(r Rule) bool { return r.Name == name })
			if i < 0 {
				var known []string
				for _, r := range defaults {
					known = append(known, r.Name)
				}
				return nil, fmt.Errorf("unknown selection %q: use default, %s, category:<c>, tag:<t> or tech:<name>", name, strings.Join(known, ", "))
			}
			add(defaults[i])
		}
	}
	for _, r := range sel.Rules {
		add(r)
	}
	return out, nil
}

func genericRule(name, title string, want func(result.Tech) bool) Rule {
	return Rule{Name: name, Title: title, Why: "Selected for export.", Action: "Review the evidence.", Match: matchTech(want)}
}

// Observe extracts the selected observations from scans. When several scans
// contain the same observation, the newest one provides the evidence and
// the oldest one the first-seen time.
func Observe(sel Selection, scans ...*result.Scan) ([]Observation, error) {
	rules, err := sel.rules()
	if err != nil {
		return nil, err
	}
	byID := map[string]Observation{}
	for _, scan := range scans {
		at := seenAt(scan)
		for i := range scan.Hosts {
			h := &scan.Hosts[i]
			for j := range h.Services {
				if h.Services[j].State != "open" {
					continue
				}
				for _, o := range observeService(rules, h, &h.Services[j], at) {
					if o.Confidence < sel.MinConfidence {
						continue
					}
					if prev, ok := byID[o.ID]; ok {
						if prev.LastSeen.After(o.LastSeen) {
							prev, o = o, prev
						}
						o.FirstSeen = earlier(prev.FirstSeen, o.FirstSeen)
					}
					byID[o.ID] = o
				}
			}
		}
	}
	out := make([]Observation, 0, len(byID))
	for _, o := range byID {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := &out[i], &out[j]
		switch {
		case a.Address != b.Address:
			return result.AddrLess(a.Address, b.Address)
		case a.Service.Port != b.Service.Port:
			return a.Service.Port < b.Service.Port
		}
		return a.ID < b.ID
	})
	return out, nil
}

func observeService(rules []Rule, h *result.Host, s *result.Service, at time.Time) []Observation {
	var out []Observation
	for _, r := range rules {
		for _, m := range r.Match(s, at) {
			id := fmt.Sprintf("sotw:%s:%s:%s:%d", r.Name, h.Address, s.Proto, s.Port)
			if m.Component != "" {
				id += ":" + strings.ToLower(m.Component)
			}
			o := Observation{
				ID: id, Rule: r.Name, Title: r.Title, Why: r.Why, Action: r.Action,
				Address: h.Address, Hostnames: h.Hostnames, Service: *s,
				Confidence: m.Confidence, Matched: m.Tech, Component: m.Component, Version: m.Version,
				VulnIDs: m.VulnIDs, FirstSeen: at, LastSeen: at,
			}
			if m.Title != "" {
				o.Title = m.Title
			}
			if m.Why != "" {
				o.Why = m.Why
			}
			out = append(out, o)
		}
	}
	return out
}

func seenAt(s *result.Scan) time.Time {
	if s.FinishedAt.IsZero() {
		return s.StartedAt
	}
	return s.FinishedAt
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// AddHistory lowers first-seen times using older scans. An observation only
// present in the old scans is not added: it may be gone.
func AddHistory(obs []Observation, sel Selection, old ...*result.Scan) error {
	sel.MinConfidence = 0
	prev, err := Observe(sel, old...)
	if err != nil {
		return err
	}
	first := map[string]time.Time{}
	for _, o := range prev {
		first[o.ID] = o.FirstSeen
	}
	for i := range obs {
		if t, ok := first[obs[i].ID]; ok {
			obs[i].FirstSeen = earlier(t, obs[i].FirstSeen)
		}
	}
	return nil
}

// maxEvents keeps the evidence readable: the latest events matter most.
const maxEvents = 5

// AddFindings attaches what the sensor and the trigger noticed about each
// observed service: the latest few findings about its host and port.
func AddFindings(obs []Observation, findings []trigger.Finding) {
	for i := range obs {
		o := &obs[i]
		var events []Event
		for _, f := range findings {
			if f.Target.IP.String() != o.Address {
				continue
			}
			var types []string
			for _, e := range f.Events {
				if concerns(e, o) && !slices.Contains(types, string(e.Type)) {
					types = append(types, string(e.Type))
				}
			}
			if len(types) == 0 {
				continue
			}
			events = append(events, Event{Time: f.Time, Text: strings.Join(types, ", ") + " -> " + f.Verdict, Reason: f.Reason})
		}
		sort.SliceStable(events, func(a, b int) bool { return events[a].Time.Before(events[b].Time) })
		if n := len(events); n > maxEvents {
			events = events[n-maxEvents:]
		}
		o.Events = events
	}
}

// concerns reports whether a sensor event is about the observed service or
// its host as a whole.
func concerns(e sensor.Event, o *Observation) bool {
	return e.Port == 0 || (int(e.Port) == o.Service.Port && (e.Proto == "" || e.Proto == o.Service.Proto))
}
