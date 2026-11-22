package defectdojo

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Inner-Savages/silence-on-the-wire/internal/export"
)

// Finding is one observation in DefectDojo's "Generic Findings Import"
// format. Severity is always Info: these are observations to look into, and
// rating them is the analyst's job.
type Finding struct {
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Mitigation       string   `json:"mitigation,omitempty"`
	Date             string   `json:"date"` // first seen
	Active           bool     `json:"active"`
	Verified         bool     `json:"verified"`
	DynamicFinding   bool     `json:"dynamic_finding"`
	StaticFinding    bool     `json:"static_finding"`
	UniqueID         string   `json:"unique_id_from_tool"`
	VulnID           string   `json:"vuln_id_from_tool"` // the rule
	ComponentName    string   `json:"component_name,omitempty"`
	ComponentVersion string   `json:"component_version,omitempty"`
	VulnerabilityIDs []string `json:"vulnerability_ids,omitempty"`
	Tags             []string `json:"tags"`
	Endpoints        []string `json:"endpoints"`
}

const dateFormat = "2006-01-02"

// DefectDojo column limits.
const (
	maxTitle     = 500
	maxComponent = 100
	maxVersion   = 100
	maxUniqueID  = 500
)

// NewFinding renders an observation.
func NewFinding(o export.Observation) Finding {
	f := Finding{
		Title:            truncate(fmt.Sprintf("%s on %s/%s", clean(o.Title), o.HostPort(), o.Service.Proto), maxTitle),
		Severity:         "Info",
		Description:      describe(o),
		Mitigation:       o.Action,
		Date:             o.FirstSeen.UTC().Format(dateFormat),
		Active:           true,
		DynamicFinding:   true,
		UniqueID:         truncate(o.ID, maxUniqueID),
		VulnID:           o.Rule,
		ComponentName:    truncate(clean(o.Component), maxComponent),
		ComponentVersion: truncate(clean(o.Version), maxVersion),
		VulnerabilityIDs: o.VulnIDs,
		// DefectDojo tags may not contain commas or spaces; the rule's
		// prefix separator would read oddly in its tag filter.
		Tags:      []string{"silence-on-the-wire", strings.NewReplacer(":", "-", " ", "-", ",", "-").Replace(strings.ToLower(o.Rule))},
		Endpoints: []string{o.URL()},
	}
	return f
}

// describe renders the evidence as Markdown. Everything the scanned host
// controls (titles, headers, certificate names, versions) goes into code
// spans, so a hostile page cannot put links or markup into the report.
func describe(o export.Observation) string {
	var b strings.Builder
	section := func(name string) { fmt.Fprintf(&b, "\n**%s**\n\n", name) }
	item := func(name, value string) {
		if clean(value) != "" {
			fmt.Fprintf(&b, "- %s: %s\n", name, code(value))
		}
	}
	fmt.Fprintf(&b, "%s\n", strings.TrimSpace(clean(o.Why)))

	s := o.Service
	section("Service")
	item("Address", o.HostPort()+"/"+s.Proto)
	item("Hostnames", strings.Join(o.Hostnames, ", "))
	item("Service", s.Name)
	item("Banner", strings.Join(strings.Fields(s.Product+" "+s.Version+" "+s.ExtraInfo), " "))
	item("CPE", strings.Join(s.CPE, ", "))
	item("Confidence", fmt.Sprintf("%.2f", o.Confidence))
	item("First seen", o.FirstSeen.UTC().Format(dateFormat))
	item("Last seen", o.LastSeen.UTC().Format(time.RFC3339))

	if h := s.HTTP; h != nil {
		section("HTTP")
		item("URL", h.URL)
		if h.FinalURL != h.URL {
			item("Final URL", h.FinalURL)
		}
		if h.Status != 0 {
			item("Status", fmt.Sprint(h.Status))
		}
		item("Title", h.Title)
		item("Server", strings.Join(h.Headers["server"], ", "))
		item("X-Powered-By", strings.Join(h.Headers["x-powered-by"], ", "))
		if h.Favicon != nil {
			item("Favicon hash (mmh3)", fmt.Sprint(h.Favicon.Hash))
		}
		if t := h.TLS; t != nil {
			section("Certificate")
			item("Subject", t.Subject)
			item("Issuer", t.Issuer)
			item("Names", strings.Join(append(append([]string{}, t.DNSNames...), t.IPs...), ", "))
			item("Valid", t.NotBefore.UTC().Format(dateFormat)+" to "+t.NotAfter.UTC().Format(dateFormat))
			item("Self-signed", fmt.Sprint(t.SelfSigned))
			item("SHA-256", t.SHA256)
			item("Protocol", t.Version+" "+t.Cipher)
		}
	}
	if len(s.Tech) > 0 {
		section("Technologies")
		for _, t := range s.Tech {
			name := strings.TrimSpace(t.Name + " " + t.Version)
			fmt.Fprintf(&b, "- %s, confidence %.2f\n", code(name), t.Confidence)
			for _, e := range t.Evidence {
				fmt.Fprintf(&b, "    - %s\n", code(e))
			}
		}
	}
	if len(o.Events) > 0 {
		section("Seen by the passive sensor")
		for _, e := range o.Events {
			line := e.Text
			if e.Reason != "" {
				line += " (" + e.Reason + ")"
			}
			item(e.Time.UTC().Format(time.RFC3339), line)
		}
	}
	return strings.TrimSpace(b.String())
}

// clean makes untrusted text a single line of printable characters.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case r == unicode.ReplacementChar || !unicode.IsPrint(r):
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

const maxValue = 300

// code renders untrusted text as a Markdown code span. A span cannot be
// closed early because backticks are replaced.
func code(s string) string {
	return "`" + strings.ReplaceAll(truncate(clean(s), maxValue), "`", "'") + "`"
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
