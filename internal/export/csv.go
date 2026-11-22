// Package export turns scan results and trigger findings into formats other
// tools read: CSV for spreadsheets, nmap XML, and selected observations
// (admin panels, default pages, expired certificates, ...) that the
// defectdojo subpackage sends to DefectDojo.
//
// It only depends on the result model and the trigger's finding type, so
// the CLI and a server can use it alike.
package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/diff"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/trigger"
)

// ScanColumns is the CSV header of a scan export. The order is stable: new
// columns are only ever appended.
var ScanColumns = []string{
	"address", "hostnames", "port", "proto", "service", "product", "version",
	"http_status", "http_title", "http_server",
	"tls_subject", "tls_issuer", "tls_not_after", "tls_self_signed",
	"technologies", "tags", "confidence", "max_confidence",
}

// FindingColumns is the CSV header of a trigger findings export.
var FindingColumns = []string{
	"time", "target", "kind", "verdict", "events", "services", "technologies", "changes",
	"score", "reason", "error",
}

// listSep separates list items inside one CSV cell.
const listSep = "; "

// WriteScanCSV writes one row per open service. The confidence column lists
// one value per technology, in the same order as the technologies column.
func WriteScanCSV(w io.Writer, scans ...*result.Scan) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(ScanColumns); err != nil {
		return err
	}
	for _, s := range scans {
		for i := range s.Hosts {
			h := &s.Hosts[i]
			for j := range h.Services {
				if h.Services[j].State != "open" {
					continue
				}
				if err := cw.Write(safeRow(scanRow(h, &h.Services[j]))); err != nil {
					return err
				}
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

func scanRow(h *result.Host, s *result.Service) []string {
	var status, title, server, subject, issuer, notAfter, selfSigned string
	if p := s.HTTP; p != nil {
		if p.Status != 0 {
			status = strconv.Itoa(p.Status)
		}
		title = p.Title
		server = strings.Join(p.Headers["server"], ", ")
		if t := p.TLS; t != nil {
			subject, issuer = t.Subject, t.Issuer
			notAfter = t.NotAfter.UTC().Format(time.RFC3339)
			selfSigned = strconv.FormatBool(t.SelfSigned)
		}
	}
	var techs, conf []string
	best := 0.0
	tags := map[string]bool{}
	for _, t := range s.Tech {
		techs = append(techs, techLabel(t))
		conf = append(conf, strconv.FormatFloat(t.Confidence, 'f', 2, 64))
		best = max(best, t.Confidence)
		for _, tag := range t.Tags {
			tags[tag] = true
		}
	}
	maxConf := ""
	if len(s.Tech) > 0 {
		maxConf = strconv.FormatFloat(best, 'f', 2, 64)
	}
	return []string{
		h.Address, strings.Join(h.Hostnames, listSep), strconv.Itoa(s.Port), s.Proto, s.Name, s.Product, s.Version,
		status, title, server,
		subject, issuer, notAfter, selfSigned,
		strings.Join(techs, listSep), strings.Join(sortedKeys(tags), listSep), strings.Join(conf, listSep), maxConf,
	}
}

// WriteFindingsCSV writes one row per trigger finding.
func WriteFindingsCSV(w io.Writer, findings []trigger.Finding) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(FindingColumns); err != nil {
		return err
	}
	for _, f := range findings {
		if err := cw.Write(safeRow(findingRow(f))); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func findingRow(f trigger.Finding) []string {
	var events, services, techs []string
	for _, e := range f.Events {
		label := string(e.Type)
		if e.Port != 0 {
			label += fmt.Sprintf(" %d/%s", e.Port, e.Proto)
		}
		events = append(events, label)
	}
	seen := map[string]bool{}
	for _, s := range f.Services {
		label := fmt.Sprintf("%d/%s", s.Port, s.Name)
		if p := strings.TrimSpace(s.Product + " " + s.Version); p != "" {
			label += " " + p
		}
		services = append(services, label)
		for _, t := range s.Tech {
			if !seen[t] {
				seen[t] = true
				techs = append(techs, t)
			}
		}
	}
	score := ""
	if f.Score != 0 {
		score = strconv.FormatFloat(f.Score, 'f', -1, 64)
	}
	return []string{
		f.Time.UTC().Format(time.RFC3339), f.Target.String(), string(f.Kind), f.Verdict,
		strings.Join(events, listSep), strings.Join(services, listSep), strings.Join(techs, listSep), changes(f.Changes),
		score, f.Reason, f.Error,
	}
}

// changes summarizes a diff in one cell: "new 8787/tcp http nginx;
// changed 80/tcp: http.title "a" -> "b"".
func changes(d *diff.Diff) string {
	if d == nil {
		return ""
	}
	var out []string
	for _, h := range d.Hosts {
		if h.Kind != diff.Changed {
			out = append(out, fmt.Sprintf("host %s", h.Kind))
		}
		for _, s := range h.Services {
			item := fmt.Sprintf("%s %d/%s %s", s.Kind, s.Port, s.Proto, s.Label)
			if s.Kind == diff.Changed {
				var fields []string
				for _, c := range s.Changes {
					fields = append(fields, fmt.Sprintf("%s %q -> %q", c.Field, c.Old, c.New))
				}
				item = fmt.Sprintf("%s %d/%s: %s", s.Kind, s.Port, s.Proto, strings.Join(fields, ", "))
			}
			out = append(out, item)
		}
	}
	return strings.Join(out, listSep)
}

// safeRow keeps spreadsheets from running cells as formulas. Titles and
// headers come from the scanned hosts, so a page titled
// =HYPERLINK("http://evil") would otherwise become active content in the
// analyst's spreadsheet. JSON exports keep the raw value.
func safeRow(row []string) []string {
	for i, c := range row {
		if c != "" && strings.ContainsRune("=+-@\t\r\n", rune(c[0])) {
			row[i] = "'" + c
		}
	}
	return row
}

func techLabel(t result.Tech) string {
	if t.Version == "" {
		return t.Name
	}
	return t.Name + " " + t.Version
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
