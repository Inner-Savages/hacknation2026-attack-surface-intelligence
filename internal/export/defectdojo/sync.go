package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/export"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Scan types: DefectDojo's names for its report parsers, which are also the
// names of the test types.
const (
	genericScan = "Generic Findings Import"
	nmapScan    = "Nmap Scan"
)

// Context names where findings go in DefectDojo. Missing parts are created.
type Context struct {
	ProductType string
	Product     string
	Engagement  string
	Test        string
}

// DefaultContext is used for empty fields.
var DefaultContext = Context{
	ProductType: "Attack Surface",
	Product:     "Silence on the Wire",
	Engagement:  "Continuous discovery",
	Test:        "Silence on the Wire observations",
}

func (c Context) withDefaults() Context {
	for _, f := range []struct {
		v   *string
		def string
	}{
		{&c.ProductType, DefaultContext.ProductType}, {&c.Product, DefaultContext.Product},
		{&c.Engagement, DefaultContext.Engagement}, {&c.Test, DefaultContext.Test},
	} {
		if *f.v == "" {
			*f.v = f.def
		}
	}
	return c
}

// Status of one observation after a sync.
type Status string

const (
	Created   Status = "created"
	Updated   Status = "updated"   // already there, evidence refreshed
	Unchanged Status = "unchanged" // already there, nothing new
	// Closed: already there, but an analyst closed it (mitigated, false
	// positive, risk accepted, out of scope). Left alone.
	Closed Status = "closed"
)

// Item is the outcome for one observation.
type Item struct {
	Status   Status
	ID       int // DefectDojo finding id
	UniqueID string
	Title    string
}

// Report is the outcome of a sync.
type Report struct {
	TestID int
	Items  []Item
}

// Count returns how many items ended with the status.
func (r *Report) Count(s Status) int {
	n := 0
	for _, it := range r.Items {
		if it.Status == s {
			n++
		}
	}
	return n
}

// remoteFinding is what the sync needs to know about an existing finding.
type remoteFinding struct {
	ID            int      `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Date          string   `json:"date"`
	Active        bool     `json:"active"`
	Duplicate     bool     `json:"duplicate"`
	UniqueID      *string  `json:"unique_id_from_tool"`
	ComponentName *string  `json:"component_name"`
	Version       *string  `json:"component_version"`
	Tags          []string `json:"tags"`
}

// Sync makes DefectDojo contain one finding per observation. Findings are
// matched by unique_id_from_tool within the test:
//
//   - new ones are created in one reimport of only those findings, because
//     that is the one API that links them to endpoints both in DefectDojo 2
//     and in DefectDojo 3 (where endpoints became locations);
//   - existing active ones get fresh evidence if it changed;
//   - closed ones stay as the analyst left them.
//
// Findings whose observation is missing from this run are not closed: the
// run may have covered only a part of the network.
func (c *Client) Sync(ctx context.Context, where Context, obs []export.Observation) (*Report, error) {
	testID, err := c.ensureTest(ctx, where.withDefaults(), genericScan)
	if err != nil {
		return nil, err
	}
	rep := &Report{TestID: testID}
	existing, err := c.findings(ctx, testID)
	if err != nil {
		return nil, err
	}

	var fresh []Finding
	for _, o := range obs {
		f := NewFinding(o)
		old, ok := existing[f.UniqueID]
		if !ok {
			fresh = append(fresh, f)
			continue
		}
		it := Item{Status: Closed, ID: old.ID, UniqueID: f.UniqueID, Title: f.Title}
		// DefectDojo's date is the first time it was reported there.
		if t, err := time.Parse(dateFormat, old.Date); err == nil && t.Before(o.FirstSeen) {
			o.FirstSeen = t
			f = NewFinding(o)
		}
		if old.Active {
			if it.Status, err = c.refresh(ctx, old, f); err != nil {
				return rep, err
			}
		}
		rep.Items = append(rep.Items, it)
	}
	if len(fresh) == 0 {
		return rep, nil
	}

	report, err := json.Marshal(map[string]any{"findings": fresh})
	if err != nil {
		return rep, err
	}
	if err := c.reimport(ctx, testID, genericScan, time.Time{}, "silence-on-the-wire.json", report); err != nil {
		return rep, err
	}
	// Trust what is there, not what was sent.
	if existing, err = c.findings(ctx, testID); err != nil {
		return rep, err
	}
	var missing []string
	for _, f := range fresh {
		got, ok := existing[f.UniqueID]
		if !ok {
			missing = append(missing, f.UniqueID)
			continue
		}
		rep.Items = append(rep.Items, Item{Status: Created, ID: got.ID, UniqueID: f.UniqueID, Title: f.Title})
	}
	if len(missing) > 0 {
		return rep, fmt.Errorf("DefectDojo accepted the import but %d finding(s) are not in test %d: %v", len(missing), testID, missing)
	}
	return rep, nil
}

func (c *Client) findings(ctx context.Context, testID int) (map[string]remoteFinding, error) {
	all, err := list[remoteFinding](ctx, c, "/findings/", url.Values{"test": {strconv.Itoa(testID)}, "o": {"id"}})
	if err != nil {
		return nil, err
	}
	out := map[string]remoteFinding{}
	for _, f := range all {
		if f.UniqueID == nil || *f.UniqueID == "" {
			continue
		}
		// Should there be several anyway, the active one is the live one.
		if prev, ok := out[*f.UniqueID]; ok && prev.Active {
			continue
		}
		out[*f.UniqueID] = f
	}
	return out, nil
}

// refresh updates title, evidence, component and tags if they changed. It
// never touches status, severity, notes or tags analysts added.
func (c *Client) refresh(ctx context.Context, old remoteFinding, f Finding) (Status, error) {
	patch := map[string]any{}
	// DefectDojo stores titles in title case.
	if !strings.EqualFold(strings.TrimSpace(old.Title), strings.TrimSpace(f.Title)) {
		patch["title"] = f.Title
	}
	if normalize(old.Description) != normalize(f.Description) {
		patch["description"] = f.Description
	}
	if deref(old.Version) != f.ComponentVersion {
		patch["component_version"] = f.ComponentVersion
	}
	tags := slices.Clone(old.Tags)
	for _, t := range f.Tags {
		if !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	if len(tags) != len(old.Tags) {
		patch["tags"] = tags
	}
	if len(patch) == 0 {
		return Unchanged, nil
	}
	return Updated, c.send(ctx, http.MethodPatch, fmt.Sprintf("/findings/%d/", old.ID), patch, nil)
}

func normalize(s string) string {
	return string(bytes.TrimSpace(bytes.ReplaceAll([]byte(s), []byte("\r\n"), []byte("\n"))))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ImportNmap hands the scan to DefectDojo's built-in "Nmap Scan" importer:
// one informational finding per open port number. It goes into a test of
// its own in the same engagement. The importer only understands hosts with
// an IPv4 address; skipped is how many were left out.
func (c *Client) ImportNmap(ctx context.Context, where Context, s *result.Scan) (testID, skipped int, err error) {
	where = where.withDefaults()
	where.Test += " (nmap)"
	v4 := *s
	v4.Hosts = nil
	for _, h := range s.Hosts {
		if a, err := netip.ParseAddr(h.Address); err == nil && a.Is4() {
			v4.Hosts = append(v4.Hosts, h)
		} else {
			skipped++
		}
	}
	if len(v4.Hosts) == 0 {
		return 0, skipped, errors.New("no IPv4 hosts to import")
	}
	var buf bytes.Buffer
	if err := export.WriteNmapXML(&buf, &v4); err != nil {
		return 0, skipped, err
	}
	if testID, err = c.ensureTest(ctx, where, nmapScan); err != nil {
		return 0, skipped, err
	}
	return testID, skipped, c.reimport(ctx, testID, nmapScan, s.FinishedAt, "nmap.xml", buf.Bytes())
}

// reimport uploads a report into a test. close_old_findings is off because
// a report may cover only a part of what earlier ones did. A zero date
// leaves dates to the report.
func (c *Client) reimport(ctx context.Context, testID int, scanType string, date time.Time, name string, report []byte) error {
	fields := map[string]string{
		"test": strconv.Itoa(testID), "scan_type": scanType,
		"minimum_severity": "Info", "active": "true", "verified": "false",
		"close_old_findings": "false", "do_not_reactivate": "true",
	}
	if !date.IsZero() {
		fields["scan_date"] = date.UTC().Format(dateFormat)
	}
	var resp struct {
		TestID int `json:"test_id"`
	}
	return c.upload(ctx, fields, name, report, &resp)
}

type named struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

// ensureTest finds or creates product type, product, engagement and test.
func (c *Client) ensureTest(ctx context.Context, where Context, scanType string) (int, error) {
	today := time.Now().UTC()
	ptype, err := c.ensure(ctx, "/product_types/", url.Values{"name": {where.ProductType}}, where.ProductType,
		map[string]any{"name": where.ProductType})
	if err != nil {
		return 0, fmt.Errorf("product type %q: %w", where.ProductType, err)
	}
	product, err := c.ensure(ctx, "/products/", url.Values{"name_exact": {where.Product}}, where.Product,
		map[string]any{"name": where.Product, "prod_type": ptype, "description": "Services found by Silence on the Wire (passive sensor and safe active scans)."})
	if err != nil {
		return 0, fmt.Errorf("product %q: %w", where.Product, err)
	}
	engagement, err := c.ensure(ctx, "/engagements/", url.Values{"product": {strconv.Itoa(product)}, "name": {where.Engagement}}, where.Engagement,
		map[string]any{
			"name": where.Engagement, "product": product, "engagement_type": "CI/CD", "status": "In Progress",
			"target_start": today.Format(dateFormat), "target_end": today.AddDate(1, 0, 0).Format(dateFormat),
		})
	if err != nil {
		return 0, fmt.Errorf("engagement %q: %w", where.Engagement, err)
	}
	ttype, err := c.ensure(ctx, "/test_types/", url.Values{"name": {scanType}}, scanType,
		map[string]any{"name": scanType, "dynamic_tool": true, "active": true})
	if err != nil {
		return 0, fmt.Errorf("test type %q: %w", scanType, err)
	}
	test, err := c.ensure(ctx, "/tests/", url.Values{"engagement": {strconv.Itoa(engagement)}, "test_type": {strconv.Itoa(ttype)}}, where.Test,
		map[string]any{
			"title": where.Test, "engagement": engagement, "test_type": ttype,
			"target_start": today.Format(time.RFC3339), "target_end": today.AddDate(1, 0, 0).Format(time.RFC3339),
		})
	if err != nil {
		return 0, fmt.Errorf("test %q: %w", where.Test, err)
	}
	return test, nil
}

// ensure returns the object with exactly this name (or title), creating it
// if there is none. Server-side name filters match substrings in some
// versions, hence the check here.
func (c *Client) ensure(ctx context.Context, path string, query url.Values, name string, create map[string]any) (int, error) {
	found, err := list[named](ctx, c, path, query)
	if err != nil {
		return 0, err
	}
	for _, n := range found {
		if n.Name == name || n.Title == name {
			return n.ID, nil
		}
	}
	var got named
	if err := c.send(ctx, http.MethodPost, path, create, &got); err != nil {
		return 0, err
	}
	return got.ID, nil
}
