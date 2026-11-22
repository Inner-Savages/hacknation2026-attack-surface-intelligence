package export

import (
	"bytes"
	"encoding/csv"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/diff"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
	"github.com/Inner-Savages/silence-on-the-wire/internal/sensor"
	"github.com/Inner-Savages/silence-on-the-wire/internal/trigger"
)

var t0 = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

func testScan(at time.Time) *result.Scan {
	return &result.Scan{
		StartedAt: at.Add(-time.Minute), FinishedAt: at,
		Hosts: []result.Host{{
			Address: "10.0.0.5", State: "up", Hostnames: []string{"a.test", "b.test"},
			Services: []result.Service{
				{Port: 22, Proto: "tcp", State: "closed", Name: "ssh"},
				{Port: 443, Proto: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.18.0", Tunnel: "ssl", CPE: []string{"cpe:/a:igor_sysoev:nginx:1.18.0"},
					HTTP: &result.HTTP{
						URL: "https://10.0.0.5/", FinalURL: "https://10.0.0.5/", Status: 200, Title: `=cmd|"x", evil`,
						Headers: map[string][]string{"server": {"nginx/1.18.0"}},
						TLS: &result.TLS{Subject: "CN=a.test", Issuer: "CN=a.test", NotBefore: t0.AddDate(-1, 0, 0),
							NotAfter: t0.Add(time.Hour), SelfSigned: true, SHA256: "ab"},
					},
					Tech: []result.Tech{
						{Name: "nginx", Category: "server", Version: "1.18.0", Confidence: 0.98, Evidence: []string{"header server"}},
						{Name: "phpMyAdmin", Category: "db-admin", Confidence: 0.9, Tags: []string{"admin-panel"}, Evidence: []string{"title"}},
						{Name: "Admin panel", Category: "exposure", Confidence: 0.6, Tags: []string{"admin-panel"}, Evidence: []string{"title"}},
					}},
				{Port: 5432, Proto: "tcp", State: "open", Name: "postgresql", Product: "PostgreSQL DB", Version: "9.6.0 or later",
					Tech: []result.Tech{{Name: "PostgreSQL", Category: "database", Version: "9.6.0 or later", Confidence: 0.95}}},
			},
		}},
	}
}

func readCSV(t *testing.T, b []byte) []map[string]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, r := range rows[1:] {
		m := map[string]string{}
		for i, c := range r {
			m[rows[0][i]] = c
		}
		out = append(out, m)
	}
	return out
}

func TestScanCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteScanCSV(&buf, testScan(t0)); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, buf.Bytes())
	if len(rows) != 2 {
		t.Fatalf("want 2 open services, got %d", len(rows))
	}
	want := map[string]string{
		"address": "10.0.0.5", "hostnames": "a.test; b.test", "port": "443", "product": "nginx", "version": "1.18.0",
		"http_status": "200", "http_server": "nginx/1.18.0",
		"http_title":  `'=cmd|"x", evil`, // not a formula any more
		"tls_subject": "CN=a.test", "tls_not_after": "2026-11-22T11:00:00Z", "tls_self_signed": "true",
		"technologies": "nginx 1.18.0; phpMyAdmin; Admin panel", "tags": "admin-panel",
		"confidence": "0.98; 0.90; 0.60", "max_confidence": "0.98",
	}
	for k, v := range want {
		if rows[0][k] != v {
			t.Errorf("%s = %q, want %q", k, rows[0][k], v)
		}
	}
	if rows[1]["tls_self_signed"] != "" || rows[1]["http_status"] != "" {
		t.Errorf("non-web service has web columns: %v", rows[1])
	}
}

func testFinding() trigger.Finding {
	return trigger.Finding{
		Time: t0, Target: trigger.Target{IP: netip.MustParseAddr("10.0.0.5"), Port: 443}, Kind: trigger.ScanService,
		Verdict: trigger.VerdictScanned, Score: 0.75, Reason: "new banner",
		Events: []sensor.Event{
			{Type: sensor.ServiceChanged, IP: netip.MustParseAddr("10.0.0.5"), Port: 443, Proto: "tcp"},
			{Type: sensor.ServiceChanged, IP: netip.MustParseAddr("10.0.0.5"), Port: 443, Proto: "tcp"},
		},
		Services: []trigger.ServiceSummary{{Port: 443, Name: "http", Product: "nginx", Version: "1.18.0", Tech: []string{"nginx 1.18.0", "nginx 1.18.0"}}},
		Changes: &diff.Diff{Hosts: []diff.HostChange{{Address: "10.0.0.5", Kind: diff.Changed, Services: []diff.ServiceChange{
			{Port: 443, Proto: "tcp", Kind: diff.Changed, Changes: []diff.FieldChange{{Field: "http.title", Old: "a", New: "b"}}},
			{Port: 80, Proto: "tcp", Kind: diff.New, Label: "http nginx"},
		}}}},
	}
}

func TestFindingsCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFindingsCSV(&buf, []trigger.Finding{testFinding()}); err != nil {
		t.Fatal(err)
	}
	row := readCSV(t, buf.Bytes())[0]
	for k, v := range map[string]string{
		"time": "2026-11-22T10:00:00Z", "target": "10.0.0.5:443", "verdict": "scanned",
		"events":   "service_changed 443/tcp; service_changed 443/tcp",
		"services": "443/http nginx 1.18.0", "technologies": "nginx 1.18.0", "score": "0.75",
		"changes": `changed 443/tcp: http.title "a" -> "b"; new 80/tcp http nginx`,
	} {
		if row[k] != v {
			t.Errorf("%s = %q, want %q", k, row[k], v)
		}
	}
}

func ids(obs []Observation) []string {
	var out []string
	for _, o := range obs {
		out = append(out, o.ID)
	}
	return out
}

func TestObserveDefaults(t *testing.T) {
	obs, err := Observe(Selection{}, testScan(t0))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"sotw:admin-panel:10.0.0.5:tcp:443",
		"sotw:cert-self-signed:10.0.0.5:tcp:443",
		"sotw:outdated-component:10.0.0.5:tcp:443:nginx",
	}
	if got := ids(obs); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if len(obs[0].Matched) != 2 || obs[0].Confidence != 0.9 {
		t.Errorf("admin panel evidence: %+v", obs[0])
	}
	if obs[0].URL() != "https://10.0.0.5:443" {
		t.Errorf("URL = %s", obs[0].URL())
	}
	// The certificate runs out between two scans: same service, new finding.
	obs, _ = Observe(Selection{Names: []string{"cert-expired"}}, testScan(t0.Add(2*time.Hour)))
	if len(obs) != 1 {
		t.Errorf("expired certificate not observed: %v", ids(obs))
	}
}

func TestSelection(t *testing.T) {
	for _, tc := range []struct {
		names string
		min   float64
		want  string
	}{
		{"category:database", 0, "sotw:category:database:10.0.0.5:tcp:5432"},
		{"tech:NGINX", 0, "sotw:tech:NGINX:10.0.0.5:tcp:443"},
		{"tag:admin-panel", 0, "sotw:tag:admin-panel:10.0.0.5:tcp:443"},
		{"admin-panel, admin-panel", 0.91, ""},
		{"default", 0.99, "sotw:cert-self-signed:10.0.0.5:tcp:443"},
	} {
		obs, err := Observe(Selection{Names: ParseSelection(tc.names), MinConfidence: tc.min}, testScan(t0))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(ids(obs), " "); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.names, got, tc.want)
		}
	}
	if _, err := Observe(Selection{Names: []string{"admin-pannel"}}, testScan(t0)); err == nil {
		t.Error("a misspelled rule must not silently select nothing")
	}
}

// How known vulnerabilities plug in once results carry them.
func TestExtraRule(t *testing.T) {
	rule := Rule{Name: "known-vulnerability", Title: "Known vulnerability", Match: func(s *result.Service, _ time.Time) []Match {
		if s.Port != 443 {
			return nil
		}
		return []Match{{Confidence: 1, Component: "nginx", Version: "1.18.0", VulnIDs: []string{"CVE-2021-23017"}}}
	}}
	obs, err := Observe(Selection{Names: []string{"setup-page"}, Rules: []Rule{rule}}, testScan(t0))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].ID != "sotw:known-vulnerability:10.0.0.5:tcp:443:nginx" || obs[0].VulnIDs[0] != "CVE-2021-23017" {
		t.Errorf("got %+v", obs)
	}
}

func TestHistory(t *testing.T) {
	old := testScan(t0.AddDate(0, 0, -3))
	old.Hosts[0].Services = append(old.Hosts[0].Services, result.Service{Port: 8080, Proto: "tcp", State: "open",
		Tech: []result.Tech{{Name: "x", Confidence: 1, Tags: []string{"staging"}}}})
	// A newer version keeps the identity.
	cur := testScan(t0)
	cur.Hosts[0].Services[1].Tech[0].Version = "1.19.0"

	sel := Selection{}
	obs, err := Observe(sel, cur)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddHistory(obs, sel, old); err != nil {
		t.Fatal(err)
	}
	if len(obs) != 3 {
		t.Errorf("history must not add observations: %v", ids(obs))
	}
	for _, o := range obs {
		if !o.FirstSeen.Equal(old.FinishedAt) || !o.LastSeen.Equal(t0) {
			t.Errorf("%s: seen %v..%v", o.ID, o.FirstSeen, o.LastSeen)
		}
	}

	// Several current scans: newest evidence wins in any order.
	for _, scans := range [][]*result.Scan{{old, cur}, {cur, old}} {
		obs, _ := Observe(Selection{Names: []string{"outdated-component"}}, scans...)
		if len(obs) != 1 || obs[0].Version != "1.19.0" || !obs[0].FirstSeen.Equal(old.FinishedAt) {
			t.Errorf("merge: %+v", obs)
		}
	}
}

func TestAddFindings(t *testing.T) {
	obs, _ := Observe(Selection{Names: []string{"admin-panel"}}, testScan(t0))
	var fs []trigger.Finding
	for i := range 7 {
		f := testFinding()
		f.Time = t0.Add(-time.Duration(i) * time.Minute)
		fs = append(fs, f)
	}
	other := testFinding()
	other.Events = []sensor.Event{{Type: sensor.ServiceNew, IP: other.Target.IP, Port: 80, Proto: "tcp"}}
	AddFindings(obs, append(fs, other))
	ev := obs[0].Events
	if len(ev) != maxEvents || !ev[len(ev)-1].Time.Equal(t0) {
		t.Fatalf("want the latest %d events, oldest first: %+v", maxEvents, ev)
	}
	if ev[0].Text != "service_changed -> scanned" {
		t.Errorf("text %q", ev[0].Text)
	}
}

func TestOutdated(t *testing.T) {
	for _, tc := range []struct {
		tech, version string
		want          bool
	}{
		{"nginx", "1.18.0", true},
		{"nginx", "1.31.9", false},
		{"nginx", "", false},
		{"nginx", "1", false}, // minor unknown
		{"Apache httpd", "2.4.65", false},
		{"Apache httpd", "2.2.8", true},
		{"OpenSSH", "7.4p1 Debian 10+deb9u7", true},
		{"OpenSSH", "9.6p1 Ubuntu 3ubuntu13", false},
		{"OpenSSH", "10.3", false},
		{"PostgreSQL", "9.6.0 or later", false},
		{"PostgreSQL", "9.5.0 - 9.5.2", false},
		{"PostgreSQL", "9.5.25", true},
		{"MySQL", "5.x", false},
		{"PHP", "99999999999999999999999.1", false},
		{"Unknown", "0.1", false},
	} {
		if _, _, got := outdated(tc.tech, tc.version); got != tc.want {
			t.Errorf("outdated(%s, %q) = %v", tc.tech, tc.version, got)
		}
	}
}

// Our own nmap parser must read back what we wrote.
func TestNmapXMLRoundTrip(t *testing.T) {
	s := testScan(t0)
	s.Hosts[0].ExtraPorts = []result.ExtraPorts{{State: "closed", Count: 97}}
	s.Hosts[0].Services[1].ExtraInfo = `"<Ubuntu>" & co`
	s.Hosts = append(s.Hosts, result.Host{Address: "fd00::1", State: "up"})
	var buf bytes.Buffer
	if err := WriteNmapXML(&buf, s); err != nil {
		t.Fatal(err)
	}
	hosts, err := scan.ParseXML(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[1].Address != "fd00::1" {
		t.Fatalf("hosts: %+v", hosts)
	}
	h := hosts[0]
	if len(h.Services) != 3 || len(h.Hostnames) != 2 || h.ExtraPorts[0].Count != 97 {
		t.Fatalf("host: %+v", h)
	}
	got, want := h.Services[1], s.Hosts[0].Services[1]
	if got.Product != want.Product || got.ExtraInfo != want.ExtraInfo || got.Tunnel != "ssl" || got.CPE[0] != want.CPE[0] || got.State != "open" {
		t.Errorf("service: %+v", got)
	}
}
