package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCPEFor(t *testing.T) {
	cpe, ok := CPEFor("WordPress", "6.4")
	if !ok {
		t.Fatal("expected ok for a versioned product")
	}
	want := "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*"
	if cpe != want {
		t.Fatalf("CPE = %q, want %q", cpe, want)
	}

	cpe, ok = CPEFor("Apache httpd", "2.4.49")
	if !ok {
		t.Fatal("expected ok for Apache httpd")
	}
	want = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	if cpe != want {
		t.Fatalf("CPE = %q, want %q", cpe, want)
	}
}

func TestCPEForNoVersion(t *testing.T) {
	if _, ok := CPEFor("WordPress", ""); ok {
		t.Fatal("a versionless lookup must report false — it would be noise")
	}
	if _, ok := CPEFor("WordPress", "   "); ok {
		t.Fatal("whitespace-only version must report false")
	}
}

func TestCPEForFallbackNormalization(t *testing.T) {
	cpe, ok := CPEFor("Some Custom-App", "1.2.3")
	if !ok {
		t.Fatal("expected ok")
	}
	want := "cpe:2.3:a:some_custom_app:some_custom_app:1.2.3:*:*:*:*:*:*:*"
	if cpe != want {
		t.Fatalf("fallback CPE = %q, want %q", cpe, want)
	}
}

func TestParseBanner(t *testing.T) {
	cases := []struct {
		banner, product, version string
	}{
		{"SSH-2.0-OpenSSH_9.6", "OpenSSH", "9.6"},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "OpenSSH", "8.9"},
		{"Apache/2.4.49 (Ubuntu)", "Apache httpd", "2.4.49"},
		{"nginx/1.24.0", "nginx", "1.24.0"},
		{"Microsoft-IIS/10.0", "Microsoft IIS", "10.0"},
		{"redis_version:7.2.4", "Redis", "7.2.4"},
	}
	for _, c := range cases {
		product, version, ok := ParseBanner(c.banner)
		if !ok {
			t.Fatalf("ParseBanner(%q) not recognized", c.banner)
		}
		if product != c.product || version != c.version {
			t.Fatalf("ParseBanner(%q) = (%q, %q), want (%q, %q)", c.banner, product, version, c.product, c.version)
		}
	}
}

func TestParseBannerNoise(t *testing.T) {
	for _, banner := range []string{"", "   ", "220 some random ftp greeting", "HTTP/1.1 200 OK"} {
		if _, _, ok := ParseBanner(banner); ok {
			t.Fatalf("ParseBanner(%q) should report false", banner)
		}
	}
}

const testNVDResponse = `{
  "vulnerabilities": [
    {"cve": {"id": "CVE-2021-41773", "descriptions": [{"lang": "en", "value": "path traversal in Apache httpd 2.4.49"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}},
    {"cve": {"id": "CVE-2021-42013", "descriptions": [{"lang": "en", "value": "RCE in Apache httpd 2.4.49 and 2.4.50"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}
  ]
}`

const testEPSSResponse = `{
  "data": [
    {"cve": "CVE-2021-41773", "epss": "0.94000", "percentile": "0.99000"},
    {"cve": "CVE-2021-42013", "epss": "0.97000", "percentile": "0.99500"}
  ]
}`

const testKEVResponse = `{"vulnerabilities": [{"cveID": "CVE-2021-42013"}]}`

// newTestClient points a Client at the three fake upstreams.
func newTestClient(t *testing.T, nvdHits *int64) (*Client, func()) {
	t.Helper()
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cpeName") == "" {
			t.Errorf("NVD query without cpeName")
		}
		if nvdHits != nil {
			atomic.AddInt64(nvdHits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testNVDResponse)
	}))
	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testEPSSResponse)
	}))
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testKEVResponse)
	}))
	c, err := NewClient(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.NVDBase, c.EPSSBase, c.KEVURL = nvd.URL, epss.URL, kev.URL
	c.NVDDelay = 0
	return c, func() { nvd.Close(); epss.Close(); kev.Close() }
}

func TestLookupRanksByEPSS(t *testing.T) {
	c, cleanup := newTestClient(t, nil)
	defer cleanup()

	vulns, err := c.Lookup(context.Background(), "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2", len(vulns))
	}
	// Higher EPSS first, KEV flagged, CVSS from the v3.1 metric.
	if vulns[0].CVE != "CVE-2021-42013" {
		t.Fatalf("first vuln = %s, want CVE-2021-42013 (EPSS 0.97 > 0.94)", vulns[0].CVE)
	}
	if vulns[0].EPSS != 0.97 || vulns[0].CVSS != 9.8 {
		t.Fatalf("first vuln scores = EPSS %v CVSS %v, want 0.97 / 9.8", vulns[0].EPSS, vulns[0].CVSS)
	}
	if !vulns[0].KEV {
		t.Fatal("CVE-2021-42013 must be flagged as KEV")
	}
	if vulns[1].KEV {
		t.Fatal("CVE-2021-41773 must not be flagged as KEV")
	}
	if vulns[1].Summary == "" {
		t.Fatal("summary should come from the English NVD description")
	}
}

func TestLookupUsesCache(t *testing.T) {
	var nvdHits int64
	c, cleanup := newTestClient(t, &nvdHits)
	defer cleanup()
	cpe := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

	if _, err := c.Lookup(context.Background(), cpe); err != nil {
		t.Fatalf("first Lookup: %v", err)
	}
	if got := atomic.LoadInt64(&nvdHits); got != 1 {
		t.Fatalf("NVD hit %d times on first lookup, want 1", got)
	}
	if _, err := c.Lookup(context.Background(), cpe); err != nil {
		t.Fatalf("second Lookup: %v", err)
	}
	if got := atomic.LoadInt64(&nvdHits); got != 1 {
		t.Fatalf("NVD hit %d times after cached lookup, want still 1", got)
	}
}

func TestEnrichBanner(t *testing.T) {
	c, cleanup := newTestClient(t, nil)
	defer cleanup()

	vulns, err := c.EnrichBanner(context.Background(), "Apache/2.4.49 (Ubuntu)")
	if err != nil {
		t.Fatalf("EnrichBanner: %v", err)
	}
	if len(vulns) == 0 {
		t.Fatal("banner lookup should return the fixture CVEs")
	}

	// A banner without a recognizable version is a safe no-op.
	vulns, err = c.EnrichBanner(context.Background(), "220 welcome")
	if err != nil {
		t.Fatalf("EnrichBanner(noise): %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("noise banner returned %d vulns, want 0", len(vulns))
	}
}

func TestEnrichTechRequiresVersion(t *testing.T) {
	c, cleanup := newTestClient(t, nil)
	defer cleanup()
	vulns, err := c.EnrichTech(context.Background(), "WordPress", "")
	if err != nil {
		t.Fatalf("EnrichTech: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("versionless tech returned %d vulns, want 0", len(vulns))
	}
}
