package exposure

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testShodanHost = `{
  "ip_str": "203.0.113.10",
  "org": "Example ISP",
  "last_update": "2026-11-20T10:00:00.000000",
  "hostnames": ["fw.example.com"],
  "tags": ["vpn"],
  "vulns": ["CVE-2021-42013"],
  "data": [
    {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24.0", "data": "HTTP/1.1 200 OK",
     "http": {"favicon": {"hash": -247388890, "location": "/favicon.ico"}}},
    {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "9.6", "data": "SSH-2.0-OpenSSH_9.6"},
    {"port": 8080, "transport": "tcp", "data": "mystery listener"}
  ]
}`

const testShodanSearch = `{
  "total": 2,
  "matches": [
    {"ip_str": "203.0.113.10", "port": 443},
    {"ip_str": "198.51.100.77", "port": 8443}
  ]
}`

func testShodanServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "test-key" {
			t.Errorf("missing API key on %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/tools/myip":
			fmt.Fprint(w, `"203.0.113.10"`)
		case r.URL.Path == "/shodan/host/203.0.113.10":
			fmt.Fprint(w, testShodanHost)
		case r.URL.Path == "/shodan/search":
			if r.URL.Query().Get("query") != "favicon:-247388890" {
				t.Errorf("unexpected query: %s", r.URL.Query().Get("query"))
			}
			fmt.Fprint(w, testShodanSearch)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
}

func TestShodanHost(t *testing.T) {
	srv := testShodanServer(t)
	defer srv.Close()
	s := &Shodan{APIKey: "test-key", Base: srv.URL}

	view, err := s.Host(context.Background(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if view.Org != "Example ISP" || len(view.Services) != 3 {
		t.Fatalf("view = %+v", view)
	}
	if len(view.Vulns) != 1 || view.Vulns[0] != "CVE-2021-42013" {
		t.Fatalf("vulns = %v", view.Vulns)
	}
	nginx := view.Services[0]
	if nginx.Key() != "443/tcp" || nginx.Product != "nginx" || nginx.Version != "1.24.0" {
		t.Fatalf("nginx service = %+v", nginx)
	}
	if nginx.FaviconMMH3 == nil || *nginx.FaviconMMH3 != -247388890 {
		t.Fatalf("favicon hash lost: %+v", nginx)
	}
	// A service without a favicon must not invent one.
	if view.Services[1].FaviconMMH3 != nil {
		t.Fatal("ssh service should have no favicon hash")
	}
}

func TestShodanMyIPAndFaviconSearch(t *testing.T) {
	srv := testShodanServer(t)
	defer srv.Close()
	s := &Shodan{APIKey: "test-key", Base: srv.URL}

	ip, err := s.MyIP(context.Background())
	if err != nil || ip != "203.0.113.10" {
		t.Fatalf("MyIP = %q, %v", ip, err)
	}
	addrs, err := s.FaviconSearch(context.Background(), -247388890)
	if err != nil {
		t.Fatalf("FaviconSearch: %v", err)
	}
	if len(addrs) != 2 || addrs[0] != "203.0.113.10:443" || addrs[1] != "198.51.100.77:8443" {
		t.Fatalf("addrs = %v", addrs)
	}
}

const testCensysHost = `{
  "result": {
    "services": [
      {"port": 443, "service_name": "HTTP", "software": [{"product": "nginx", "version": "1.24.0"}]},
      {"port": 23, "service_name": "TELNET", "banner": "login:"}
    ],
    "autonomous_system": {"name": "Example ASN"},
    "last_updated_at": "2026-11-20T10:00:00.000Z"
  }
}`

func TestCensysHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "test-id" || secret != "test-secret" {
			t.Errorf("bad basic auth: %v %v %v", id, secret, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testCensysHost)
	}))
	defer srv.Close()
	c := &Censys{ID: "test-id", Secret: "test-secret", Base: srv.URL}

	view, err := c.Host(context.Background(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if view.Source != "censys" || view.Org != "Example ASN" || len(view.Services) != 2 {
		t.Fatalf("view = %+v", view)
	}
	if view.Services[0].Product != "nginx" || view.Services[0].Version != "1.24.0" {
		t.Fatalf("nginx = %+v", view.Services[0])
	}
	// Without software entries the service name is the product fallback.
	if view.Services[1].Product != "telnet" {
		t.Fatalf("telnet fallback = %+v", view.Services[1])
	}
	if _, err := c.FaviconSearch(context.Background(), 123); err == nil {
		t.Fatal("censys favicon search must report unsupported")
	}
}

func TestNewProvider(t *testing.T) {
	if _, err := NewProvider("shodan", ""); err == nil {
		t.Fatal("shodan without a key must fail")
	}
	if _, err := NewProvider("", "key"); err != nil {
		t.Fatalf("default provider: %v", err)
	}
	if _, err := NewProvider("censys", "only-id"); err == nil {
		t.Fatal("censys key must require id:secret")
	}
	if _, err := NewProvider("censys", "id:secret"); err != nil {
		t.Fatalf("censys provider: %v", err)
	}
	if _, err := NewProvider("bing", "key"); err == nil {
		t.Fatal("unknown provider must fail")
	}
}
