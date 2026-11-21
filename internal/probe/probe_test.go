package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Reference values from Python's mmh3 (pip install mmh3).
func TestMurmur3MatchesPythonMmh3(t *testing.T) {
	for in, want := range map[string]int32{
		"": 0, "hello": 613153351, "foo": -156908512, "abc": -1277324294,
		"The quick brown fox jumps over the lazy dog": 776992547,
	} {
		if got := murmur3([]byte(in), 0); got != want {
			t.Errorf("murmur3(%q) = %d, want %d", in, got, want)
		}
	}
}

// mmh3.hash(base64.encodebytes(bytes(range(256))*3)) in Python.
func TestFaviconHashMatchesShodanFormula(t *testing.T) {
	icon := make([]byte, 0, 768)
	for i := 0; i < 3; i++ {
		for b := 0; b < 256; b++ {
			icon = append(icon, byte(b))
		}
	}
	if got := FaviconHash(icon); got != 1836528006 {
		t.Fatalf("FaviconHash = %d, want 1836528006", got)
	}
}

func targetFor(t *testing.T, srv *httptest.Server) Target {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return Target{Host: u.Hostname(), Addr: u.Hostname(), Port: port, Scheme: u.Scheme}
}

func TestProbeHTTPPage(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/wp/", http.StatusFound)
		case "/wp/":
			ua = r.UserAgent()
			w.Header().Set("Server", "nginx/1.31.9")
			w.Header().Set("X-Powered-By", "PHP/8.1.2")
			http.SetCookie(w, &http.Cookie{Name: "wordpress_test_cookie", Value: "secret-value", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			w.Write([]byte(`<html><head><title>  Blog &amp; news
				</title><link rel="icon" href="/img/fav.png"></head><body>hi</body></html>`))
		case "/img/fav.png":
			w.Write([]byte("ICON"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := (&Prober{Timeout: 2 * time.Second}).Probe(context.Background(), targetFor(t, srv))
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	if r.Status != 200 || r.Title != "Blog & news" || !strings.HasSuffix(r.FinalURL, "/wp/") {
		t.Fatalf("status %d title %q final %q", r.Status, r.Title, r.FinalURL)
	}
	if len(r.Redirects) != 1 || r.Redirects[0].Status != 302 || r.Redirects[0].Location != "/wp/" {
		t.Fatalf("redirects: %+v", r.Redirects)
	}
	if got := r.Headers["server"]; len(got) != 1 || got[0] != "nginx/1.31.9" {
		t.Errorf("server header: %v", got)
	}
	if _, ok := r.Headers["set-cookie"]; ok {
		t.Error("set-cookie values must not be stored")
	}
	if len(r.Cookies) != 1 || r.Cookies[0].Name != "wordpress_test_cookie" || !r.Cookies[0].HttpOnly || r.Cookies[0].SameSite != "Lax" {
		t.Errorf("cookies: %+v", r.Cookies)
	}
	if r.Favicon == nil || !strings.HasSuffix(r.Favicon.URL, "/img/fav.png") || r.Favicon.Hash != FaviconHash([]byte("ICON")) {
		t.Errorf("favicon: %+v", r.Favicon)
	}
	if r.TLS != nil || r.BodySize == 0 || len(r.BodySHA256) != 64 || len(r.Body) != r.BodySize {
		t.Errorf("tls %v size %d sha %q", r.TLS, r.BodySize, r.BodySHA256)
	}
	if !strings.HasPrefix(ua, "silence-on-the-wire/") {
		t.Errorf("user agent %q", ua)
	}
}

func TestProbeDoesNotFollowOffHostRedirects(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "https://evil.example/", http.StatusMovedPermanently)
	}))
	defer srv.Close()
	r := (&Prober{Timeout: 2 * time.Second}).Probe(context.Background(), targetFor(t, srv))
	if hits != 1 || r.Status != 301 || len(r.Redirects) != 1 || r.Redirects[0].Location != "https://evil.example/" {
		t.Fatalf("hits %d result %+v", hits, r)
	}
	if r.Favicon != nil {
		t.Error("no favicon fetch after an off-host redirect")
	}
}

func TestProbeRedirectLoopIsBounded(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()
	r := (&Prober{Timeout: 2 * time.Second}).Probe(context.Background(), targetFor(t, srv))
	if len(r.Redirects) != maxRedirects || hits > maxRedirects+2 { // +1 last hop, +1 favicon attempt
		t.Fatalf("redirects %d hits %d", len(r.Redirects), hits)
	}
}

func TestProbeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<title>secure</title>"))
	}))
	defer srv.Close()
	r := (&Prober{Timeout: 2 * time.Second}).Probe(context.Background(), targetFor(t, srv))
	if r.Error != "" || r.Title != "secure" || r.TLS == nil {
		t.Fatalf("result %+v", r)
	}
	if !strings.HasPrefix(r.TLS.Version, "TLS 1.") || r.TLS.Subject == "" || len(r.TLS.SHA256) != 64 || r.TLS.Expired {
		t.Errorf("tls: %+v", r.TLS)
	}
	if len(r.TLS.IPs) == 0 || r.TLS.NotAfter.IsZero() {
		t.Errorf("tls names/validity: %+v", r.TLS)
	}
}

func TestProbeDialsAddrButSendsHostname(t *testing.T) {
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { host = r.Host }))
	defer srv.Close()
	tg := targetFor(t, srv)
	tg.Host = "web-cms.lab" // not resolvable: the connection must go to Addr
	r := (&Prober{Timeout: 2 * time.Second}).Probe(context.Background(), tg)
	if r.Error != "" || host != net.JoinHostPort("web-cms.lab", strconv.Itoa(tg.Port)) {
		t.Fatalf("host header %q, err %q", host, r.Error)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	r := (&Prober{Timeout: time.Second}).Probe(context.Background(), Target{Host: "127.0.0.1", Addr: "127.0.0.1", Port: port, Scheme: "http"})
	if r.Error == "" || !strings.Contains(r.Error, "refused") || strings.Contains(r.Error, "Get \"") {
		t.Fatalf("error %q", r.Error)
	}
}

func TestTitleEdgeCases(t *testing.T) {
	for body, want := range map[string]string{
		"":                               "",
		"<TITLE>Admin Panel</TITLE>":     "Admin Panel",
		"<title lang=en>a\n\n b</title>": "a b",
		"<title>" + strings.Repeat("x", 300) + "</title>": strings.Repeat("x", 200),
		"<title>unterminated":                             "",
	} {
		if got := title([]byte(body)); got != want {
			t.Errorf("title(%.30q) = %q, want %q", body, got, want)
		}
	}
}

func TestSchemes(t *testing.T) {
	svc := func(name, tunnel string, port int) result.Service {
		return result.Service{Port: port, Proto: "tcp", State: "open", Name: name, Tunnel: tunnel}
	}
	cases := []struct {
		s    result.Service
		want string
	}{
		{svc("http", "", 8787), "http"},
		{svc("http-proxy", "", 8080), "http"},
		{svc("http", "ssl", 443), "https"},
		{svc("https", "", 8443), "https"},
		{svc("tcpwrapped", "", 8888), "http,https"},
		{svc("tcpwrapped", "", 5432), ""},
		{svc("ssh", "", 22), ""},
		{result.Service{Port: 80, Proto: "tcp", State: "closed", Name: "http"}, ""},
	}
	for _, c := range cases {
		if got := strings.Join(Schemes(c.s), ","); got != c.want {
			t.Errorf("%s/%s:%d -> %q, want %q", c.s.Name, c.s.Tunnel, c.s.Port, got, c.want)
		}
	}
}

func TestProbeScanFillsWebServicesOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<title>ok</title>")) }))
	defer srv.Close()
	tg := targetFor(t, srv)
	s := &result.Scan{Hosts: []result.Host{{Address: tg.Addr, State: "up", Services: []result.Service{
		{Port: tg.Port, Proto: "tcp", State: "open", Name: "http"},
		{Port: 22, Proto: "tcp", State: "open", Name: "ssh"},
	}}}}
	if n := (&Prober{Timeout: 2 * time.Second}).ProbeScan(context.Background(), s, 4); n != 1 {
		t.Fatalf("probed %d services", n)
	}
	if h := s.Hosts[0].Services[0].HTTP; h == nil || h.Title != "ok" {
		t.Fatalf("http: %+v", h)
	}
	if s.Hosts[0].Services[1].HTTP != nil {
		t.Fatal("ssh must not be probed")
	}
}

func TestFetchPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-login.php" {
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Write([]byte(`<title>Log In</title><form id="loginform">`))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	tg := targetFor(t, srv)
	h := &result.Host{Address: tg.Addr}
	s := &result.Service{Port: tg.Port, HTTP: &result.HTTP{URL: srv.URL + "/"}}
	p := &Prober{Timeout: 2 * time.Second}

	page, err := p.FetchPath(context.Background(), h, s, "/wp-login.php")
	if err != nil || page.Status != 200 || page.Title != "Log In" || page.Headers["x-frame-options"][0] != "SAMEORIGIN" {
		t.Fatalf("page %+v, err %v", page, err)
	}
	page, err = p.FetchPath(context.Background(), h, s, "/admin/")
	if err != nil || page.Status != 302 {
		t.Fatalf("redirects must not be followed: %+v, %v", page, err)
	}
	if _, err := p.FetchPath(context.Background(), h, s, "//evil.example/x"); err == nil {
		t.Fatal("a path must not leave the service")
	}
	if _, err := p.FetchPath(context.Background(), h, &result.Service{Port: tg.Port}, "/"); err == nil {
		t.Fatal("unprobed service must be refused")
	}
}
