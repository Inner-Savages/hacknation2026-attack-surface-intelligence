package fingerprint

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

func engine(t *testing.T, extra ...string) *Engine {
	t.Helper()
	e, err := NewEngine(extra...)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func web(headers map[string][]string, title, body string, cookies ...string) *result.Service {
	h := &result.HTTP{Status: 200, Headers: headers, Title: title, Body: []byte(body)}
	for _, c := range cookies {
		h.Cookies = append(h.Cookies, result.Cookie{Name: c})
	}
	return &result.Service{Port: 80, Proto: "tcp", State: "open", Name: "http", HTTP: h}
}

func find(techs []result.Tech, name string) *result.Tech {
	for i := range techs {
		if techs[i].Name == name {
			return &techs[i]
		}
	}
	return nil
}

func TestBuiltinSignaturesLoad(t *testing.T) {
	e := engine(t)
	if len(e.Signatures()) < 30 {
		t.Fatalf("only %d signatures", len(e.Signatures()))
	}
	want := []string{"/admin/", "/dashboard/", "/login", "/login.php", "/wp-login.php"}
	if got := e.Paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths %v, want %v", got, want)
	}
}

func TestWordPressFromLabFakeWithVersion(t *testing.T) {
	svc := web(map[string][]string{
		"server":       {"nginx/1.31.9"},
		"x-powered-by": {"PHP/8.1.2"},
		"link":         {`<http://web-cms/wp-json/>; rel="https://api.w.org/"`},
	}, "Blog Katedry", `<meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/themes/x.css">`, "wordpress_test_cookie")
	techs := engine(t).Identify(svc, nil)

	wp := find(techs, "WordPress")
	if wp == nil || wp.Version != "6.4.2" || wp.Category != "cms" || wp.Confidence < 0.99 || len(wp.Evidence) != 4 {
		t.Fatalf("wordpress: %+v", wp)
	}
	if n := find(techs, "nginx"); n == nil || n.Version != "1.31.9" {
		t.Errorf("nginx: %+v", n)
	}
	if p := find(techs, "PHP"); p == nil || p.Version != "8.1.2" {
		t.Errorf("php: %+v", p)
	}
	if techs[0].Confidence < techs[len(techs)-1].Confidence {
		t.Error("techs must be sorted by confidence")
	}
}

func TestNmapOnlyServices(t *testing.T) {
	e := engine(t)
	ssh := &result.Service{Port: 2223, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "10.3"}
	if o := find(e.Identify(ssh, nil), "OpenSSH"); o == nil || o.Version != "10.3" || o.Evidence[0] != "nmap product OpenSSH" {
		t.Fatalf("openssh: %+v", o)
	}
	amqp := &result.Service{Port: 5673, Proto: "tcp", State: "open", Name: "amqp", Product: "Advanced Message Queue Protocol"}
	if a := find(e.Identify(amqp, nil), "AMQP broker"); a == nil {
		t.Fatal("amqp not recognized")
	}
}

func TestStagingNeedsMoreThanWeakEvidence(t *testing.T) {
	e := engine(t)
	weak := web(map[string][]string{"x-robots-tag": {"noindex"}}, "Shop", "")
	if s := find(e.Identify(weak, nil), "Staging / test environment"); s != nil {
		t.Fatalf("noindex alone must stay below the threshold: %+v", s)
	}
	strong := web(map[string][]string{"x-env": {"staging"}, "x-robots-tag": {"noindex"}}, "STAGING - MyApp", "")
	s := find(e.Identify(strong, nil), "Staging / test environment")
	if s == nil || !reflect.DeepEqual(s.Tags, []string{"staging"}) || s.Confidence < 0.97 || len(s.Evidence) != 3 {
		t.Fatalf("staging: %+v", s)
	}
}

func TestPathEvidence(t *testing.T) {
	e := engine(t)
	svc := web(nil, "MyApp", "")
	pages := map[string]*result.Page{
		"/admin/":    {Path: "/admin/", Status: 200, Title: "Admin Panel", Body: []byte("<h1>Administration</h1>")},
		"/login":     {Path: "/login", Status: 404},
		"/login.php": {Path: "/login.php", Status: 200, Title: "Login :: Damn Vulnerable Web Application (DVWA)"},
	}
	techs := e.Identify(svc, pages)
	if a := find(techs, "Admin panel"); a == nil || a.Evidence[0] != "path /admin/ 200" {
		t.Errorf("admin panel: %+v", a)
	}
	if d := find(techs, "DVWA"); d == nil || d.Tags[0] != "intentionally-vulnerable" {
		t.Errorf("dvwa: %+v", d)
	}
	if l := find(techs, "Login page"); l != nil {
		t.Errorf("404 /login must not count: %+v", l)
	}
}

func TestCustomSignatureFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "ours.yaml")
	os.WriteFile(good, []byte(`
- name: Internal HR portal
  category: app
  tags: [internal]
  match:
    - {title: 'HR Portal', weight: 0.7}
    - {header: x-app, value: 'hr-([0-9.]+)', version: 1, weight: 0.8}
`), 0o600)
	e := engine(t, good)
	tech := find(e.Identify(web(map[string][]string{"x-app": {"hr-2.1"}}, "HR Portal - login", ""), nil), "Internal HR portal")
	if tech == nil || tech.Version != "2.1" || tech.Confidence != 0.94 {
		t.Fatalf("custom: %+v", tech)
	}

	for name, body := range map[string]string{
		"unknown field": "- name: X\n  match:\n    - {titel: 'x'}\n",
		"bad regex":     "- name: X\n  match:\n    - {title: '('}\n",
		"two subjects":  "- name: X\n  match:\n    - {cookie: 'a', favicon: 1}\n",
		"no subject":    "- name: X\n  match:\n    - {weight: 0.5}\n",
		"no matches":    "- name: X\n",
		"no name":       "- match:\n    - {title: 'x'}\n",
		"bad weight":    "- name: X\n  match:\n    - {title: 'x', weight: 2}\n",
		"relative path": "- name: X\n  match:\n    - {path: 'admin'}\n",
	} {
		f := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yaml")
		os.WriteFile(f, []byte(body), 0o600)
		if _, err := NewEngine(f); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

type fakeFetcher struct {
	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeFetcher) FetchPath(_ context.Context, h *result.Host, s *result.Service, path string) (*result.Page, error) {
	f.mu.Lock()
	f.calls[path]++
	f.mu.Unlock()
	if path == "/wp-login.php" {
		return &result.Page{Path: path, Status: 200, Body: []byte(`<form name="loginform" id="loginform">`)}, nil
	}
	return &result.Page{Path: path, Status: 404}, nil
}

func TestRunFetchesPathsOnlyForWebServices(t *testing.T) {
	s := &result.Scan{Hosts: []result.Host{{Address: "10.0.0.1", State: "up", Services: []result.Service{
		*web(nil, "", ""),
		{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6"},
		{Port: 8080, Proto: "tcp", State: "closed", Name: "http-proxy"},
	}}}}
	f := &fakeFetcher{calls: map[string]int{}}
	engine(t).Run(context.Background(), s, f, 4)

	if len(f.calls) != 6 || f.calls["/wp-login.php"] != 1 { // 5 signature paths + 1 not-found baseline
		t.Fatalf("fetches: %v", f.calls)
	}
	svcs := s.Hosts[0].Services
	if wp := find(svcs[0].Tech, "WordPress"); wp == nil || wp.Evidence[0] != "path /wp-login.php 200" {
		t.Errorf("wordpress via path: %+v", svcs[0].Tech)
	}
	if find(svcs[1].Tech, "OpenSSH") == nil || svcs[2].Tech != nil {
		t.Errorf("ssh %+v, closed %+v", svcs[1].Tech, svcs[2].Tech)
	}
}

// httpbin's page has <span class="version"> 0.9.2: a version extractor
// alone must never be enough to claim a product.
func TestVersionOnlyEvidenceIsNotEnough(t *testing.T) {
	svc := web(map[string][]string{"server": {"gunicorn/19.9.0"}}, "httpbin.org", `<h2 class="title">httpbin.org <small><pre class="version">0.9.2</pre></small></h2>`)
	techs := engine(t).Identify(svc, nil)
	if a := find(techs, "Adminer"); a != nil {
		t.Fatalf("false positive: %+v", a)
	}
	if find(techs, "httpbin") == nil {
		t.Fatal("httpbin not recognized")
	}
	adminer := web(nil, "Login - Adminer", `<span class="version">4.8.1</span>`)
	if a := find(engine(t).Identify(adminer, nil), "Adminer"); a == nil || a.Version != "4.8.1" {
		t.Fatalf("adminer with title: %+v", a)
	}
}

// catchAll answers every path with the same login page, like Adminer.
type catchAll struct{}

func (catchAll) FetchPath(_ context.Context, _ *result.Host, _ *result.Service, path string) (*result.Page, error) {
	body := `<title>Login - Adminer</title><form><input type="password" name="auth[password]"></form><a href="` + path + `">`
	return &result.Page{Path: path, Status: 200, Title: "Login - Adminer", Body: []byte(body)}, nil
}

func TestCatchAllPathsAreNotEvidence(t *testing.T) {
	s := &result.Scan{Hosts: []result.Host{{Address: "127.0.0.1", State: "up", Services: []result.Service{
		*web(nil, "Login - Adminer", `<span class="version">4.8.1</span><input type="password">`),
	}}}}
	engine(t).Run(context.Background(), s, catchAll{}, 2)
	techs := s.Hosts[0].Services[0].Tech
	for _, tech := range techs {
		for _, ev := range tech.Evidence {
			if strings.HasPrefix(ev, "path ") {
				t.Errorf("%s: path evidence from a catch-all app: %v", tech.Name, tech.Evidence)
			}
		}
	}
	if find(techs, "Adminer") == nil {
		t.Fatal("adminer must still be recognized from the main page")
	}
}

func TestSoftNotFound(t *testing.T) {
	base := &result.Page{Status: 200, Title: "App", Body: make([]byte, 1000)}
	for _, c := range []struct {
		page *result.Page
		want bool
	}{
		{&result.Page{Status: 200, Title: "App", Body: make([]byte, 1100)}, true},
		{&result.Page{Status: 200, Title: "App", Body: make([]byte, 2000)}, false},
		{&result.Page{Status: 200, Title: "Admin", Body: make([]byte, 1000)}, false},
		{&result.Page{Status: 302, Title: "App", Body: make([]byte, 1000)}, false},
	} {
		if got := SoftNotFound(base, c.page); got != c.want {
			t.Errorf("%+v: %v, want %v", c.page.Title, got, c.want)
		}
	}
	if SoftNotFound(&result.Page{Status: 404}, base) || SoftNotFound(nil, base) {
		t.Error("a real 404 baseline never hides pages")
	}
}

func TestDVWATitleIsNotAStagingEnvironment(t *testing.T) {
	svc := web(nil, "Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*", "")
	if s := find(engine(t).Identify(svc, nil), "Staging / test environment"); s != nil {
		t.Fatalf("false positive: %+v", s)
	}
}

func TestAdminerVersionFromAssetLinks(t *testing.T) {
	svc := web(nil, "Login - Adminer", `<link rel="stylesheet" href="?file=default.css&amp;version=5.3.0+9afc53aa">`)
	if a := find(engine(t).Identify(svc, nil), "Adminer"); a == nil || a.Version != "5.3.0" {
		t.Fatalf("adminer: %+v", a)
	}
}

// Facts observed on the CBI AGH "modern" stack.
func TestModernStackSignatures(t *testing.T) {
	e := engine(t)
	npm := web(map[string][]string{"server": {"openresty"}}, "Default Site", "<h1>Congratulations!</h1> Nginx Proxy Manager")
	techs := e.Identify(npm, nil)
	for _, name := range []string{"OpenResty", "Nginx Proxy Manager", "Default web server page"} {
		if find(techs, name) == nil {
			t.Errorf("NPM :80: %s not recognized in %+v", name, techs)
		}
	}
	pma := web(map[string][]string{"server": {"Apache/2.4.71"}}, "phpMyAdmin", `<link href="./themes/pmahomme/css/theme.css?v=5.2.3">`, "phpMyAdmin")
	if p := find(e.Identify(pma, nil), "phpMyAdmin"); p == nil || p.Version != "5.2.3" {
		t.Errorf("phpMyAdmin: %+v", p)
	}
	// ?v= alone must never claim phpMyAdmin.
	if p := find(e.Identify(web(nil, "Shop", `<script src="app.js?v=1.2.3">`), nil), "phpMyAdmin"); p != nil {
		t.Errorf("false positive: %+v", p)
	}
}
