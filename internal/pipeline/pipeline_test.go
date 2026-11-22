package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
)

// End to end without nmap: the fake reports 127.0.0.1 with the test
// server's port open, then the real prober and signatures take over.
func TestRunScansProbesAndFingerprints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.31.9")
		w.Write([]byte(`<title>Blog</title><meta name="generator" content="WordPress 6.4.2">`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	t.Setenv("FAKE_NMAP_PORT", u.Port())

	engine, err := fingerprint.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	var tg scan.Targets
	_ = tg.Add("127.0.0.1")
	var logged int
	cfg := Config{
		Scanner: scan.Scanner{Options: scan.Options{Binary: "../scan/testdata/fake-nmap.sh"}},
		Engine:  engine,
		Logf:    func(string, ...any) { logged++ },
	}
	res, err := cfg.Run(context.Background(), &tg)
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Hosts[0].Services[0]
	if svc.HTTP == nil || svc.HTTP.Title != "Blog" {
		t.Fatalf("not probed: %+v", svc.HTTP)
	}
	var wp bool
	for _, tech := range svc.Tech {
		if tech.Name == "WordPress" && tech.Version == "6.4.2" {
			wp = true
		}
	}
	if !wp || logged != 2 {
		t.Fatalf("tech %+v, log lines %d", svc.Tech, logged)
	}
	if up, open := Counts(res); up != 1 || open != 1 {
		t.Fatalf("counts %d %d", up, open)
	}

	cfg.SkipProbe, cfg.SkipFingerprint = true, true
	res, _ = cfg.Run(context.Background(), &tg)
	if res.Hosts[0].Services[0].HTTP != nil || res.Hosts[0].Services[0].Tech != nil {
		t.Fatal("probe and fingerprint must be skippable")
	}
}
