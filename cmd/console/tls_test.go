package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// directDial ignores the address and always reaches the test TLS server —
// probeTLS only needs "a connection that will do a handshake".
func directDial(addr string) dialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", addr)
	}
}

func TestProbeTLSCapturesCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	rec := probeTLS(context.Background(), "10.0.0.9", 443, directDial(srv.Listener.Addr().String()), 2*time.Second)
	if rec == nil {
		t.Fatal("probeTLS returned nil for a live TLS server")
	}
	if rec.Subject == "" || rec.Issuer == "" {
		t.Fatalf("subject/issuer missing: %+v", rec)
	}
	if !rec.SelfSigned {
		t.Fatal("httptest certificate must be detected as self-signed")
	}
	if len(rec.SHA256) != 64 || rec.NotAfter.IsZero() {
		t.Fatalf("fingerprint/validity: %+v", rec)
	}
	if !strings.HasPrefix(rec.Version, "TLS 1.") || rec.Cipher == "" {
		t.Fatalf("handshake params: %+v", rec)
	}

	// A plain-text port yields no record.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	if rec := probeTLS(context.Background(), "10.0.0.9", 80, directDial(plain.Listener.Addr().String()), 500*time.Millisecond); rec != nil {
		t.Fatalf("plain HTTP must not produce a TLS record: %+v", rec)
	}
}

// seedTLSHost injects a host with one certificate into the registry.
func seedTLSHost(gt *groundTruth, ip string, rec *TLSRecord) {
	gt.registry.mu.Lock()
	defer gt.registry.mu.Unlock()
	gt.registry.hosts[ip] = &HostRecord{
		IP: ip, SensorID: "edge-1",
		FirstSeen: time.Now(), LastSeen: time.Now(),
		TLS: map[string]*TLSRecord{"443/tcp": rec},
	}
}

func newTestTLSMonitor(t *testing.T) (*tlsMonitor, *groundTruth, *Store) {
	t.Helper()
	gt, store := newTestGroundTruth(t, fakeDial(map[string]string{}))
	m, err := newTLSMonitor(t.TempDir(), store, newLiveFeed(100), gt.settings, gt)
	if err != nil {
		t.Fatal(err)
	}
	return m, gt, store
}

func TestTLSRunEscalatesExpiringAndTightens(t *testing.T) {
	m, gt, store := newTestTLSMonitor(t)
	now := time.Now()
	rec := &TLSRecord{
		Subject: "CN=app.internal", Issuer: "CN=Internal CA",
		NotAfter: now.Add(20 * 24 * time.Hour), SHA256: strings.Repeat("a", 64),
		Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", CheckedAt: now,
	}
	seedTLSHost(gt, "10.0.0.44", rec)

	// 20 days left -> threshold 30, warn, one case.
	m.run("test")
	cases := store.ListCases()
	if len(cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(cases))
	}
	c := cases[0]
	if c.EventType != "tls" || c.Source != "10.0.0.44" || c.Score != 0.5 {
		t.Fatalf("case = %+v", c)
	}
	if !strings.Contains(c.Reason, "wygasa za") || !strings.Contains(c.Reason, "próg 30") {
		t.Fatalf("reason = %s", c.Reason)
	}

	// Same cert, same threshold: no re-escalation.
	m.run("test")
	if cases := store.ListCases(); len(cases) != 1 {
		t.Fatalf("repeat run must not re-escalate, got %d cases", len(cases))
	}

	// Time passed: 10 days left -> threshold 14 tightens, new escalation.
	rec.NotAfter = now.Add(10 * 24 * time.Hour)
	m.run("test")
	if cases := store.ListCases(); len(cases) != 2 {
		t.Fatalf("tightened threshold must escalate, got %d cases", len(cases))
	}
	// ListCases is newest-first: the tightened escalation is the first one.
	if !strings.Contains(store.ListCases()[0].Reason, "próg 14") {
		t.Fatalf("tightened case reason = %s", store.ListCases()[0].Reason)
	}

	// The timeline shows the findings.
	var tlsEvents int
	for _, ev := range gt.registry.timeline(time.Time{}, time.Time{}) {
		if ev.Type == "tls_finding" {
			tlsEvents++
		}
	}
	if tlsEvents != 2 {
		t.Fatalf("expected 2 tls_finding timeline events, got %d", tlsEvents)
	}
}

func TestTLSRunDetectsCAChangeAndSelfSigned(t *testing.T) {
	m, gt, store := newTestTLSMonitor(t)
	now := time.Now()
	seedTLSHost(gt, "10.0.0.45", &TLSRecord{
		Subject: "CN=app.internal", Issuer: "CN=Internal CA",
		NotAfter: now.Add(200 * 24 * time.Hour), SHA256: strings.Repeat("b", 64),
		Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", CheckedAt: now,
	})
	m.run("test") // baseline: healthy cert, no findings
	if cases := store.ListCases(); len(cases) != 0 {
		t.Fatalf("healthy cert must not escalate, got %d cases", len(cases))
	}

	// The certificate is replaced: new fingerprint, a public CA now, and
	// suddenly weak crypto. Expect CA-change + weak-crypto cases.
	seedTLSHost(gt, "10.0.0.45", &TLSRecord{
		Subject: "CN=app.internal", Issuer: "CN=Let's Encrypt R11",
		NotAfter: now.Add(80 * 24 * time.Hour), SHA256: strings.Repeat("c", 64),
		Version: "TLS 1.0", Cipher: "TLS_RSA_WITH_RC4_128_SHA", CheckedAt: now,
	})
	m.run("test")
	cases := store.ListCases()
	if len(cases) != 2 {
		t.Fatalf("expected CA-change + weak-crypto cases, got %d: %v", len(cases), cases)
	}
	kinds := map[string]bool{}
	for _, c := range cases {
		var env struct {
			Event struct {
				Kind string `json:"kind"`
			} `json:"event"`
		}
		if err := json.Unmarshal(c.Envelope, &env); err != nil {
			t.Fatal(err)
		}
		kinds[env.Event.Kind] = true
	}
	if !kinds["tls_ca_change"] || !kinds["tls_weak"] {
		t.Fatalf("kinds = %v", kinds)
	}
}

func TestTLSMonitorStatePersists(t *testing.T) {
	gt, store := newTestGroundTruth(t, fakeDial(map[string]string{}))
	dir := t.TempDir()
	m, err := newTLSMonitor(dir, store, newLiveFeed(100), gt.settings, gt)
	if err != nil {
		t.Fatal(err)
	}
	seedTLSHost(gt, "10.0.0.46", &TLSRecord{
		Subject: "CN=nas.local", Issuer: "CN=nas.local", SelfSigned: true,
		NotAfter: time.Now().Add(90 * 24 * time.Hour), SHA256: strings.Repeat("d", 64),
		Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", CheckedAt: time.Now(),
	})
	m.run("test")
	if cases := store.ListCases(); len(cases) != 1 {
		t.Fatalf("self-signed must escalate once, got %d", len(cases))
	}

	// A fresh monitor over the same directory remembers: the restart does
	// not re-raise the finding.
	m2, err := newTLSMonitor(dir, store, newLiveFeed(100), gt.settings, gt)
	if err != nil {
		t.Fatal(err)
	}
	m2.run("test")
	if cases := store.ListCases(); len(cases) != 1 {
		t.Fatalf("restart must not re-escalate, got %d cases", len(cases))
	}
	if len(m2.state.Issues) != 1 {
		t.Fatalf("issues not persisted: %+v", m2.state.Issues)
	}
}

// RBAC: TLS findings are readable by every role, but only roles holding
// tls:run (editor, admin) may trigger a pass; viewer and analyst get 403.
func TestTLSEndpointsRBAC(t *testing.T) {
	s, _, adminTok := testServer(t)
	h := s.routes()
	viewer := userWithRole(t, s, "vera", "viewer")
	analyst := userWithRole(t, s, "anna", "analyst")
	editor := userWithRole(t, s, "edek", "editor")
	for _, tok := range []string{viewer, analyst, editor, adminTok} {
		if w := call(t, h, "GET", "/api/tls", "", tok); w.Code != 200 {
			t.Errorf("GET /api/tls = %d, want 200", w.Code)
		}
	}
	for name, tok := range map[string]string{"viewer": viewer, "analyst": analyst} {
		if w := call(t, h, "POST", "/api/tls/run", `{}`, tok); w.Code != 403 {
			t.Errorf("%s POST /api/tls/run = %d, want 403", name, w.Code)
		}
	}
	for name, tok := range map[string]string{"editor": editor, "admin": adminTok} {
		if w := call(t, h, "POST", "/api/tls/run", `{}`, tok); w.Code == 403 || w.Code == 401 {
			t.Errorf("%s POST /api/tls/run = %d, want allowed", name, w.Code)
		}
	}
}
