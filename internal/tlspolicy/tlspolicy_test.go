package tlspolicy

import (
	"testing"
	"time"
)

func TestExpiryThresholds(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		daysLeft  int
		wantKind  string
		wantTh    int
		wantSev   string
		wantCount int
	}{
		{45, "", 0, "", 0},
		{31, "", 0, "", 0},
		{29, KindExpiring, 30, SevWarn, 1},
		{14, KindExpiring, 14, SevHigh, 1},
		{6, KindExpiring, 7, SevCrit, 1},
		{0, KindExpiring, 7, SevCrit, 1},
		{-1, KindExpired, 0, SevCrit, 1},
	}
	for _, c := range cases {
		rec := Record{
			Subject: "CN=app.internal", Issuer: "CN=Internal CA",
			NotAfter: now.Add(time.Duration(c.daysLeft) * 24 * time.Hour),
			Version:  "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256",
		}
		findings := Evaluate(rec, nil, now)
		if len(findings) != c.wantCount {
			t.Fatalf("%d days left: got %d findings (%+v), want %d", c.daysLeft, len(findings), findings, c.wantCount)
		}
		if c.wantCount == 0 {
			continue
		}
		f := findings[0]
		if f.Kind != c.wantKind || f.Threshold != c.wantTh || f.Severity != c.wantSev {
			t.Fatalf("%d days left: finding = %+v, want kind %s th %d sev %s", c.daysLeft, f, c.wantKind, c.wantTh, c.wantSev)
		}
	}
}

func TestSelfSignedFinding(t *testing.T) {
	now := time.Now()
	rec := Record{
		Subject: "CN=nas.local", Issuer: "CN=nas.local", SelfSigned: true,
		NotAfter: now.Add(90 * 24 * time.Hour), Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256",
	}
	findings := Evaluate(rec, nil, now)
	if len(findings) != 1 || findings[0].Kind != KindSelfSigned || findings[0].Severity != SevWarn {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCAChange(t *testing.T) {
	now := time.Now()
	rec := Record{
		Subject: "CN=app.internal", Issuer: "CN=Let's Encrypt R11",
		NotAfter: now.Add(90 * 24 * time.Hour), Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256",
	}
	// No previous observation: no CA finding.
	if findings := Evaluate(rec, nil, now); len(findings) != 0 {
		t.Fatalf("first sight must not raise CA change: %+v", findings)
	}
	// Same issuer: quiet.
	same := &Record{Issuer: "CN=Let's Encrypt R11"}
	if findings := Evaluate(rec, same, now); len(findings) != 0 {
		t.Fatalf("same issuer must be quiet: %+v", findings)
	}
	// Different issuer: high finding.
	other := &Record{Issuer: "CN=Internal CA"}
	findings := Evaluate(rec, other, now)
	if len(findings) != 1 || findings[0].Kind != KindCAChange || findings[0].Severity != SevHigh {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestWeakCrypto(t *testing.T) {
	cases := []struct {
		version, cipher string
		wantWeak        bool
	}{
		{"TLS 1.3", "TLS_AES_128_GCM_SHA256", false},
		{"TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false},
		{"TLS 1.1", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", true}, // old version
		{"TLS 1.0", "TLS_RSA_WITH_AES_128_CBC_SHA", true},          // both old and weak
		{"TLS 1.2", "TLS_RSA_WITH_RC4_128_SHA", true},              // RC4
		{"TLS 1.2", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", true},         // 3DES (CBC check must not win)
		{"TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", true},    // CBC
		{"TLS 1.2", "TLS_RSA_WITH_AES_128_GCM_SHA256", true},       // no forward secrecy
		{"TLS 1.2", "TLS_NULL_WITH_NULL_NULL", true},               // NULL
	}
	for _, c := range cases {
		weak, why := WeakCrypto(c.version, c.cipher)
		if weak != c.wantWeak {
			t.Fatalf("WeakCrypto(%q, %q) = %v (%s), want %v", c.version, c.cipher, weak, why, c.wantWeak)
		}
	}
}
