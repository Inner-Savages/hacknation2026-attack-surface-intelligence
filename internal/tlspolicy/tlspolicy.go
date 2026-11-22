// Package tlspolicy evaluates TLS certificate and handshake records
// collected by scans and turns them into findings: certificates expiring
// within 30/14/7 days, self-signed certificates, issuer (CA) changes and
// weak negotiated cryptography. It is deliberately pure — the console and
// the scanner feed it records and decide what to do with the findings.
package tlspolicy

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Severity buckets. Blockers fire once when the threshold is crossed, not
// on every scan — the console tracks which threshold was last reported.
const (
	SevInfo = "info"
	SevWarn = "warn" // 30 days, weak crypto, self-signed on a public service
	SevHigh = "high" // 14 days
	SevCrit = "crit" // 7 days, expired
)

// Finding kinds.
const (
	KindExpiring   = "tls_expiring"
	KindExpired    = "tls_expired"
	KindSelfSigned = "tls_self_signed"
	KindCAChange   = "tls_ca_change"
	KindWeakTLS    = "tls_weak"
)

// Record is the certificate state observed on one host:port. It mirrors
// what a TLS handshake (or the scanner's prober) can see.
type Record struct {
	Subject    string
	Issuer     string
	NotAfter   time.Time
	SelfSigned bool
	Version    string // negotiated TLS version, e.g. "TLS 1.2"
	Cipher     string // negotiated cipher suite name
}

// Finding is one policy violation tied to one host:port.
type Finding struct {
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	Threshold  int       `json:"threshold,omitempty"` // expiry bucket: 30/14/7
	Message    string    `json:"message"`
	DetectedAt time.Time `json:"detected_at"`
}

// ExpiryThresholds are the warning windows, longest first.
var ExpiryThresholds = []int{30, 14, 7}

// Evaluate checks one record and returns every current finding. now is
// injectable for tests. A nil previous record means "no CA-change check".
func Evaluate(rec Record, prev *Record, now time.Time) []Finding {
	var out []Finding

	if now.After(rec.NotAfter) {
		out = append(out, Finding{
			Kind: KindExpired, Severity: SevCrit, DetectedAt: now,
			Message: fmt.Sprintf("certyfikat wygasł %s (%s)",
				rec.NotAfter.Format("2006-01-02"), shortName(rec.Subject)),
		})
	} else {
		daysLeft := int(rec.NotAfter.Sub(now).Hours() / 24)
		// Tightest first: the reported threshold is the most urgent bucket
		// crossed, so the console can re-escalate 30 -> 14 -> 7.
		for i := len(ExpiryThresholds) - 1; i >= 0; i-- {
			th := ExpiryThresholds[i]
			if daysLeft <= th {
				sev := SevWarn
				if th <= 7 {
					sev = SevCrit
				} else if th <= 14 {
					sev = SevHigh
				}
				out = append(out, Finding{
					Kind: KindExpiring, Severity: sev, Threshold: th, DetectedAt: now,
					Message: fmt.Sprintf("certyfikat wygasa za %d dni (%s, próg %d dni)",
						daysLeft, rec.NotAfter.Format("2006-01-02"), th),
				})
				break // report only the tightest crossed threshold
			}
		}
	}

	if rec.SelfSigned {
		out = append(out, Finding{
			Kind: KindSelfSigned, Severity: SevWarn, DetectedAt: now,
			Message: fmt.Sprintf("certyfikat self-signed (%s wystawiony przez %s)",
				shortName(rec.Subject), shortName(rec.Issuer)),
		})
	}

	if prev != nil && prev.Issuer != "" && rec.Issuer != prev.Issuer {
		out = append(out, Finding{
			Kind: KindCAChange, Severity: SevHigh, DetectedAt: now,
			Message: fmt.Sprintf("zmiana wystawcy (CA): %q → %q",
				shortName(prev.Issuer), shortName(rec.Issuer)),
		})
	}

	if weak, why := WeakCrypto(rec.Version, rec.Cipher); weak {
		out = append(out, Finding{
			Kind: KindWeakTLS, Severity: SevWarn, DetectedAt: now,
			Message: "słaba kryptografia: " + why,
		})
	}
	return out
}

// WeakCrypto reports whether the negotiated parameters fall below a modern
// baseline: TLS 1.2 or newer and a forward-secret AEAD suite.
func WeakCrypto(version, cipher string) (bool, string) {
	switch strings.ToUpper(strings.ReplaceAll(version, " ", "")) {
	case "TLS1.3", "TLS1.2":
		// fine
	case "":
		// unknown — no judgement
	default:
		return true, fmt.Sprintf("przestarzała wersja %s (wymagane ≥ TLS 1.2)", version)
	}
	c := strings.ToUpper(cipher)
	switch {
	case strings.Contains(c, "RC4"):
		return true, "szyfr RC4 (złamany, RFC 7465)"
	case strings.Contains(c, "_DES_") || strings.Contains(c, "3DES"):
		return true, "szyfr 3DES/DES (Sweet32, wycofany przez NIST)"
	case strings.Contains(c, "_CBC_") && !strings.Contains(c, "GCM"):
		return true, fmt.Sprintf("szyfr %s w trybie CBC (podatny na oracle padding)", cipher)
	case strings.Contains(c, "RSA") && !strings.Contains(c, "ECDHE") && !strings.Contains(c, "DHE"):
		return true, fmt.Sprintf("szyfr %s bez forward secrecy", cipher)
	case strings.Contains(c, "NULL"):
		return true, "brak szyfrowania (NULL cipher)"
	}
	return false, ""
}

// IsSelfSigned mirrors the scanner's definition: subject == issuer and the
// signature verifies with the cert's own key.
func IsSelfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
}

// shortName keeps messages readable: the CN if present, else the full DN.
func shortName(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if cn, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
			return cn
		}
	}
	return dn
}
