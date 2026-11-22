// Package riskscore aggregates every signal the console already collects
// about a host — CVE/EPSS hits, the ML cascade's case scores, newly seen
// services, administrative ports, missing TLS, odd banners, open TLS
// findings, external exposure, ground-truth drift and the asset class —
// into one 0..100 risk score with an auditable factor breakdown. It is
// the "what do I fix first" view: a pure function over the signals, so
// the ranking is explainable point by point.
package riskscore

import (
	"fmt"
	"sort"
	"strings"
)

// Input is everything known about one host that moves its risk score.
type Input struct {
	// Known vulnerabilities tied to the host (from case envelopes).
	MaxEPSS  float64 // highest EPSS across findings, 0..1
	KEV      bool    // any finding on the CISA KEV list
	CVECount int
	// ML cascade / triage state.
	MaxModelScore float64 // highest model score across the host's cases
	OpenCases     int     // cases in status nowe / do weryfikacji
	Unresolved    int     // cases the models could not resolve
	// Service surface.
	NewServices int      // services first seen within the last 48 h
	AdminPorts  []int    // management/admin ports currently open
	PlainHTTP   []int    // cleartext HTTP services
	MissingTLS  []int    // TLS-candidate ports without a certificate record
	OddBanners  []string // banners that do not match their well-known port
	// Open TLS findings, by severity.
	TLSCrit int
	TLSHigh int
	TLSWarn int
	// Correlations.
	Exposed            bool   // internal service confirmed visible from the internet
	ChangedWhileSilent bool   // ground truth saw drift under passive silence
	AlertClass         string // asset class that alerts on sight: kamera, drukarka, telefon, iot
	Silent             bool   // host is currently passively silent
}

// Factor is one scored contribution, kept so the ranking stays explainable.
type Factor struct {
	Name   string  `json:"name"`   // stable key, e.g. "cve", "admin_ports"
	Points float64 `json:"points"` // contribution to the total
	Detail string  `json:"detail"` // human-readable justification (Polish, like the console)
}

// Output is the aggregate: 0..100 plus a coarse grade and the breakdown.
type Output struct {
	Score   float64  `json:"score"` // 0..100
	Grade   string   `json:"grade"` // krytyczne / wysokie / średnie / niskie
	Factors []Factor `json:"factors"`
}

// Grades: 70+ krytyczne, 40+ wysokie, 15+ średnie, below niskie.
const (
	GradeCritical = "krytyczne"
	GradeHigh     = "wysokie"
	GradeMedium   = "średnie"
	GradeLow      = "niskie"
)

// Score folds the input into the aggregate. Every component is capped, so a
// single noisy signal cannot dominate the ranking; the total caps at 100.
func Score(in Input) Output {
	var factors []Factor
	add := func(name string, points float64, detail string) {
		if points <= 0 {
			return
		}
		factors = append(factors, Factor{Name: name, Points: round1(points), Detail: detail})
	}
	capAt := func(v, max float64) float64 {
		if v > max {
			return max
		}
		return v
	}

	// Known vulnerabilities: EPSS is the exploitation probability, KEV is
	// actively exploited — the single strongest "fix first" signal.
	if in.MaxEPSS > 0 {
		pts := capAt(in.MaxEPSS*25, 25)
		if in.KEV {
			pts = capAt(pts+8, 33)
		}
		detail := fmt.Sprintf("%s (EPSS %.2f)", pluralCVE(in.CVECount), in.MaxEPSS)
		if in.KEV {
			detail += " — na liście CISA KEV, aktywnie eksploitowane"
		}
		add("cve", pts, detail)
	}

	// The ML cascade already judged this host's events; open and unresolved
	// cases keep the pressure on.
	if in.MaxModelScore > 0 {
		pts := capAt(in.MaxModelScore*20, 20)
		add("model", pts, fmt.Sprintf("najwyższa ocena kaskady modeli %.2f", in.MaxModelScore))
	}
	if in.OpenCases > 0 {
		add("open_cases", capAt(float64(in.OpenCases)*2, 6), fmt.Sprintf("%d otwartych spraw", in.OpenCases))
	}
	if in.Unresolved > 0 {
		add("unresolved", capAt(float64(in.Unresolved)*3, 6), fmt.Sprintf("%d spraw nierozstrzygniętych przez modele", in.Unresolved))
	}

	// Attack surface: what the host exposes and how fresh it is.
	if in.NewServices > 0 {
		add("new_services", capAt(float64(in.NewServices)*4, 12), fmt.Sprintf("%d nowych usług w ostatnich 48 h", in.NewServices))
	}
	if len(in.AdminPorts) > 0 {
		add("admin_ports", capAt(float64(len(in.AdminPorts))*6, 18), "otwarte porty administracyjne: "+joinPorts(in.AdminPorts))
	}
	if len(in.MissingTLS) > 0 {
		add("missing_tls", capAt(float64(len(in.MissingTLS))*4, 8), "usługi TLS bez potwierdzonego certyfikatu: "+joinPorts(in.MissingTLS))
	}
	if len(in.PlainHTTP) > 0 {
		add("plain_http", capAt(float64(len(in.PlainHTTP))*2, 6), "nieszyfrowane HTTP na portach: "+joinPorts(in.PlainHTTP))
	}
	if len(in.OddBanners) > 0 {
		add("odd_banners", capAt(float64(len(in.OddBanners))*3, 9), fmt.Sprintf("%d bannerów niepasujących do portu", len(in.OddBanners)))
	}

	// Certificate hygiene.
	if in.TLSCrit > 0 {
		add("tls_crit", capAt(float64(in.TLSCrit)*10, 20), fmt.Sprintf("%d krytycznych znalezień TLS (wygasły / ≤ 7 dni)", in.TLSCrit))
	}
	if in.TLSHigh > 0 {
		add("tls_high", capAt(float64(in.TLSHigh)*6, 12), fmt.Sprintf("%d poważnych znalezień TLS", in.TLSHigh))
	}
	if in.TLSWarn > 0 {
		add("tls_warn", capAt(float64(in.TLSWarn)*2, 6), fmt.Sprintf("%d ostrzeżeń TLS", in.TLSWarn))
	}

	// Correlations: exposure and silent drift are the multipliers of
	// everything above.
	if in.Exposed {
		add("exposed", 20, "usługa hosta potwierdzona jako widoczna z internetu (Shodan/Censys)")
	}
	if in.ChangedWhileSilent {
		add("silent_drift", 15, "skan kontrolny wykrył zmianę u hosta cichego pasywnie (silent_stealth)")
	}
	if in.AlertClass != "" {
		pts := map[string]float64{"kamera": 8, "drukarka": 4, "telefon": 4, "iot": 4}[in.AlertClass]
		add("asset_class", pts, "urządzenie klasy "+in.AlertClass+" w sieci (pasywna klasyfikacja)")
	}
	if in.Silent {
		add("silent", 2, "host aktualnie cichy pasywnie — stan niepewny")
	}

	sort.Slice(factors, func(i, j int) bool {
		if factors[i].Points != factors[j].Points {
			return factors[i].Points > factors[j].Points
		}
		return factors[i].Name < factors[j].Name
	})

	total := 0.0
	for _, f := range factors {
		total += f.Points
	}
	if total > 100 {
		total = 100
	}
	out := Output{Score: round1(total), Grade: GradeLow, Factors: factors}
	switch {
	case total >= 70:
		out.Grade = GradeCritical
	case total >= 40:
		out.Grade = GradeHigh
	case total >= 15:
		out.Grade = GradeMedium
	}
	return out
}

func pluralCVE(n int) string {
	switch {
	case n == 1:
		return "1 znana podatność"
	case n > 1 && n < 5:
		return fmt.Sprintf("%d znane podatności", n)
	default:
		return fmt.Sprintf("%d znanych podatności", n)
	}
}

func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(s, ", ")
}

func round1(v float64) float64 {
	if v < 0 {
		return 0
	}
	return float64(int(v*10+0.5)) / 10
}
