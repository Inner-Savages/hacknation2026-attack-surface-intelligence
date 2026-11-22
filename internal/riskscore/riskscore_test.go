package riskscore

import "testing"

func TestScoreEmpty(t *testing.T) {
	out := Score(Input{})
	if out.Score != 0 || out.Grade != GradeLow || len(out.Factors) != 0 {
		t.Fatalf("empty input: %+v", out)
	}
}

func TestScoreCVE(t *testing.T) {
	out := Score(Input{MaxEPSS: 0.9, KEV: true, CVECount: 3})
	if len(out.Factors) != 1 || out.Factors[0].Name != "cve" {
		t.Fatalf("factors = %+v", out.Factors)
	}
	// 0.9*25 = 22.5 + 8 KEV = 30.5 (cap 33 does not bite).
	if out.Score != 30.5 {
		t.Fatalf("score = %v, want 30.5", out.Score)
	}
}

func TestScoreExposedDominates(t *testing.T) {
	plain := Score(Input{AdminPorts: []int{3389}})
	exposed := Score(Input{AdminPorts: []int{3389}, Exposed: true})
	if exposed.Score-plain.Score != 20 {
		t.Fatalf("exposure should add 20, got %v vs %v", exposed.Score, plain.Score)
	}
}

func TestScoreCapsAndGrade(t *testing.T) {
	// Everything at once must saturate at 100 and grade critical.
	out := Score(Input{
		MaxEPSS: 1, KEV: true, CVECount: 9,
		MaxModelScore: 1, OpenCases: 10, Unresolved: 5,
		NewServices: 10, AdminPorts: []int{22, 23, 3389, 5900, 5985},
		PlainHTTP: []int{80, 8080}, MissingTLS: []int{443, 8443},
		OddBanners: []string{"a", "b", "c", "d"},
		TLSCrit:    5, TLSHigh: 5, TLSWarn: 5,
		Exposed: true, ChangedWhileSilent: true,
		AlertClass: "kamera", Silent: true,
	})
	if out.Score != 100 {
		t.Fatalf("saturated score = %v, want 100", out.Score)
	}
	if out.Grade != GradeCritical {
		t.Fatalf("grade = %q, want krytyczne", out.Grade)
	}
	// Factors sorted by points, descending.
	for i := 1; i < len(out.Factors); i++ {
		if out.Factors[i].Points > out.Factors[i-1].Points {
			t.Fatalf("factors not sorted: %+v", out.Factors)
		}
	}
}

func TestScoreGrades(t *testing.T) {
	cases := []struct {
		in    Input
		grade string
	}{
		{Input{Silent: true, NewServices: 1}, GradeLow},                             // 2+4=6
		{Input{NewServices: 3, AdminPorts: []int{3389}, Silent: true}, GradeMedium}, // 12+6+2=20
		{Input{MaxEPSS: 0.9, MaxModelScore: 0.9, OpenCases: 3}, GradeHigh},          // 22.5+18+6=46.5
		{Input{Exposed: true, ChangedWhileSilent: true, MaxEPSS: 0.95, KEV: true, MaxModelScore: 0.95}, GradeCritical},
	}
	for _, tc := range cases {
		out := Score(tc.in)
		if out.Grade != tc.grade {
			t.Errorf("input %+v: grade = %q (score %v), want %q", tc.in, out.Grade, out.Score, tc.grade)
		}
	}
}

func TestScoreZeroValueSignalsIgnored(t *testing.T) {
	out := Score(Input{AlertClass: "serwer"})
	if len(out.Factors) != 0 {
		t.Fatalf("expected-class asset adds nothing: %+v", out.Factors)
	}
}
