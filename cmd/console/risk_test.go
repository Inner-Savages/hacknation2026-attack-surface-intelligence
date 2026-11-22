package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/riskscore"
	"github.com/Inner-Savages/silence-on-the-wire/internal/tlspolicy"
)

// newRiskTestServer builds a console with ground truth, TLS monitor and
// exposure check wired.
func newRiskTestServer(t *testing.T) *server {
	t.Helper()
	s := newTestAssetServer(t)
	dir := t.TempDir()
	tlsMon, err := newTLSMonitor(dir, s.store, s.feed, s.settings, s.gt)
	if err != nil {
		t.Fatal(err)
	}
	s.tlsMon = tlsMon
	exp, err := newExposureCheck(dir, s.store, s.feed, s.settings, s.gt)
	if err != nil {
		t.Fatal(err)
	}
	s.exposure = exp
	return s
}

func vulnEnvelope(epss float64, kev bool) []byte {
	env, _ := json.Marshal(map[string]interface{}{
		"event": map[string]interface{}{
			"time": time.Now().UTC().Format(time.RFC3339), "type": "ground_truth_change", "ip": "10.0.0.50",
			"vulns": []map[string]interface{}{{"cve": "CVE-2026-0001", "epss": epss, "kev": kev}},
		},
		"event_id": "gt-test-1", "sensor_id": "edge-1", "forward": true,
	})
	return env
}

func TestBuildRiskInputsAggregatesAllSignals(t *testing.T) {
	s := newRiskTestServer(t)
	now := time.Now()

	// Host: admin port, plain HTTP, TLS candidate without a certificate,
	// odd banner, silent-drift verdict, camera class.
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.50", New: "44:19:b6:10:20:30"}, "edge-1", now)
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.50", Port: 3389, Proto: "tcp"}, "edge-1", now)
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.50", Port: 80, Proto: "tcp"}, "edge-1", now)
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.50", Port: 443, Proto: "tcp"}, "edge-1", now)
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.50", Port: 22, Proto: "tcp"}, "edge-1", now)
	h := s.gt.registry.hosts["10.0.0.50"]
	h.Services["22/tcp"].Banner = "Apache httpd 2.4" // SSH port, web banner: odd
	h.CheckVerdict = verdictChanged
	h.Class = "kamera"

	// A case with a KEV-listed, high-EPSS vulnerability and a top model
	// score.
	s.store.AddEscalation(&Case{
		EventID: "gt-test-1", Received: now, Envelope: vulnEnvelope(0.91, true),
		SensorID: "edge-1", EventType: "ground_truth_change", EventTime: now.Format(time.RFC3339),
		Source: "10.0.0.50", Target: "—", Score: 0.93, Reason: "test", Status: StatusNew,
	})

	// Open critical TLS finding and external exposure on the same host.
	s.tlsMon.state.Issues = []*tlsIssue{{IP: "10.0.0.50", Port: 443, Severity: tlspolicy.SevCrit, Kind: "tls_expired"}}
	s.exposure.state.Findings = []ExposureFinding{{Kind: findExposedInternal, MatchIP: "10.0.0.50", FirstSeen: now}}

	inputs := s.buildRiskInputs(now)
	in, ok := inputs["10.0.0.50"]
	if !ok {
		t.Fatal("host missing from risk inputs")
	}
	if in.MaxEPSS != 0.91 || !in.KEV || in.CVECount != 1 {
		t.Errorf("CVE signals = epss %v kev %v n %d", in.MaxEPSS, in.KEV, in.CVECount)
	}
	if in.MaxModelScore != 0.93 || in.OpenCases != 1 {
		t.Errorf("model signals = score %v open %d", in.MaxModelScore, in.OpenCases)
	}
	if in.NewServices != 4 {
		t.Errorf("new services = %d, want 4", in.NewServices)
	}
	if len(in.AdminPorts) != 1 || in.AdminPorts[0] != 3389 {
		t.Errorf("admin ports = %v", in.AdminPorts)
	}
	if len(in.PlainHTTP) != 1 || len(in.MissingTLS) != 1 {
		t.Errorf("http/tls surface = %v / %v", in.PlainHTTP, in.MissingTLS)
	}
	if len(in.OddBanners) != 1 {
		t.Errorf("odd banners = %v", in.OddBanners)
	}
	if in.TLSCrit != 1 || !in.Exposed || !in.ChangedWhileSilent || in.AlertClass != "kamera" {
		t.Errorf("correlations = crit %d exposed %v drift %v class %q", in.TLSCrit, in.Exposed, in.ChangedWhileSilent, in.AlertClass)
	}

	out := riskscore.Score(in)
	if out.Grade != riskscore.GradeCritical {
		t.Errorf("grade = %q (score %v), want krytyczne", out.Grade, out.Score)
	}
}

func TestRiskAPIOrdersByScore(t *testing.T) {
	s := newRiskTestServer(t)
	now := time.Now()

	// Quiet host: just exists.
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.60", New: "b8:27:eb:12:34:56"}, "edge-1", now)
	// Loud host: RDP open plus a high-scoring open case.
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.61", New: "00:0c:29:11:22:33"}, "edge-1", now)
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.61", Port: 3389, Proto: "tcp"}, "edge-1", now)
	s.store.AddEscalation(&Case{
		EventID: "demo-risk-1", Received: now, Envelope: json.RawMessage(`{"event":{"type":"service_new","ip":"10.0.0.61"}}`),
		SensorID: "edge-1", EventType: "service_new", EventTime: now.Format(time.RFC3339),
		Source: "10.0.0.61", Target: ":3389", Score: 0.95, Reason: "test", Status: StatusNew,
	})

	req := httptest.NewRequest("GET", "/api/risk", nil)
	rec := httptest.NewRecorder()
	s.risk(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Hosts []hostRisk `json:"hosts"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 || len(body.Hosts) != 2 {
		t.Fatalf("total = %d, hosts = %d", body.Total, len(body.Hosts))
	}
	if body.Hosts[0].IP != "10.0.0.61" || body.Hosts[0].Score <= body.Hosts[1].Score {
		t.Fatalf("ordering wrong: %+v", body.Hosts)
	}
	top := body.Hosts[0]
	var names []string
	for _, f := range top.Factors {
		names = append(names, f.Name)
	}
	want := map[string]bool{"model": true, "open_cases": true, "admin_ports": true, "new_services": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Fatalf("missing factors %v in %+v", want, top.Factors)
	}

	// The limit parameter bounds the listing but not the total.
	req = httptest.NewRequest("GET", "/api/risk?limit=1", nil)
	rec = httptest.NewRecorder()
	s.risk(rec, req)
	body = struct {
		Hosts []hostRisk `json:"hosts"`
		Total int        `json:"total"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Hosts) != 1 || body.Total != 2 {
		t.Fatalf("limit: hosts = %d, total = %d", len(body.Hosts), body.Total)
	}
}

func TestEnvelopeVulns(t *testing.T) {
	epss, kev, n := envelopeVulns(vulnEnvelope(0.42, false))
	if epss != 0.42 || kev || n != 1 {
		t.Fatalf("got epss %v kev %v n %d", epss, kev, n)
	}
	epss, kev, n = envelopeVulns(json.RawMessage(`{"event":{"type":"host_new"}}`))
	if epss != 0 || kev || n != 0 {
		t.Fatalf("envelope without vulns: got %v %v %d", epss, kev, n)
	}
}
