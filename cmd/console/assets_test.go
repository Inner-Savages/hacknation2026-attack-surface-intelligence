package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestAssetServer builds a console with ground truth wired, ready to
// consume passive log lines.
func newTestAssetServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	feed := newLiveFeed(100)
	cfg, err := openSettings(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gt, err := newGroundTruth(dir, store, feed, cfg, "tester")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := openAuth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &server{store: store, token: "tok", feed: feed, settings: cfg, gt: gt, auth: auth}
}

func TestRegistryCapturesMAC(t *testing.T) {
	r := &hostRegistry{hosts: map[string]*HostRecord{}}
	r.Observe(sensorLog{Type: "host_new", IP: "10.0.0.5", New: "44:19:b6:10:20:30"}, "edge-1", time.Now())
	h := r.hosts["10.0.0.5"]
	if h == nil || h.MAC != "44:19:b6:10:20:30" {
		t.Fatalf("host_new must record the MAC, got %+v", h)
	}
}

func TestAssetClassificationEscalatesNewCamera(t *testing.T) {
	s := newTestAssetServer(t)
	now := time.Now()

	// A new host with a Hikvision OUI appears; then it exposes RTSP.
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.7", New: "44:19:b6:10:20:30"}, "edge-1", now)
	s.updateAssetClass("10.0.0.7")
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.7", Port: 554, Proto: "tcp"}, "edge-1", now.Add(time.Second))
	s.updateAssetClass("10.0.0.7")

	h := s.gt.registry.hosts["10.0.0.7"]
	if h.Class != "kamera" {
		t.Fatalf("class = %q, want kamera (reasons %v)", h.Class, h.ClassReasons)
	}
	if h.ClassVendor != "Hikvision" {
		t.Fatalf("vendor = %q, want Hikvision", h.ClassVendor)
	}
	if h.ClassConfidence < 0.9 {
		t.Fatalf("OUI + RTSP should be >= 0.9, got %v", h.ClassConfidence)
	}
	if len(h.ClassReasons) < 2 {
		t.Fatalf("expected at least OUI and port evidence, got %v", h.ClassReasons)
	}
	if h.ClassifiedAt == nil {
		t.Fatal("classification timestamp must be set")
	}

	// The classification is a topology event on the attack map.
	found := false
	for _, ev := range s.gt.registry.timeline(time.Time{}, time.Time{}) {
		if ev.Type == "asset_classified" && ev.IP == "10.0.0.7" {
			found = true
			if !strings.Contains(ev.Detail, "kamera") || !strings.Contains(ev.Detail, "Hikvision") {
				t.Fatalf("timeline detail = %q", ev.Detail)
			}
		}
	}
	if !found {
		t.Fatal("timeline must contain asset_classified for the new camera")
	}

	// One case per host, score 0.8, auditable reason.
	cases := s.store.ListCases()
	if len(cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(cases))
	}
	c := cases[0]
	if c.EventID != assetEventID("10.0.0.7") || c.EventType != "asset_new" || c.Source != "10.0.0.7" {
		t.Fatalf("case = %+v", c)
	}
	if c.Score != 0.8 {
		t.Fatalf("camera case score = %v, want 0.8", c.Score)
	}
	if !strings.Contains(c.Reason, "kamera") || !strings.Contains(c.Reason, "Hikvision") || !strings.Contains(c.Reason, "44:19:b6") {
		t.Fatalf("reason must carry class, vendor and MAC: %s", c.Reason)
	}

	// Repeated evidence never duplicates the case (stable event ID).
	s.updateAssetClass("10.0.0.7")
	if cases := s.store.ListCases(); len(cases) != 1 {
		t.Fatalf("reclassification must not duplicate the case, got %d", len(cases))
	}
}

func TestAssetClassificationIgnoresExpectedClasses(t *testing.T) {
	s := newTestAssetServer(t)
	now := time.Now()

	// A VMware guest with SSH: a server, expected in the network — no case.
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.9", New: "00:0c:29:11:22:33"}, "edge-2", now)
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.9", Port: 22, Proto: "tcp"}, "edge-2", now)
	s.updateAssetClass("10.0.0.9")

	h := s.gt.registry.hosts["10.0.0.9"]
	if h.Class != "serwer" {
		t.Fatalf("class = %q, want serwer", h.Class)
	}
	if cases := s.store.ListCases(); len(cases) != 0 {
		t.Fatalf("server must not escalate, got %d cases", len(cases))
	}
}

func TestAssetReclassificationIsNoted(t *testing.T) {
	s := newTestAssetServer(t)
	now := time.Now()

	// First we only see a printer port; later the OUI says camera — the
	// reclassification is recorded on the timeline.
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.11", New: "02:42:aa:bb:cc:dd"}, "edge-3", now)
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.11", Port: 9100, Proto: "tcp"}, "edge-3", now)
	s.updateAssetClass("10.0.0.11")
	if h := s.gt.registry.hosts["10.0.0.11"]; h.Class != "drukarka" {
		t.Fatalf("class = %q, want drukarka", h.Class)
	}

	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.11", New: "3c:e3:8b:00:11:22"}, "edge-3", now.Add(time.Minute))
	s.gt.registry.Observe(sensorLog{Type: "service_new", IP: "10.0.0.11", Port: 554, Proto: "tcp"}, "edge-3", now.Add(time.Minute))
	s.updateAssetClass("10.0.0.11")

	h := s.gt.registry.hosts["10.0.0.11"]
	if h.Class != "kamera" {
		t.Fatalf("reclassified class = %q, want kamera", h.Class)
	}
	var reEv *topologyEvent
	for i, ev := range s.gt.registry.events {
		if ev.Type == "asset_classified" && strings.Contains(ev.Detail, "reklasyfikacja") {
			reEv = &s.gt.registry.events[i]
		}
	}
	if reEv == nil {
		t.Fatal("timeline must note the drukarka → kamera reclassification")
	}
	if !strings.Contains(reEv.Detail, "drukarka") || !strings.Contains(reEv.Detail, "kamera") {
		t.Fatalf("reclassification detail = %q", reEv.Detail)
	}
}

func TestAssetsAPI(t *testing.T) {
	s := newTestAssetServer(t)
	now := time.Now()
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.20", New: "44:19:b6:10:20:30"}, "edge-1", now)
	s.updateAssetClass("10.0.0.20")
	s.gt.registry.Observe(sensorLog{Type: "host_new", IP: "10.0.0.21", New: "b8:27:eb:12:34:56"}, "edge-1", now)
	s.updateAssetClass("10.0.0.21")

	req := httptest.NewRequest("GET", "/api/assets", nil)
	rec := httptest.NewRecorder()
	s.assets(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Hosts   []*HostRecord  `json:"hosts"`
		Classes map[string]int `json:"classes"`
		Total   int            `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 || len(body.Hosts) != 2 {
		t.Fatalf("total = %d, hosts = %d", body.Total, len(body.Hosts))
	}
	if body.Classes["kamera"] != 1 || body.Classes["iot"] != 1 {
		t.Fatalf("classes = %v", body.Classes)
	}

	// Class filter narrows the listing but keeps full counters.
	req = httptest.NewRequest("GET", "/api/assets?class=kamera", nil)
	rec = httptest.NewRecorder()
	s.assets(rec, req)
	body = struct {
		Hosts   []*HostRecord  `json:"hosts"`
		Classes map[string]int `json:"classes"`
		Total   int            `json:"total"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Hosts) != 1 || body.Hosts[0].IP != "10.0.0.20" {
		t.Fatalf("filtered hosts = %+v", body.Hosts)
	}
	if body.Classes["iot"] != 1 {
		t.Fatalf("counters must stay global, classes = %v", body.Classes)
	}
}

func TestIntakeLogsTriggersClassification(t *testing.T) {
	s := newTestAssetServer(t)
	body := strings.NewReader(
		`{"time":"2026-11-22T10:00:00Z","type":"host_new","ip":"10.0.0.30","new":"00:0b:82:aa:bb:cc","source":"passive"}` + "\n" +
			`{"time":"2026-11-22T10:00:01Z","type":"service_new","ip":"10.0.0.30","port":5060,"proto":"tcp","source":"passive"}` + "\n")
	req := httptest.NewRequest("POST", "/logs?sensor=edge-7", body)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.intakeLogs(rec, req)
	if rec.Code != 202 {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	h := s.gt.registry.hosts["10.0.0.30"]
	if h == nil || h.Class != "telefon" {
		t.Fatalf("class = %+v, want telefon", h)
	}
	cases := s.store.ListCases()
	if len(cases) != 1 || cases[0].EventType != "asset_new" {
		t.Fatalf("expected one asset_new case, got %+v", cases)
	}
}

// RBAC: asset inventory is read-only; every built-in role (viewer included)
// reads it, anonymous callers get 401, and no write method exists.
func TestAssetEndpointsRBAC(t *testing.T) {
	s, _, adminTok := testServer(t)
	h := s.routes()
	viewer := userWithRole(t, s, "vera", "viewer")
	for _, tok := range []string{viewer, adminTok} {
		if w := call(t, h, "GET", "/api/assets", "", tok); w.Code != 200 {
			t.Errorf("GET /api/assets = %d, want 200", w.Code)
		}
	}
	if w := call(t, h, "GET", "/api/assets", "", ""); w.Code != 401 {
		t.Errorf("anonymous GET /api/assets = %d, want 401", w.Code)
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if w := call(t, h, m, "/api/assets", `{}`, viewer); w.Code < 400 || w.Code == 200 {
			t.Errorf("viewer %s /api/assets = %d, want error", m, w.Code)
		}
	}
}
