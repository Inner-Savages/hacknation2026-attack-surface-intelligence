package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type triggerSink struct {
	mu     sync.Mutex
	events []map[string]any
	auth   []string
	fail   bool
}

func (t *triggerSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.auth = append(t.auth, r.Header.Get("Authorization"))
	if t.fail {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	var batch []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t.events = append(t.events, batch...)
	w.WriteHeader(http.StatusAccepted)
}

// newTestGate builds a gate whose models all answer with the given score.
func newTestGate(t *testing.T, early bool, modelScore float64, trigger string) *gateServer {
	t.Helper()
	p := testCascadePolicy(t, early)
	g, _ := testCascadeEngine(t, p, time.Second, func(name string, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testModelReply(p, name, modelScore)))
	})
	s, err := newGateServer(g, serveOptions{
		cascadeGateOptions: cascadeGateOptions{Sensor: "fallback", Outbox: t.TempDir()},
		TriggerURL:         trigger, Token: "tok", Queue: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const (
	evNew    = `{"time":"2026-11-22T10:00:00Z","type":"service_new","ip":"172.20.0.8","port":80,"proto":"tcp","source":"passive","sensor":"agh-lab"}`
	evSilent = `{"time":"2026-11-22T10:01:00Z","type":"service_silent","ip":"172.20.0.3","port":80,"proto":"tcp","source":"passive"}`
)

func postEvents(t *testing.T, h http.Handler, token string, events ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader("["+strings.Join(events, ",")+"]"))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func drain(s *gateServer, out *bytes.Buffer) {
	for len(s.queue) > 0 {
		s.process(<-s.queue, out)
	}
}

func TestServeAcceptsSensorBatchesWithAuthAndBackpressure(t *testing.T) {
	s := newTestGate(t, true, 1, "http://127.0.0.1:1/events")
	h := s.handler()
	if rec := postEvents(t, h, "", evNew); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := postEvents(t, h, "tok", "{broken"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body: %d", rec.Code)
	}
	if rec := postEvents(t, h, "tok", evNew, evNew); rec.Code != http.StatusAccepted || len(s.queue) != 2 {
		t.Fatalf("accept: %d, queued %d", rec.Code, len(s.queue))
	}
	// Queue of 4 holds 2 more; a batch of 3 is refused as a whole.
	if rec := postEvents(t, h, "tok", evNew, evNew, evNew); rec.Code != http.StatusServiceUnavailable || len(s.queue) != 2 {
		t.Fatalf("backpressure: %d, queued %d", rec.Code, len(s.queue))
	}
}

func TestServeForwardsEscalationsInSensorFormatWithScore(t *testing.T) {
	sink := &triggerSink{}
	trig := httptest.NewServer(sink)
	defer trig.Close()
	s := newTestGate(t, true, 1, trig.URL+"/events") // early escalation
	var decisions bytes.Buffer
	postEvents(t, s.handler(), "tok", evNew)
	drain(s, &decisions)
	if n, err := s.deliverOnce(cascadeCentralClient()); err != nil || n != 1 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	e := sink.events[0]
	if e["type"] != "service_new" || e["ip"] != "172.20.0.8" || e["sensor"] != "agh-lab" || e["port"].(float64) != 80 {
		t.Fatalf("original fields lost: %v", e)
	}
	if _, ok := e["score"].(float64); !ok || e["reason"] == "" || e["event_id"] == "" {
		t.Fatalf("gate verdict missing: %v", e)
	}
	if sink.auth[0] != "Bearer tok" {
		t.Fatalf("trigger auth %q", sink.auth[0])
	}
	if !bytes.Contains(decisions.Bytes(), []byte(`"sensor_id":"agh-lab"`)) {
		t.Fatalf("sensor id from the event must be used: %s", decisions.String())
	}
}

func TestServeVerificationEventsAlwaysPass(t *testing.T) {
	sink := &triggerSink{}
	trig := httptest.NewServer(sink)
	defer trig.Close()
	s := newTestGate(t, false, 0, trig.URL+"/events") // models find everything boring
	var decisions bytes.Buffer
	postEvents(t, s.handler(), "tok", evNew, evSilent)
	drain(s, &decisions)
	if n, _ := s.deliverOnce(cascadeCentralClient()); n != 1 {
		t.Fatalf("only the verification event should be forwarded, got %d", n)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.events[0]["type"] != "service_silent" || sink.events[0]["reason"] != "verification_passthrough" {
		t.Fatalf("forwarded: %v", sink.events[0])
	}
	if s.passed.Load() != 1 || s.seen.Load() != 2 {
		t.Fatalf("counters passed=%d seen=%d", s.passed.Load(), s.seen.Load())
	}
}

func TestServeKeepsEventsWhileTriggerIsDown(t *testing.T) {
	sink := &triggerSink{fail: true}
	trig := httptest.NewServer(sink)
	defer trig.Close()
	s := newTestGate(t, true, 1, trig.URL+"/events")
	var decisions bytes.Buffer
	postEvents(t, s.handler(), "tok", evNew)
	drain(s, &decisions)
	if _, err := s.deliverOnce(cascadeCentralClient()); err == nil {
		t.Fatal("expected an error while the trigger is down")
	}
	entries, _ := os.ReadDir(s.outbox.dir)
	if len(entries) != 1 {
		t.Fatalf("event must stay in the outbox: %d files", len(entries))
	}
	sink.mu.Lock()
	sink.fail = false
	sink.mu.Unlock()
	if n, err := s.deliverOnce(cascadeCentralClient()); err != nil || n != 1 {
		t.Fatalf("retry: %d %v", n, err)
	}
}
