package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

func testCascadePolicy(t *testing.T, early bool) *cascadePolicy {
	t.Helper()
	p, _, err := loadCascadePolicy("../../deploy/cascade50/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	prob := 0.
	if early {
		prob = 1
	}
	p.Tree.Tree = &aiml.Node{P: prob}
	for c := 0; c < 2; c++ {
		p.GNB.Prior[c] = .5
		for i := 0; i < aiml.Dimension; i++ {
			p.GNB.Mean[c][i] = 0
			p.GNB.Var[c][i] = 1
		}
	}
	r, _ := aiml.NewWeightedECDF([]float64{0, .5, 1}, []float64{1, 1, 1})
	for n := range p.Cascade.Rankers {
		p.Cascade.Rankers[n] = r
	}
	p.Cascade.FastThreshold = .6
	p.Cascade.RemoteThreshold = .6
	return p
}
func testModelReply(p *cascadePolicy, name string, score float64) string {
	b, _ := json.Marshal(map[string]interface{}{"model": p.Backends[name].Model, "routing": map[string]string{"model": p.Backends[name].Routing}, "answers": map[string]interface{}{"attack": map[string]float64{"noul": score}}})
	return string(b)
}
func testCascadeEngine(t *testing.T, p *cascadePolicy, timeout time.Duration, handler func(string, http.ResponseWriter, *http.Request)) (*cascadeEngine, *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	urls := map[string]string{}
	for _, name := range p.Cascade.Remote {
		name := name
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); handler(name, w, r) }))
		t.Cleanup(srv.Close)
		urls[name] = srv.URL + "/v1/systemone"
	}
	g, err := newCascadeEngine(p, "test-policy", urls, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return g, calls
}

var testCascadeEvent = []byte(`{"time":"2026-11-21T17:28:55Z","type":"host_silent","ip":"10.0.0.1","source":"passive"}`)

func TestCascadeEarlySkipsEveryHTTPModel(t *testing.T) {
	p := testCascadePolicy(t, true)
	g, calls := testCascadeEngine(t, p, time.Second, func(string, http.ResponseWriter, *http.Request) { t.Error("early event called model") })
	d := g.decide("sensor", testCascadeEvent, aiml.NewExtractor())
	if !d.Forward || d.Unresolved || d.Remote != nil || calls.Load() != 0 {
		t.Fatalf("incorrect early route: %+v", d)
	}
}

func TestCascadeHTTPConcurrentAndFrozenBaseline(t *testing.T) {
	p := testCascadePolicy(t, false)
	before, _ := json.Marshal(p.Baseline)
	arrived := make(chan struct{}, 3)
	release := make(chan struct{})
	g, calls := testCascadeEngine(t, p, time.Second, func(n string, w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		score := .1
		if n == "laya" {
			score = .9
		}
		fmt.Fprint(w, testModelReply(p, n, score))
	})
	done := make(chan cascadeEnvelope, 1)
	go func() { done <- g.decide("sensor", testCascadeEvent, aiml.NewExtractor()) }()
	for i := 0; i < 3; i++ {
		select {
		case <-arrived:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("models were not called concurrently")
		}
	}
	close(release)
	d := <-done
	if !d.Forward || d.Unresolved || calls.Load() != 3 || d.Remote == nil || len(d.Scores) != 3 {
		t.Fatalf("wrong remote decision %+v", d)
	}
	after, _ := json.Marshal(p.Baseline)
	if !bytes.Equal(before, after) {
		t.Fatal("baseline updated from inference")
	}
}

func TestCascadeFailuresForceEscalation(t *testing.T) {
	for _, kind := range []string{"http", "timeout", "abstain", "unbound", "review", "truncated", "dropped", "question", "missing", "wrong_model", "wrong_routing", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			p := testCascadePolicy(t, false)
			g, _ := testCascadeEngine(t, p, 30*time.Millisecond, func(n string, w http.ResponseWriter, r *http.Request) {
				if n != "laya" {
					fmt.Fprint(w, testModelReply(p, n, .1))
					return
				}
				switch kind {
				case "http":
					http.Error(w, "offline", 503)
					return
				case "timeout":
					time.Sleep(80 * time.Millisecond)
				case "redirect":
					http.Redirect(w, r, "http://127.0.0.1:1/untrusted", 302)
					return
				}
				var v map[string]interface{}
				json.Unmarshal([]byte(testModelReply(p, n, .1)), &v)
				a := v["answers"].(map[string]interface{})["attack"].(map[string]interface{})
				switch kind {
				case "abstain":
					a["abstain"] = true
				case "unbound":
					a["unbound"] = true
				case "review":
					a["route"] = "review"
				case "truncated":
					v["usage"] = map[string]bool{"truncated": true}
				case "dropped":
					v["usage"] = map[string]int{"state_tokens_dropped": 1}
				case "question":
					v["usage"] = map[string]interface{}{"truncated_questions": []string{"attack"}}
				case "missing":
					delete(a, "noul")
				case "wrong_model":
					v["model"] = "other"
				case "wrong_routing":
					v["routing"] = map[string]string{"model": "multilingual"}
				}
				json.NewEncoder(w).Encode(v)
			})
			d := g.decide("sensor", testCascadeEvent, aiml.NewExtractor())
			if !d.Forward || !d.Unresolved || d.Errors["laya"] == "" {
				t.Fatalf("failure became benign: %+v", d)
			}
			if _, ok := d.Scores["laya"]; ok {
				t.Fatal("failure became a numeric prediction")
			}
		})
	}
}

type brokenCascadeWriter struct{}

func (brokenCascadeWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCascadeOutboxSurvivesNetworkAndOutputFailures(t *testing.T) {
	p := testCascadePolicy(t, true)
	g, _ := testCascadeEngine(t, p, time.Second, func(string, http.ResponseWriter, *http.Request) { t.Error("unexpected inference") })
	dir := t.TempDir()
	opts := cascadeGateOptions{Sensor: "sensor", Outbox: dir}
	input := strings.NewReader(string(testCascadeEvent) + "\n")
	if runCascadeStream(context.Background(), g, opts, input, brokenCascadeWriter{}) == nil {
		t.Fatal("ignored output failure")
	}
	q, _ := openCascadeOutbox(dir)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("lost pending escalation: %v", entries)
	}
	var accepted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accepted.Load() {
			http.Error(w, "down", 503)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	if n, err := q.deliver(srv.Client(), srv.URL); n != 0 || err == nil {
		t.Fatal("failed delivery was acknowledged")
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("deleted unacknowledged event")
	}
	accepted.Store(true)
	if n, err := q.deliver(srv.Client(), srv.URL); n != 1 || err != nil {
		t.Fatalf("retry: %d %v", n, err)
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("acknowledged event retained")
	}
}

func TestCascadeInvalidEventsAreDurableAndNoHardQuota(t *testing.T) {
	p := testCascadePolicy(t, false)
	g, calls := testCascadeEngine(t, p, time.Second, func(string, http.ResponseWriter, *http.Request) { t.Error("invalid input called a model") })
	var out bytes.Buffer
	dir := t.TempDir()
	err := runCascadeStream(context.Background(), g, cascadeGateOptions{Sensor: "s", Outbox: dir}, strings.NewReader("{bad\nnull\n{}\n"+`{"time":"2026-11-21T17:28:55Z","type":"host_new","ip":"10.0.0.1","unknown_field":true}`+"\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(&out)
	n := 0
	for s.Scan() {
		var d cascadeEnvelope
		if json.Unmarshal(s.Bytes(), &d) != nil || !d.Forward || !d.Unresolved || d.RawEvent == "" {
			t.Fatal("invalid input dropped")
		}
		n++
	}
	entries, _ := os.ReadDir(dir)
	if n != 4 || len(entries) != 4 || calls.Load() != 0 {
		t.Fatal("50% quota dropped unresolved events")
	}
}

func TestCascadePolicyValidation(t *testing.T) {
	p := testCascadePolicy(t, false)
	p.Cascade.Rankers["laya"] = aiml.WeightedECDF{}
	if p.validate() == nil {
		t.Fatal("accepted absent ranker")
	}
	p = testCascadePolicy(t, false)
	p.GNB.Var[0] = nil
	if p.validate() == nil {
		t.Fatal("accepted malformed GNB")
	}
	p = testCascadePolicy(t, false)
	p.PromptSHA = "other"
	if p.validate() == nil {
		t.Fatal("accepted another prompt")
	}
}

func TestCascadeFollowWaitsForCompleteLineAndRejectsTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sensor.jsonl")
	os.WriteFile(path, []byte("part"), 0600)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := bufio.NewScanner(&cascadeFollowReader{ctx, f, path, info})
	done := make(chan string, 1)
	go func() {
		if s.Scan() {
			done <- s.Text()
		} else {
			done <- ""
		}
	}()
	select {
	case <-done:
		t.Fatal("consumed an incomplete append")
	case <-time.After(30 * time.Millisecond):
	}
	w, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	w.WriteString("ial\n")
	w.Close()
	if got := <-done; got != "partial" {
		t.Fatalf("partial line lost: %q", got)
	}
	os.Truncate(path, 0)
	if s.Scan() || s.Err() == nil {
		t.Fatal("silently accepted input truncation")
	}
}
