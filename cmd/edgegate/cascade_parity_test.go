package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

// Opt-in large-fixture integration: real recorded model outputs are served
// over HTTP, but this is a parity test, NOT a fresh inference accuracy run.
// All 120k source events restore causal history; only the selected cohort is
// sent through the gate. Merely replaying the cohort would change features.
func TestCascadeFullStreamParityWithRecordedInference(t *testing.T) {
	exp := os.Getenv("ASI_CASCADE_EXPERIMENT")
	if exp == "" {
		t.Skip("set ASI_CASCADE_EXPERIMENT to the real-model experiment directory")
	}
	p, id, err := loadCascadePolicy("../../deploy/cascade50/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []benchRow
	b, err := os.ReadFile(filepath.Join(exp, "scored-cohort.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	bySplit := map[string]map[int]benchRow{}
	splits := map[string][]benchRow{}
	for _, r := range rows {
		if bySplit[r.Split] == nil {
			bySplit[r.Split] = map[int]benchRow{}
		}
		bySplit[r.Split][r.Index] = r
		splits[r.Split] = append(splits[r.Split], r)
	}
	canonical := func(raw []byte) string {
		var v interface{}
		if json.Unmarshal(raw, &v) != nil {
			return "invalid"
		}
		b, _ := json.Marshal(v)
		return sourceDigest(b)
	}
	urls := map[string]string{}
	counters := map[string]*atomic.Int64{}
	for _, name := range p.Cascade.Remote {
		name := name
		cache := map[string]json.RawMessage{}
		f, err := os.Open(filepath.Join(exp, name+"-observations.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 65536), 4*1024*1024)
		for s.Scan() {
			var o benchObservation
			if json.Unmarshal(s.Bytes(), &o) != nil || o.Error != "" {
				t.Fatal("invalid observation fixture")
			}
			cache[canonical(o.Request)] = o.Response
		}
		if err = s.Err(); err != nil {
			t.Fatal(err)
		}
		f.Close()
		counter := &atomic.Int64{}
		counters[name] = counter
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counter.Add(1)
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", 500)
				return
			}
			answer, ok := cache[canonical(raw)]
			if !ok {
				t.Errorf("%s input differs from calibrated request: %s", name, string(raw))
				http.Error(w, "input mismatch", 400)
				return
			}
			w.Write(answer)
		}))
		t.Cleanup(srv.Close)
		urls[name] = srv.URL + "/v1/systemone"
	}
	g, err := newCascadeEngine(p, id, urls, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wantFN := map[string]int{"val": 0, "test": 0, "shift": 0}
	wantRawForward := map[string]int{"val": 307, "test": 315, "shift": 289}
	wantWeighted := map[string]float64{"val": .4997477373757826, "test": .4615869378401604, "shift": .45674616922051964}
	expectedCalls := int64(0)
	for _, split := range []string{"val", "test", "shift"} {
		f, err := os.Open(filepath.Join(exp, "..", "..", "data", split, "events.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 65536), 4*1024*1024)
		x := aiml.NewExtractor()
		index, checked, fn, forward := 0, 0, 0, 0
		weighted, total := 0., 0.
		for s.Scan() {
			r, selected := bySplit[split][index]
			index++
			if !selected {
				var e aiml.Event
				if json.Unmarshal(s.Bytes(), &e) != nil {
					t.Fatal("bad source event")
				}
				x.Features(e)
				continue
			}
			d := g.decide("fixture", s.Bytes(), x)
			checked++
			if d.Unresolved || !reflect.DeepEqual(d.Features, r.Sample.X) {
				t.Fatalf("%s/%d feature/model failure: %+v", split, r.Index, d)
			}
			scores := map[string]float64{}
			for j, n := range remoteNames {
				scores[n] = r.Scores[j]
			}
			want := p.Cascade.Decide(scores)
			if d.Forward != want.Forward || d.Fast.Forward != (want.Stage == "fast") {
				t.Fatalf("routing differs at %s/%d", split, r.Index)
			}
			if d.Remote != nil {
				expectedCalls++
				for j, n := range remoteNames {
					if j >= 5 && d.Scores[n].Score != r.Scores[j] {
						t.Fatal("changed cached prediction")
					}
				}
			}
			if d.Forward {
				forward++
				weighted += r.Weight
			} else if r.Sample.Y {
				fn++
			}
			total += r.Weight
		}
		if err = s.Err(); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if checked != len(splits[split]) || fn != wantFN[split] || forward != wantRawForward[split] || absFloat(weighted/total-wantWeighted[split]) > 1e-12 {
			t.Fatalf("%s changed: count=%d fn=%d forwarded=%d weighted=%g", split, checked, fn, forward, weighted/total)
		}
		t.Logf("%s: exact features/requests/decisions for %d cohort events; FN=%d forwarded=%d weighted=%.8f", split, checked, fn, forward, weighted/total)
	}
	for n, c := range counters {
		if c.Load() != expectedCalls {
			t.Fatalf("%s calls=%d wanted=%d", n, c.Load(), expectedCalls)
		}
	}
	if expectedCalls != 981 {
		t.Fatal(fmt.Sprintf("wrong remote route count %d", expectedCalls))
	}
}
func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// Offline benchmark record types are test-only. Labels never reach the gate.
type benchRow struct {
	Split  string
	Index  int
	Weight float64
	Sample struct {
		Event aiml.Event
		X     []float64
		Y     bool
	}
	Scores []float64
}
type benchObservation struct {
	Request  json.RawMessage
	Response json.RawMessage
	Error    string
}

var remoteNames = []string{"logistic", "tree", "gnb", "rules", "baseline", "basal", "laya", "kev"}
