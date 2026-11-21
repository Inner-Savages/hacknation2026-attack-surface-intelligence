package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

// Small, complete host histories from the original real-inference experiment.
// This runs in CI without weights, Docker, external caches or test labels.
// It checks the exact requests against captured traffic, not model accuracy.
func TestPortableRecordedInference(t *testing.T) {
	var records []struct {
		Event    aiml.Event                                             `json:"event"`
		Features []float64                                              `json:"features"`
		Scores   map[string]float64                                     `json:"scores"`
		Models   map[string]struct{ Request, Response json.RawMessage } `json:"models"`
		Forward  bool                                                   `json:"expected_forward"`
		Fast     bool                                                   `json:"expected_fast"`
	}
	raw, err := os.ReadFile("testdata/recorded-inference.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}
	canonical := func(b []byte) string {
		var v interface{}
		if json.Unmarshal(b, &v) != nil {
			return "invalid"
		}
		b, _ = json.Marshal(v)
		return string(b)
	}
	p, id, err := loadCascadePolicy("../../deploy/cascade50/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	urls := map[string]string{}
	for _, name := range p.Cascade.Remote {
		cache := map[string]json.RawMessage{}
		for _, r := range records {
			cache[canonical(r.Models[name].Request)] = r.Models[name].Response
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			response, ok := cache[canonical(b)]
			if !ok {
				t.Errorf("%s request changed: %s", name, b)
				http.Error(w, "request differs", 400)
				return
			}
			w.Write(response)
		}))
		t.Cleanup(srv.Close)
		urls[name] = srv.URL + "/v1/systemone"
	}
	g, err := newCascadeEngine(p, id, urls, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	x := aiml.NewExtractor()
	for i, r := range records {
		b, _ := json.Marshal(r.Event)
		d := g.decide("golden", b, x)
		if d.Unresolved || d.Forward != r.Forward || d.Fast.Forward != r.Fast || !reflect.DeepEqual(d.Features, r.Features) {
			t.Fatalf("record %d changed: %+v", i, d)
		}
		// Go's math.Log/math.Exp use per-architecture assembly, so a recorded
		// score can differ by a few ULP between amd64 and arm64. A relative
		// 1e-12 tolerance absorbs that while still catching real regressions.
		close := func(a, b float64) bool {
			return math.Abs(a-b) <= 1e-12*math.Max(1, math.Max(math.Abs(a), math.Abs(b)))
		}
		if !close(p.Tree.Score(d.Features), r.Scores["tree"]) || !close(p.GNB.Score(d.Features), r.Scores["gnb"]) || !close(p.Baseline.Anomaly(d.Event), r.Scores["baseline"]) {
			t.Fatalf("record %d Go scoring changed", i)
		}
	}
}

func TestInboxRequiresAuthAndDurablyDeduplicates(t *testing.T) {
	q, err := openCascadeOutbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := inboxHandler(q, "test-token")
	id := sourceDigest([]byte("event"))
	b, _ := json.Marshal(cascadeEnvelope{EventID: id, Forward: true, Unresolved: true})
	request := func(body []byte, token string) int {
		r := httptest.NewRequest("POST", "/events", bytes.NewReader(body))
		r.Header.Set("Authorization", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if request(b, "") != 401 {
		t.Fatal("accepted without token")
	}
	if request([]byte("{}"), "Bearer test-token") != 400 {
		t.Fatal("accepted invalid envelope")
	}
	if request(b, "Bearer test-token") != 202 {
		t.Fatal("did not accept escalation")
	}
	if request(b, "Bearer test-token") != 202 {
		t.Fatal("duplicate was not acknowledged")
	}
	got, err := q.read(id)
	if err != nil || !bytes.Equal(b, got) {
		t.Fatal("lost unresolved escalation")
	}
	files, _ := os.ReadDir(q.dir)
	if len(files) != 1 {
		t.Fatal("duplicate stored")
	}
}

func TestArtifactVerificationRejectsLFSPointerAndCorruption(t *testing.T) {
	dir := t.TempDir()
	data := []byte("real model test fixture")
	manifest, _ := json.Marshal(map[string]interface{}{"version": 1, "files": []map[string]interface{}{{"path": "model.gguf", "size": len(data), "sha256": sourceDigest(data)}}})
	path := filepath.Join(dir, "manifest.json")
	os.WriteFile(path, manifest, 0600)
	model := filepath.Join(dir, "model.gguf")
	for _, bad := range []string{"version https://git-lfs.github.com/spec/v1\n", "corrupt"} {
		os.WriteFile(model, []byte(bad), 0600)
		if verifyModels(path) == nil {
			t.Fatal("accepted missing/corrupt weight")
		}
	}
	os.WriteFile(model, data, 0600)
	if err := verifyModels(path); err != nil {
		t.Fatal(err)
	}
}
