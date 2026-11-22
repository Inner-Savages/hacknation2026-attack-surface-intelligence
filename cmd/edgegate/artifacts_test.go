package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func writeManifest(t *testing.T, dir string, files []modelArtifact) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"version": 1, "files": files})
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func artifact(path, body, source string) modelArtifact {
	sum := sha256.Sum256([]byte(body))
	return modelArtifact{Path: path, SHA: hex.EncodeToString(sum[:]), Size: int64(len(body)), Source: source}
}

func TestFetchModelsDownloadsVerifiesAndSkips(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/org/model/resolve/abc/weights.gguf":
			w.Write([]byte("WEIGHTS"))
		case "/org/model/resolve/abc/tampered.bin":
			w.Write([]byte("EVIL"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	dir := t.TempDir()

	good := artifact("m/weights.gguf", "WEIGHTS", srv.URL+"/org/model/resolve/abc/weights.gguf")
	manifest := writeManifest(t, dir, []modelArtifact{good})
	if err := fetchModels(manifest, host, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "m/weights.gguf")); string(b) != "WEIGHTS" {
		t.Fatalf("content %q", b)
	}
	if err := verifyModels(manifest); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()
	if err := fetchModels(manifest, host, srv.Client()); err != nil || hits.Load() != before {
		t.Fatalf("a matching file must not be downloaded again (err %v)", err)
	}

	bad := artifact("m/tampered.bin", "GOOD", srv.URL+"/org/model/resolve/abc/tampered.bin")
	manifest = writeManifest(t, dir, []modelArtifact{bad})
	if err := fetchModels(manifest, host, srv.Client()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered download must fail: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "m/tampered.bin")); !os.IsNotExist(err) {
		t.Fatal("a mismatching download must not land in place")
	}
}

func TestFetchModelsRefusesOtherHostsAndPlainHTTP(t *testing.T) {
	dir := t.TempDir()
	for _, src := range []string{"https://evil.example/x.gguf", "http://huggingface.co/x.gguf"} {
		manifest := writeManifest(t, dir, []modelArtifact{artifact("x.gguf", "X", src)})
		err := fetchModels(manifest, "huggingface.co", http.DefaultClient)
		if err == nil || !strings.Contains(err.Error(), "source must be") {
			t.Errorf("%s: %v", src, err)
		}
	}
}
