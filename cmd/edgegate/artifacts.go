package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Model weights are not stored in the repository. models/manifest.json pins
// every artifact to a Hugging Face revision with its size and SHA256;
// fetch-models downloads what is missing and verify-models checks it all.

type modelArtifact struct {
	Path   string `json:"path"`
	SHA    string `json:"sha256"`
	Size   int64  `json:"size"`
	Source string `json:"source"`
}

func loadManifest(manifest string) ([]modelArtifact, error) {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return nil, err
	}
	var m struct {
		Version int             `json:"version"`
		Files   []modelArtifact `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Version != 1 || len(m.Files) == 0 {
		return nil, fmt.Errorf("empty or unsupported model manifest")
	}
	for _, a := range m.Files {
		if !filepath.IsLocal(a.Path) || a.Size <= 0 {
			return nil, fmt.Errorf("invalid artifact %q", a.Path)
		}
	}
	return m.Files, nil
}

// checkArtifact hashes by streaming so an 800 MB weight does not fill memory.
func checkArtifact(path string, a modelArtifact) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA {
		return fmt.Errorf("size/SHA256 mismatch")
	}
	return nil
}

func verifyModels(manifest string) error {
	files, err := loadManifest(manifest)
	if err != nil {
		return err
	}
	for _, a := range files {
		if err := checkArtifact(filepath.Join(filepath.Dir(manifest), a.Path), a); err != nil {
			return fmt.Errorf("%s: %w; run 'edgegate fetch-models' (make cascade50-models)", a.Path, err)
		}
	}
	log.Printf("verified %d model artifacts", len(files))
	return nil
}

// fetchModels downloads every artifact that is missing or does not match,
// only from allowedHost over HTTPS, into a temporary file that is renamed
// into place after its size and SHA256 check out.
func fetchModels(manifest, allowedHost string, client *http.Client) error {
	files, err := loadManifest(manifest)
	if err != nil {
		return err
	}
	fetched := 0
	for _, a := range files {
		dst := filepath.Join(filepath.Dir(manifest), a.Path)
		if checkArtifact(dst, a) == nil {
			continue
		}
		u, err := url.Parse(a.Source)
		if err != nil || u.Scheme != "https" || u.Host != allowedHost {
			return fmt.Errorf("%s: source must be https://%s/...: %q", a.Path, allowedHost, a.Source)
		}
		log.Printf("fetching %s (%.1f MB)", a.Path, float64(a.Size)/1e6)
		if err := download(client, a, dst); err != nil {
			return fmt.Errorf("%s: %w", a.Path, err)
		}
		fetched++
	}
	log.Printf("models ready: %d fetched, %d already present", fetched, len(files)-fetched)
	return nil
}

func download(client *http.Client, a modelArtifact, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	resp, err := client.Get(a.Source)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".fetch-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, a.Size+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA {
		return fmt.Errorf("downloaded file does not match the manifest (size %d, want %d)", n, a.Size)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func modelClient() *http.Client {
	// Hugging Face redirects /resolve/ to its CDN; follow it.
	return &http.Client{Timeout: 30 * time.Minute}
}
