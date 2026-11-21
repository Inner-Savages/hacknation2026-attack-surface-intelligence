package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// Verify the materialized LFS objects too: pointer-only checkouts cannot start
// inference. Hash by streaming so an 800 MB weight does not fill Go memory.
func verifyModels(manifest string) error {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	var m struct {
		Version int `json:"version"`
		Files   []struct {
			Path string `json:"path"`
			SHA  string `json:"sha256"`
			Size int64  `json:"size"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Version != 1 || len(m.Files) == 0 {
		return fmt.Errorf("empty or unsupported model manifest")
	}
	for _, a := range m.Files {
		if !filepath.IsLocal(a.Path) || a.Size <= 0 {
			return fmt.Errorf("invalid artifact %q", a.Path)
		}
		f, err := os.Open(filepath.Join(filepath.Dir(manifest), a.Path))
		if err != nil {
			return fmt.Errorf("%s: %w; run git lfs pull", a.Path, err)
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA {
			return fmt.Errorf("%s: size/SHA256 mismatch; run git lfs pull and verify again", a.Path)
		}
	}
	log.Printf("verified %d model artifacts", len(m.Files))
	return nil
}
