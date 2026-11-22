package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// A syntax error in the inline script leaves the console blank (no login form),
// and no Go test notices. Run node --check over it when node is available.
func TestIndexScriptSyntax(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	html, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindSubmatch(html)
	if m == nil {
		t.Fatal("no inline script found in static/index.html")
	}
	js := filepath.Join(t.TempDir(), "index.js")
	if err := os.WriteFile(js, m[1], 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, "--check", js).CombinedOutput(); err != nil {
		t.Fatalf("static/index.html script does not parse:\n%s", out)
	}
}
