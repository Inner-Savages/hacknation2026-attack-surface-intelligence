package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const scanJSON = `{"started_at":"2026-11-22T10:00:00Z","finished_at":"2026-11-22T10:01:00Z","hosts":[
 {"address":"10.0.0.5","state":"up","services":[{"port":80,"proto":"tcp","state":"open","name":"http",
  "tech":[{"name":"Admin panel","confidence":0.6,"tags":["admin-panel"],"evidence":["title"]}]}]}]}`

func TestReadFindings(t *testing.T) {
	ok := `{"target":{"ip":"10.0.0.5","port":80},"verdict":"scanned"}` + "\n"
	for _, tc := range []struct {
		in   string
		n    int
		fail bool
	}{
		{"", 0, false},
		{ok + "\n" + ok, 2, false},
		{ok + `{"target":{"ip":`, 1, false}, // being written right now
		{"nonsense\n" + ok, 0, true},
	} {
		got, err := readFindings(strings.NewReader(tc.in))
		if (err != nil) != tc.fail || (!tc.fail && len(got) != tc.n) {
			t.Errorf("%q: %d findings, err %v", tc.in, len(got), err)
		}
	}
}

func TestDoExport(t *testing.T) {
	dir := t.TempDir()
	scan, out := filepath.Join(dir, "scan.json"), filepath.Join(dir, "out")
	if err := os.WriteFile(scan, []byte(scanJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(f exportFlags) string {
		t.Helper()
		f.output = out
		if err := doExport(f, []string{scan}); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		return string(data)
	}
	if got := run(exportFlags{format: "csv"}); !strings.Contains(got, "10.0.0.5,,80,tcp,http") {
		t.Errorf("csv: %s", got)
	}
	if got := run(exportFlags{format: "nmap"}); !strings.Contains(got, `portid="80"`) {
		t.Errorf("nmap: %s", got)
	}
	// Dry run needs neither address nor token.
	t.Setenv("DEFECTDOJO_TOKEN", "")
	var found []map[string]any
	if err := json.Unmarshal([]byte(run(exportFlags{format: "defectdojo", dryRun: true})), &found); err != nil || len(found) != 1 {
		t.Errorf("dry run: %v %v", found, err)
	}
	for name, f := range map[string]exportFlags{
		"format":   {format: "xlsx"},
		"no url":   {format: "defectdojo"},
		"no token": {format: "defectdojo", url: "http://127.0.0.1:1"},
	} {
		f.output = filepath.Join(dir, "none")
		if err := doExport(f, []string{scan}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", info.Mode(), err)
	}
}
