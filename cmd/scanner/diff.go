package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Inner-Savages/silence-on-the-wire/internal/diff"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// runDiff implements `scanner diff [-json] [-exit-code] old.json new.json`.
func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the diff as JSON instead of text")
	exitCode := fs.Bool("exit-code", false, "exit with status 1 when the scans differ (like diff(1))")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: scanner diff [-json] [-exit-code] old.json new.json")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}
	old, cur := load(fs.Arg(0)), load(fs.Arg(1))
	d := diff.Compare(old, cur)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Print(d.Text())
	}
	if *exitCode && !d.Summary.Empty() {
		os.Exit(1)
	}
}

func load(path string) *result.Scan {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var s result.Scan
	if err := json.Unmarshal(data, &s); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	return &s
}
