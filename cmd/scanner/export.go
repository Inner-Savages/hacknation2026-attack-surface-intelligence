package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Inner-Savages/silence-on-the-wire/internal/export"
	"github.com/Inner-Savages/silence-on-the-wire/internal/export/defectdojo"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/trigger"
)

const exportUsage = `usage: scanner export [flags] scan.json...
       scanner export -format csv|json -findings findings.jsonl

Formats:
  csv         one row per open service (or per trigger finding)
  json        the scan (or the trigger findings) as JSON
  nmap        the nmap part of a scan as nmap XML
  defectdojo  selected observations as informational findings in DefectDojo;
              the API token comes from $DEFECTDOJO_TOKEN or -token-file

Flags:
`

type exportFlags struct {
	format, output, findings, previous string

	selection     string
	minConfidence float64
	dryRun        bool
	url           string
	tokenFile     string
	allowHTTP     bool
	nmap          bool
	where         defectdojo.Context
}

// runExport implements `scanner export`.
func runExport(args []string) {
	var f exportFlags
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	fs.StringVar(&f.format, "format", "csv", "csv, json, nmap or defectdojo")
	fs.StringVar(&f.output, "o", "", "write here (default or \"-\": stdout)")
	fs.StringVar(&f.findings, "findings", "", "findings.jsonl of the trigger: exported as csv/json, attached as evidence for defectdojo")
	fs.StringVar(&f.selection, "select", "default", "observations to send: default, rule names, category:<c>, tag:<t>, tech:<name> (comma separated)")
	fs.Float64Var(&f.minConfidence, "min-confidence", 0.5, "skip observations below this confidence (0..1)")
	fs.StringVar(&f.previous, "previous", "", "older scans, only used for first-seen dates (comma separated)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print what would be sent to DefectDojo without connecting to it")
	fs.StringVar(&f.url, "url", os.Getenv("DEFECTDOJO_URL"), "DefectDojo address, e.g. https://dojo.example.org (default $DEFECTDOJO_URL)")
	fs.StringVar(&f.tokenFile, "token-file", "", "read the API token from this file instead of $DEFECTDOJO_TOKEN")
	fs.BoolVar(&f.allowHTTP, "allow-http", false, "allow plain HTTP to hosts other than localhost")
	fs.BoolVar(&f.nmap, "nmap", false, "also hand the nmap results to DefectDojo's \"Nmap Scan\" importer (every open port)")
	d := defectdojo.DefaultContext
	fs.StringVar(&f.where.ProductType, "product-type", d.ProductType, "DefectDojo product type, created if missing")
	fs.StringVar(&f.where.Product, "product", d.Product, "DefectDojo product, created if missing")
	fs.StringVar(&f.where.Engagement, "engagement", d.Engagement, "DefectDojo engagement, created if missing")
	fs.StringVar(&f.where.Test, "test", d.Test, "DefectDojo test, created if missing")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), exportUsage)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() == 0 && f.findings == "" {
		fs.Usage()
		os.Exit(2)
	}
	if err := doExport(f, fs.Args()); err != nil {
		log.Fatal(err)
	}
}

func doExport(f exportFlags, files []string) error {
	var scans []*result.Scan
	for _, p := range files {
		scans = append(scans, load(p))
	}
	var findings []trigger.Finding
	if f.findings != "" {
		fh, err := os.Open(f.findings)
		if err != nil {
			return err
		}
		findings, err = readFindings(fh)
		fh.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", f.findings, err)
		}
	}
	if f.format == "defectdojo" {
		if len(scans) == 0 {
			return errors.New("defectdojo needs a scan result; -findings only adds evidence")
		}
		return exportDefectDojo(f, scans, findings)
	}
	if len(scans) > 0 && findings != nil {
		return errors.New("a csv or json file holds either scans or findings: export them separately")
	}
	return writeOutput(f.output, func(w io.Writer) error {
		switch {
		case f.format == "csv" && len(scans) > 0:
			return export.WriteScanCSV(w, scans...)
		case f.format == "csv":
			return export.WriteFindingsCSV(w, findings)
		case f.format == "json" && len(scans) == 1:
			return writeJSON(w, scans[0])
		case f.format == "json" && len(scans) > 1:
			return writeJSON(w, scans)
		case f.format == "json":
			return writeJSON(w, findings)
		case f.format == "nmap" && len(scans) == 1:
			return export.WriteNmapXML(w, scans[0])
		case f.format == "nmap":
			return errors.New("nmap XML is made from exactly one scan")
		}
		return fmt.Errorf("unknown format %q", f.format)
	})
}

func exportDefectDojo(f exportFlags, scans []*result.Scan, findings []trigger.Finding) error {
	sel := export.Selection{Names: export.ParseSelection(f.selection), MinConfidence: f.minConfidence}
	obs, err := export.Observe(sel, scans...)
	if err != nil {
		return err
	}
	var old []*result.Scan
	for _, p := range export.ParseSelection(f.previous) {
		old = append(old, load(p))
	}
	if err := export.AddHistory(obs, sel, old...); err != nil {
		return err
	}
	export.AddFindings(obs, findings)

	if f.dryRun {
		return writeOutput(f.output, func(w io.Writer) error {
			out := make([]defectdojo.Finding, 0, len(obs))
			for _, o := range obs {
				out = append(out, defectdojo.NewFinding(o))
			}
			log.Printf("dry run: %d finding(s) would be sent to %q / %q / %q", len(out), f.where.Product, f.where.Engagement, f.where.Test)
			return writeJSON(w, out)
		})
	}

	if f.url == "" {
		return errors.New("no DefectDojo address: use -url or $DEFECTDOJO_URL")
	}
	token := os.Getenv("DEFECTDOJO_TOKEN")
	if f.tokenFile != "" {
		data, err := os.ReadFile(f.tokenFile)
		if err != nil {
			return err
		}
		token = string(data)
	}
	client, err := defectdojo.New(f.url, token, f.allowHTTP)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep, err := client.Sync(ctx, f.where, obs)
	if rep != nil {
		for _, it := range rep.Items {
			fmt.Printf("%-9s  #%-5d %s\n", it.Status, it.ID, it.Title)
		}
		log.Printf("test %d: %d created, %d updated, %d unchanged, %d closed by analysts and left alone", rep.TestID,
			rep.Count(defectdojo.Created), rep.Count(defectdojo.Updated), rep.Count(defectdojo.Unchanged), rep.Count(defectdojo.Closed))
	}
	if err != nil || !f.nmap {
		return err
	}
	for _, s := range scans {
		id, skipped, err := client.ImportNmap(ctx, f.where, s)
		if err != nil {
			return err
		}
		log.Printf("test %d: nmap results imported", id)
		if skipped > 0 {
			log.Printf("%d host(s) without an IPv4 address skipped: the importer does not support them", skipped)
		}
	}
	return nil
}

// readFindings reads JSON lines. A line cut short at the end of the file is
// one the trigger is just writing.
func readFindings(r io.Reader) ([]trigger.Finding, error) {
	out := []trigger.Finding{}
	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		last := err == io.EOF
		if strings.TrimSpace(line) != "" {
			var f trigger.Finding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				if last {
					return out, nil
				}
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			out = append(out, f)
		}
		if last {
			return out, nil
		}
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeOutput writes to a private file, or stdout for "" and "-".
func writeOutput(path string, write func(io.Writer) error) error {
	if path == "" || path == "-" {
		return write(os.Stdout)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
