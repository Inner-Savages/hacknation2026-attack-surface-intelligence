// sigimport converts third-party technology signatures (Wappalyzer JSON,
// nuclei detection templates with favicon mmh3 hashes) into the YAML
// signature format of internal/fingerprint, so the scanner can load them
// with -signatures without adopting either engine.
//
// Usage:
//
//	sigimport -wappalyzer webappanalyzer/src/technologies \
//	    -nuclei nuclei-templates/http/technologies \
//	    -o signatures-imported.yaml [-report report.txt]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Inner-Savages/silence-on-the-wire/internal/sigimport"
)

func main() {
	var (
		wappDir   = flag.String("wappalyzer", "", "directory with webappanalyzer technology JSON files (src/technologies)")
		nucleiDir = flag.String("nuclei", "", "directory with nuclei templates, walked recursively (e.g. http/technologies)")
		out       = flag.String("o", "", "output signature YAML file (required)")
		report    = flag.String("report", "", "optional report file; stats always go to stderr")
		minConf   = flag.Float64("min-confidence", 0.5, "min_confidence set on imported signatures")
		maxWeight = flag.Float64("max-weight", 0.95, "cap on imported matcher weights (third-party confidence 100 would make one match decisive)")
		noBuiltin = flag.Bool("allow-builtin-shadow", false, "do not skip imports whose name collides with a built-in signature")
	)
	flag.Parse()

	if *out == "" {
		log.Fatal("-o is required")
	}
	if *wappDir == "" && *nucleiDir == "" {
		log.Fatal("at least one of -wappalyzer or -nuclei is required")
	}

	opts := sigimport.Options{MinConfidence: *minConf, MaxWeight: *maxWeight}
	if !*noBuiltin {
		names, err := sigimport.BuiltinNames()
		if err != nil {
			log.Fatalf("built-in signatures: %v", err)
		}
		opts.Reserved = names
	}
	imp := sigimport.NewImporter(opts)

	var sources []string
	var lines []string
	if *wappDir != "" {
		st, err := imp.ImportWappalyzer(*wappDir)
		if err != nil {
			log.Fatalf("wappalyzer: %v", err)
		}
		sources = append(sources, "Wappalyzer (webappanalyzer)")
		lines = append(lines, "wappalyzer: "+st.String())
	}
	if *nucleiDir != "" {
		st, err := imp.ImportNuclei(*nucleiDir)
		if err != nil {
			log.Fatalf("nuclei: %v", err)
		}
		sources = append(sources, "nuclei-templates")
		lines = append(lines, "nuclei:     "+st.String())
	}

	sigs := imp.Signatures()
	data, err := sigimport.Marshal(sigs, strings.Join(sources, " + "))
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		log.Fatal(err)
	}
	lines = append(lines, fmt.Sprintf("total: %d signatures written to %s", len(sigs), *out))

	for _, l := range lines {
		fmt.Fprintln(os.Stderr, l)
	}
	if *report != "" {
		if err := os.WriteFile(*report, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
