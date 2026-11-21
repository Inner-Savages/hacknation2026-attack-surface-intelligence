// Command scanner runs a safe discovery scan (nmap -sT/-sS -sV, no NSE
// scripts) over IPs, CIDRs and hostnames, split into parallel chunks, probes
// the web services it finds and writes the result as JSON.
//
//	scanner -t 127.0.0.1 -p 2223,3001,5673,8787,8888,15432,15673 -Pn -o scan.json
//	scanner -f targets.txt -allow 10.0.0.0/16 -max-rate 300
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
	"github.com/Inner-Savages/silence-on-the-wire/internal/probe"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
)

func main() {
	var (
		targetList  = flag.String("t", "", "targets: IPs, CIDRs, hostnames (comma/space separated)")
		targetFile  = flag.String("f", "", "file with targets, one or more per line, '#' comments")
		allow       = flag.String("allow", "", "only allow IP targets inside these CIDRs (comma separated)")
		ports       = flag.String("p", "", "ports, e.g. 22,80,8000-8100 (default: nmap top ports)")
		topPorts    = flag.Int("top-ports", 1000, "number of most common ports when -p is not set")
		syn         = flag.Bool("sS", false, "SYN scan (needs CAP_NET_RAW) instead of TCP connect")
		skipPing    = flag.Bool("Pn", false, "skip host discovery, treat all targets as up")
		maxRate     = flag.Int("max-rate", 300, "max packets per second per nmap process (0 = nmap default)")
		intensity   = flag.Int("version-intensity", 5, "nmap -sV intensity 0-9")
		hostTimeout = flag.Duration("host-timeout", 5*time.Minute, "give up on a single host after this long")
		chunkSize   = flag.Int("chunk", 256, "targets per nmap process")
		parallel    = flag.Int("parallel", 4, "concurrent nmap processes")
		output      = flag.String("o", "", "write the JSON result here (default stdout)")
		doProbe     = flag.Bool("probe", true, "probe web services found by nmap (GET only: page, same-host redirects, favicon)")
		probePar    = flag.Int("probe-parallel", 8, "concurrent HTTP probes")
		probeTO     = flag.Duration("probe-timeout", 10*time.Second, "timeout per HTTP request")
		doFP        = flag.Bool("fingerprint", true, "recognize technologies with signatures")
		fpPaths     = flag.Bool("fingerprint-paths", true, "let signatures GET fixed paths such as /wp-login.php")
		sigFiles    = flag.String("signatures", "", "extra signature YAML files (comma separated)")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)
	log.SetPrefix("scanner: ")

	var targets scan.Targets
	if err := targets.AddList(*targetList); err != nil {
		log.Fatal(err)
	}
	if *targetFile != "" {
		f, err := os.Open(*targetFile)
		if err != nil {
			log.Fatal(err)
		}
		err = targets.AddReader(f)
		f.Close()
		if err != nil {
			log.Fatalf("%s: %v", *targetFile, err)
		}
	}
	if targets.Len() == 0 {
		log.Fatal("no targets: use -t or -f")
	}
	if *allow != "" {
		var prefixes []netip.Prefix
		for _, s := range strings.Split(*allow, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				log.Fatalf("-allow: %v", err)
			}
			prefixes = append(prefixes, p)
		}
		if err := targets.CheckAllowed(prefixes); err != nil {
			log.Fatal(err)
		}
	}

	s := scan.Scanner{
		Options: scan.Options{
			Ports: *ports, TopPorts: *topPorts, SYN: *syn, SkipDiscovery: *skipPing,
			MaxRate: *maxRate, VersionIntensity: *intensity, HostTimeout: *hostTimeout,
		},
		ChunkSize: *chunkSize,
		Parallel:  *parallel,
		Progress: func(done, total int, c result.Chunk) {
			status := "ok"
			if c.Error != "" {
				status = "error: " + c.Error
			}
			log.Printf("chunk %d/%d: %d targets, %d up, %v, %s", done, total, c.Targets, c.HostsUp, time.Duration(c.Duration).Round(time.Millisecond), status)
		},
	}
	if err := s.Options.Validate(); err != nil {
		log.Fatal(err)
	}
	// Load signatures before scanning so a broken custom file fails fast.
	var extra []string
	for _, f := range strings.Split(*sigFiles, ",") {
		if f = strings.TrimSpace(f); f != "" {
			extra = append(extra, f)
		}
	}
	engine, err := fingerprint.NewEngine(extra...)
	if err != nil {
		log.Fatalf("signatures: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("%d targets in chunks of %d, %d in parallel: nmap %s", targets.Len(), *chunkSize, *parallel, strings.Join(s.Options.Args(), " "))
	res, err := s.Scan(ctx, &targets)
	if res == nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Printf("scan interrupted: %v (writing partial result)", err)
	}
	prober := &probe.Prober{Timeout: *probeTO}
	if *doProbe && ctx.Err() == nil {
		start := time.Now()
		n := prober.ProbeScan(ctx, res, *probePar)
		log.Printf("probed %d web services in %v", n, time.Since(start).Round(time.Millisecond))
	}
	if *doFP && ctx.Err() == nil {
		start := time.Now()
		var fetcher fingerprint.Fetcher
		if *fpPaths && *doProbe {
			fetcher = prober
		}
		engine.Run(ctx, res, fetcher, *probePar)
		log.Printf("fingerprinted in %v", time.Since(start).Round(time.Millisecond))
	}

	var w io.Writer = os.Stdout
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		log.Fatal(err)
	}
	up, open := 0, 0
	for _, h := range res.Hosts {
		if h.State == "up" {
			up++
		}
		for _, svc := range h.Services {
			if svc.State == "open" {
				open++
			}
		}
	}
	log.Printf("done in %v: %d hosts up, %d open ports", time.Duration(res.Duration).Round(time.Millisecond), up, open)
}
