package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
	"github.com/Inner-Savages/silence-on-the-wire/internal/pipeline"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
)

// scanFlags are the flags shared by a single scan and a scheduled one.
type scanFlags struct {
	fs                     *flag.FlagSet
	targetList, targetFile *string
	allow, ports, sigFiles *string
	topPorts, maxRate      *int
	syn, skipPing          *bool
	intensity              *int
	versionMode            *string
	versionWait            *time.Duration
	hostTimeout            *time.Duration
	chunkSize, parallel    *int
	chunkTime              *time.Duration
	chunkMin, chunkMax     *int
	doProbe, doFP, fpPaths *bool
	probePar               *int
	probeTO                *time.Duration
}

func addScanFlags(fs *flag.FlagSet) *scanFlags {
	return &scanFlags{
		fs:          fs,
		targetList:  fs.String("t", "", "targets: IPs, CIDRs, hostnames (comma/space separated)"),
		targetFile:  fs.String("f", "", "file with targets, one or more per line, '#' comments"),
		allow:       fs.String("allow", "", "only allow IP targets inside these CIDRs (comma separated)"),
		ports:       fs.String("p", "", "ports, e.g. 22,80,8000-8100 (default: nmap top ports)"),
		topPorts:    fs.Int("top-ports", 1000, "number of most common ports when -p is not set"),
		syn:         fs.Bool("sS", false, "SYN scan (needs CAP_NET_RAW) instead of TCP connect"),
		skipPing:    fs.Bool("Pn", false, "skip host discovery, treat all targets as up"),
		maxRate:     fs.Int("max-rate", 300, "max packets per second per nmap process (0 = nmap default)"),
		intensity:   fs.Int("version-intensity", 5, "nmap -sV intensity 0-9"),
		versionMode: fs.String("version-mode", "balanced", "service detection: balanced (short waits, unidentified ports again with nmap's own), fast (short waits only), full (plain nmap -sV)"),
		versionWait: fs.Duration("version-wait", scan.DefaultVersionWait, "how long a -sV probe waits for an answer in balanced and fast mode"),
		hostTimeout: fs.Duration("host-timeout", 5*time.Minute, "give up on a single host after this long"),
		chunkSize:   fs.Int("chunk", 0, "targets per nmap process; without -chunk-time this fixes the size, with it only the first chunks have it"),
		chunkTime:   fs.Duration("chunk-time", time.Minute, "size chunks by the measured speed to take about this long (0 = fixed size)"),
		chunkMin:    fs.Int("chunk-min", scan.DefaultMinChunk, "smallest chunk -chunk-time may choose"),
		chunkMax:    fs.Int("chunk-max", scan.DefaultMaxChunk, "largest chunk -chunk-time may choose"),
		parallel:    fs.Int("parallel", 4, "concurrent nmap processes"),
		doProbe:     fs.Bool("probe", true, "probe web services found by nmap (GET only: page, same-host redirects, favicon)"),
		probePar:    fs.Int("probe-parallel", 8, "concurrent HTTP probes"),
		probeTO:     fs.Duration("probe-timeout", 10*time.Second, "timeout per HTTP request"),
		doFP:        fs.Bool("fingerprint", true, "recognize technologies with signatures"),
		fpPaths:     fs.Bool("fingerprint-paths", true, "let signatures GET fixed paths such as /wp-login.php"),
		sigFiles:    fs.String("signatures", "", "extra signature YAML files (comma separated)"),
	}
}

// config turns parsed flags into a scan configuration and its targets.
// Mistakes end the program.
func (f *scanFlags) config() (*pipeline.Config, *scan.Targets) {
	var targets scan.Targets
	if err := targets.AddList(*f.targetList); err != nil {
		log.Fatal(err)
	}
	if *f.targetFile != "" {
		file, err := os.Open(*f.targetFile)
		if err != nil {
			log.Fatal(err)
		}
		err = targets.AddReader(file)
		file.Close()
		if err != nil {
			log.Fatalf("%s: %v", *f.targetFile, err)
		}
	}
	if targets.Len() == 0 {
		log.Fatal("no targets: use -t or -f")
	}
	if *f.allow != "" {
		prefixes, err := scan.ParseAllow(*f.allow)
		if err != nil {
			log.Fatal(err)
		}
		if err := targets.CheckAllowed(prefixes); err != nil {
			log.Fatal(err)
		}
	}

	// Load signatures before scanning so a broken custom file fails fast.
	var extra []string
	for _, s := range strings.Split(*f.sigFiles, ",") {
		if s = strings.TrimSpace(s); s != "" {
			extra = append(extra, s)
		}
	}
	engine, err := fingerprint.NewEngine(extra...)
	if err != nil {
		log.Fatalf("signatures: %v", err)
	}

	// An explicit -chunk alone asks for that size.
	chunkTime := *f.chunkTime
	set := map[string]bool{}
	f.fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	if set["chunk"] && !set["chunk-time"] {
		chunkTime = 0
	}
	cfg := &pipeline.Config{
		Scanner: scan.Scanner{
			Options: scan.Options{
				Ports: *f.ports, TopPorts: *f.topPorts, SYN: *f.syn, SkipDiscovery: *f.skipPing,
				MaxRate: *f.maxRate, VersionIntensity: *f.intensity, HostTimeout: *f.hostTimeout,
				VersionMode: scan.VersionMode(*f.versionMode), VersionWait: *f.versionWait,
			},
			ChunkSize:   *f.chunkSize,
			ChunkTarget: chunkTime,
			MinChunk:    *f.chunkMin,
			MaxChunk:    *f.chunkMax,
			Parallel:    *f.parallel,
			Progress:    func(p scan.Progress) { log.Print(progressLine(p)) },
		},
		SkipProbe:            !*f.doProbe,
		ProbeParallel:        *f.probePar,
		ProbeTimeout:         *f.probeTO,
		SkipFingerprint:      !*f.doFP,
		SkipFingerprintPaths: !*f.fpPaths,
		Engine:               engine,
		Logf:                 log.Printf,
	}
	if err := cfg.Scanner.Options.Validate(); err != nil {
		log.Fatal(err)
	}
	return cfg, &targets
}

func progressLine(p scan.Progress) string {
	c := p.Chunk
	status := "ok"
	if c.Error != "" {
		status = "error: " + c.Error
	}
	s := fmt.Sprintf("chunk %d: %d targets (%s), %d up, %v, %s; %d/%d targets", c.Index+1, c.Targets, c.Reason,
		c.HostsUp, time.Duration(c.Duration).Round(time.Millisecond), status, p.Done, p.Total)
	if p.ETA > 0 {
		s += fmt.Sprintf(", about %v left", p.ETA.Round(time.Second))
	}
	return s
}

// scope describes what a scan looks at, so a scheduled run is resumed only
// with the same options. Speed limits may change between windows.
func (f *scanFlags) scope() string {
	return fmt.Sprintf("p=%s top=%d sS=%v Pn=%v intensity=%d mode=%s probe=%v fp=%v paths=%v sig=%s",
		*f.ports, *f.topPorts, *f.syn, *f.skipPing, *f.intensity, *f.versionMode, *f.doProbe, *f.doFP, *f.fpPaths, *f.sigFiles)
}
