// Command trigger receives passive sensor events over HTTP and runs
// targeted active scans: new or changed services get scanned, silent ones
// verified. Findings (verdict, services, technologies, changes since the
// previous scan of that target) go to stdout and <state>/findings.jsonl.
//
//	trigger -allow 172.16.0.0/12 -listen 127.0.0.1:8099
//	sensor -i 'br-*' -webhook http://127.0.0.1:8099/events
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
	"github.com/Inner-Savages/silence-on-the-wire/internal/pipeline"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
	"github.com/Inner-Savages/silence-on-the-wire/internal/trigger"
)

func main() {
	var (
		listen       = flag.String("listen", "127.0.0.1:8099", "address for POST /events and GET /healthz")
		allow        = flag.String("allow", "", "required: only scan addresses inside these CIDRs (comma separated)")
		stateDir     = flag.String("state", "trigger-state", "directory for findings.jsonl and the last result per target")
		token        = flag.String("token", os.Getenv("SOTW_WEBHOOK_TOKEN"), "bearer token sensors must send (default $SOTW_WEBHOOK_TOKEN)")
		parallel     = flag.Int("parallel", 2, "concurrent scans")
		timeout      = flag.Duration("timeout", 5*time.Minute, "per scan")
		debounce     = flag.Duration("debounce", 5*time.Second, "merge events for one target arriving within this window")
		quiet        = flag.Duration("quiet", 15*time.Second, "ignore events about an address for this long after scanning it")
		cooldown     = flag.Duration("cooldown", time.Minute, "minimum time between scans of one target")
		closedCD     = flag.Duration("closed-cooldown", 5*time.Minute, "cooldown when only service_closed events arrived")
		perMinute    = flag.Int("max-per-minute", 10, "scans started per minute, at most")
		ignoreSelf   = flag.Bool("ignore-self", true, "ignore events about this machine's own addresses (the scanner's traffic source)")
		ignore       = flag.String("ignore", "", "more addresses whose events are ignored (comma separated)")
		topPorts     = flag.Int("top-ports", 100, "ports scanned for host events")
		maxRate      = flag.Int("max-rate", 300, "nmap --max-rate")
		intensity    = flag.Int("version-intensity", 5, "nmap -sV intensity 0-9")
		sigFiles     = flag.String("signatures", "", "extra signature YAML files (comma separated)")
		probeTimeout = flag.Duration("probe-timeout", 10*time.Second, "timeout per HTTP request")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)
	log.SetPrefix("trigger: ")

	prefixes, err := scan.ParseAllow(*allow)
	if err != nil {
		log.Fatal(err)
	}
	if len(prefixes) == 0 {
		log.Fatal("-allow is required: the trigger never scans outside it")
	}
	var self []netip.Addr
	if *ignoreSelf {
		self = localAddrs()
	}
	for _, s := range strings.Split(*ignore, ",") {
		if s = strings.TrimSpace(s); s != "" {
			a, err := netip.ParseAddr(s)
			if err != nil {
				log.Fatalf("-ignore: %v", err)
			}
			self = append(self, a)
		}
	}

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
	base := pipeline.Config{
		Scanner:      scan.Scanner{Options: scan.Options{MaxRate: *maxRate, VersionIntensity: *intensity}},
		ProbeTimeout: *probeTimeout,
		Engine:       engine,
	}
	if err := base.Scanner.Options.Validate(); err != nil {
		log.Fatal(err)
	}

	enc := json.NewEncoder(os.Stdout)
	svc := &trigger.Service{
		Policy: &trigger.Policy{
			Allow: prefixes, Self: self, Debounce: *debounce, Quiet: *quiet,
			Cooldown: *cooldown, ClosedCooldown: *closedCD, MaxPerMinute: *perMinute,
		},
		Scanner:   &trigger.PipelineScanner{Base: base, TopPorts: *topPorts},
		StateDir:  *stateDir,
		Parallel:  *parallel,
		Timeout:   *timeout,
		Token:     *token,
		Logf:      log.Printf,
		OnFinding: func(f trigger.Finding) { _ = enc.Encode(f) },
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Addr: *listen, Handler: svc.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	runDone := make(chan struct{})
	go func() { svc.Run(ctx); close(runDone) }()

	auth := "no token"
	if *token != "" {
		auth = "token required"
	}
	log.Printf("listening on %s (%s), allow %s, ignoring %d own addresses", *listen, auth, *allow, len(self))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-ctx.Done()
	log.Printf("stopping: waiting for running scans")
	<-runDone // Run returns once running scans have finished
}

// localAddrs lists this machine's IP addresses (with host networking these
// include the Docker bridge gateways the scanner's traffic comes from).
func localAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}
