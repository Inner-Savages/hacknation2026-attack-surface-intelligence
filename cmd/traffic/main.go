// Command traffic generates gentle background traffic in a lab so a passive
// sensor has something to observe. Targets come from -targets or $TARGETS:
//
//	TARGETS="http://web/ tcp://gitea:22 tcp://redis:6379?send=PING%0D%0A" traffic -interval 10s
package main

import (
	"context"
	"flag"
	"log"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/traffic"
)

func main() {
	var (
		targets  = flag.String("targets", os.Getenv("TARGETS"), "targets to poke (default $TARGETS)")
		interval = flag.Duration("interval", envDuration("INTERVAL", 10*time.Second), "pause between rounds (default $INTERVAL or 10s)")
		jitter   = flag.Float64("jitter", 0.3, "random +/- fraction applied to the interval")
		timeout  = flag.Duration("timeout", 5*time.Second, "per-probe timeout")
		once     = flag.Bool("once", false, "run a single round and exit")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)
	log.SetPrefix("traffic: ")

	ts, err := traffic.ParseTargets(*targets)
	if err != nil {
		log.Fatalf("%v (set -targets or $TARGETS)", err)
	}
	log.Printf("%d targets, every %v ±%.0f%%", len(ts), *interval, *jitter*100)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := traffic.NewProber(*timeout)
	for {
		for _, t := range ts {
			if ctx.Err() != nil {
				return
			}
			log.Print(p.Probe(ctx, t))
		}
		if *once {
			return
		}
		d := time.Duration(float64(*interval) * (1 + *jitter*(2*rand.Float64()-1)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
