// Package pipeline is the full active scan: nmap discovery and service
// detection, then the HTTP prober, then signature fingerprinting. Both the
// scanner CLI and the trigger service run exactly this.
package pipeline

import (
	"context"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/fingerprint"
	"github.com/Inner-Savages/silence-on-the-wire/internal/probe"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
)

// Config describes one kind of scan. A zero Config with an Engine set
// scans with nmap defaults, probes and fingerprints.
type Config struct {
	Scanner              scan.Scanner
	SkipProbe            bool
	ProbeParallel        int           // default 8
	ProbeTimeout         time.Duration // default 10s
	SkipFingerprint      bool
	SkipFingerprintPaths bool
	Engine               *fingerprint.Engine // required unless SkipFingerprint
	// Logf, if set, receives progress lines.
	Logf func(format string, args ...any)
}

func (c *Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Run scans the targets. Every chunk is probed and fingerprinted before it
// counts as finished, so whatever an interrupted scan returns is complete
// for the targets it covers. On interruption it returns that partial result
// together with the error.
func (c *Config) Run(ctx context.Context, t *scan.Targets) (*result.Scan, error) {
	s := c.Scanner
	par := c.ProbeParallel
	if par <= 0 {
		par = 8
	}
	prober := &probe.Prober{Timeout: c.ProbeTimeout}
	fp := !c.SkipFingerprint && c.Engine != nil
	// Chunks take turns, so ProbeParallel bounds the whole scan.
	var mu sync.Mutex
	var probed int
	var probeTime, fpTime time.Duration
	if !c.SkipProbe || fp {
		s.Post = func(ctx context.Context, hosts []result.Host) {
			mu.Lock()
			defer mu.Unlock()
			part := &result.Scan{Hosts: hosts}
			if !c.SkipProbe {
				start := time.Now()
				probed += prober.ProbeScan(ctx, part, par)
				probeTime += time.Since(start)
			}
			if fp && ctx.Err() == nil {
				start := time.Now()
				var fetcher fingerprint.Fetcher
				if !c.SkipProbe && !c.SkipFingerprintPaths {
					fetcher = prober
				}
				c.Engine.Run(ctx, part, fetcher, par)
				fpTime += time.Since(start)
			}
		}
	}
	res, err := s.Scan(ctx, t)
	if res == nil {
		return nil, err
	}
	if !c.SkipProbe {
		c.logf("probed %d web services in %v", probed, probeTime.Round(time.Millisecond))
	}
	if fp {
		c.logf("fingerprinted in %v", fpTime.Round(time.Millisecond))
	}
	return res, err
}

// Counts returns hosts up and open services.
func Counts(s *result.Scan) (up, open int) {
	for _, h := range s.Hosts {
		if h.State == "up" {
			up++
		}
		for _, svc := range h.Services {
			if svc.State == "open" {
				open++
			}
		}
	}
	return up, open
}
