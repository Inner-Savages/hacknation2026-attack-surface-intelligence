// Package pipeline is the full active scan: nmap discovery and service
// detection, then the HTTP prober, then signature fingerprinting. Both the
// scanner CLI and the trigger service run exactly this.
package pipeline

import (
	"context"
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

// Run scans the targets. On interruption it returns the partial result
// together with the context error.
func (c *Config) Run(ctx context.Context, t *scan.Targets) (*result.Scan, error) {
	res, err := c.Scanner.Scan(ctx, t)
	if res == nil || ctx.Err() != nil {
		return res, err
	}
	par := c.ProbeParallel
	if par <= 0 {
		par = 8
	}
	prober := &probe.Prober{Timeout: c.ProbeTimeout}
	if !c.SkipProbe {
		start := time.Now()
		n := prober.ProbeScan(ctx, res, par)
		c.logf("probed %d web services in %v", n, time.Since(start).Round(time.Millisecond))
	}
	if !c.SkipFingerprint && c.Engine != nil && ctx.Err() == nil {
		start := time.Now()
		var fetcher fingerprint.Fetcher
		if !c.SkipProbe && !c.SkipFingerprintPaths {
			fetcher = prober
		}
		c.Engine.Run(ctx, res, fetcher, par)
		c.logf("fingerprinted in %v", time.Since(start).Round(time.Millisecond))
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
