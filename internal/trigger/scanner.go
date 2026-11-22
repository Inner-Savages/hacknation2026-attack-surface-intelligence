package trigger

import (
	"context"
	"strconv"

	"github.com/Inner-Savages/silence-on-the-wire/internal/pipeline"
	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
	"github.com/Inner-Savages/silence-on-the-wire/internal/scan"
)

// PipelineScanner runs jobs through the same pipeline as the scanner CLI.
// Service jobs scan only that port; host jobs scan the most common ports.
// Discovery is skipped (-Pn): the sensor has just seen the address, and an
// unprivileged nmap would only ping ports 80/443 anyway. Whether a host is
// really there is judged from the port answers instead (Host.Responded).
type PipelineScanner struct {
	Base     pipeline.Config // scanner options, signatures, probe settings
	TopPorts int             // for host jobs; default 100
}

// Scan implements Scanner.
func (p *PipelineScanner) Scan(ctx context.Context, j Job) (*result.Scan, error) {
	cfg := p.Base
	opts := cfg.Scanner.Options
	opts.SkipDiscovery = true
	if j.Target.Port != 0 {
		opts.Ports = strconv.Itoa(int(j.Target.Port))
	} else {
		opts.Ports = ""
		opts.TopPorts = p.TopPorts
		if opts.TopPorts == 0 {
			opts.TopPorts = 100
		}
	}
	cfg.Scanner.Options = opts
	cfg.Scanner.ChunkSize, cfg.Scanner.Parallel = 1, 1
	var t scan.Targets
	if err := t.Add(j.Target.IP.String()); err != nil {
		return nil, err
	}
	return cfg.Run(ctx, &t)
}
