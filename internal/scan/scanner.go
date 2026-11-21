package scan

import (
	"context"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Scanner splits targets into chunks and runs several nmap processes at
// once. Total load stays bounded: Parallel processes, each capped by
// Options.MaxRate.
type Scanner struct {
	Options   Options
	ChunkSize int // targets per nmap process; default 256
	Parallel  int // concurrent nmap processes; default 4
	// Progress, if set, is called after each chunk finishes.
	Progress func(done, total int, c result.Chunk)
}

// Scan runs all chunks and merges their hosts into one result. A failing
// chunk is recorded in Chunks and does not abort the others.
func (s *Scanner) Scan(ctx context.Context, t *Targets) (*result.Scan, error) {
	if t.Len() == 0 {
		return nil, ErrNoTargets
	}
	if err := s.Options.Validate(); err != nil {
		return nil, err
	}
	size, par := s.ChunkSize, s.Parallel
	if size <= 0 {
		size = 256
	}
	if par <= 0 {
		par = 4
	}

	out := &result.Scan{
		StartedAt: time.Now(),
		Targets:   t.Items(),
		Settings:  result.Settings{NmapArgs: s.Options.Args(), ChunkSize: size, Parallel: par},
	}
	chunks := t.Chunks(size)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, par)
	done := 0
	for i, c := range chunks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			start := time.Now()
			hosts, err := RunChunk(ctx, s.Options, c)
			stat := result.Chunk{Index: i, Targets: len(c), Duration: result.Duration(time.Since(start))}
			if err != nil {
				stat.Error = err.Error()
			}
			for _, h := range hosts {
				if h.State == "up" {
					stat.HostsUp++
				}
			}

			mu.Lock()
			defer mu.Unlock()
			out.Hosts = append(out.Hosts, hosts...)
			out.Chunks = append(out.Chunks, stat)
			done++
			if s.Progress != nil {
				s.Progress(done, len(chunks), stat)
			}
		}()
	}
	wg.Wait()

	out.FinishedAt = time.Now()
	out.Duration = result.Duration(out.FinishedAt.Sub(out.StartedAt))
	out.Sort()
	return out, ctx.Err()
}
