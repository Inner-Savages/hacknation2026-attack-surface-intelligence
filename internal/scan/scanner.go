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
	Options  Options
	Parallel int // concurrent nmap processes; default 4

	// ChunkSize is the number of targets per nmap process: of every chunk
	// (default 256), or only of the first ones (default 32) when
	// ChunkTarget makes chunking adaptive.
	ChunkSize int
	// ChunkTarget sizes chunks so that each takes about this long, judging
	// by the chunks finished so far. 0 keeps the size fixed.
	ChunkTarget time.Duration
	// MinChunk and MaxChunk bound adaptive chunk sizes (default 8 and 4096).
	MinChunk, MaxChunk int

	// Deadline, if set, is a soft limit: no chunk is started after it, and
	// adaptive chunks are sized to finish before it. Cancel the context to
	// stop chunks already running.
	Deadline time.Time

	// Speed, if set, is the time one worker needs per target as measured
	// earlier (e.g. in a previous window). Without it adaptive chunking
	// starts from an estimate based on the ports and Options.MaxRate.
	Speed time.Duration
	// Shrink halves the size of the first chunks this many times; for
	// retrying after a window that was too short for a single chunk.
	Shrink int

	// Post, if set, processes the hosts of a chunk (HTTP probes,
	// signatures) before the chunk counts as finished. Up to Parallel
	// chunks are processed at the same time.
	Post func(ctx context.Context, hosts []result.Host)
	// Progress, if set, is called after each chunk, one call at a time.
	Progress func(Progress)

	now func() time.Time // for tests
}

// Progress describes a finished chunk and the state of the whole scan.
type Progress struct {
	Chunk   result.Chunk
	Targets []string      // the targets of the chunk
	Hosts   []result.Host // what was found on them
	Done    int           // targets finished so far (successfully or not)
	Total   int
	Elapsed time.Duration
	ETA     time.Duration // estimated time left, 0 = unknown
}

// Scan scans all targets and merges the hosts into one result. A failing
// chunk is recorded in Chunks and does not abort the others. Chunks cut
// short by the context, or never started because of Deadline, are not
// recorded at all; the context error is returned with the partial result,
// and ErrDeadline when the deadline left targets unscanned.
func (s *Scanner) Scan(ctx context.Context, t *Targets) (*result.Scan, error) {
	if t.Len() == 0 {
		return nil, ErrNoTargets
	}
	if err := s.Options.Validate(); err != nil {
		return nil, err
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	p := s.planner()
	probeDB, cleanup, err := s.Options.tunedProbeDB()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	items := t.Items()
	out := &result.Scan{StartedAt: now(), Targets: items, Settings: s.settings(p)}

	var mu sync.Mutex // guards everything below and the planner
	var next, index, done int
	take := func() (int, []string, string) {
		mu.Lock()
		defer mu.Unlock()
		var left time.Duration
		if !s.Deadline.IsZero() {
			left = s.Deadline.Sub(now())
		}
		n, why := p.next(len(items)-next, left, !s.Deadline.IsZero())
		if n == 0 {
			return 0, nil, ""
		}
		chunk := items[next : next+n]
		next += n
		index++
		return index - 1, chunk, why
	}

	var wg sync.WaitGroup
	for range p.parallel {
		wg.Go(func() {
			for ctx.Err() == nil {
				i, targets, why := take()
				if len(targets) == 0 {
					return
				}
				start := now()
				hosts, retried, err := scanChunk(ctx, s.Options, probeDB, targets)
				if err == nil && s.Post != nil {
					s.Post(ctx, hosts)
				}
				if ctx.Err() != nil {
					return // cut short: whoever resumes scans it again
				}
				d := now().Sub(start)
				c := result.Chunk{Index: i, Targets: len(targets), StartedAt: start,
					Duration: result.Duration(d), Reason: why, Retried: retried}
				if err != nil {
					c.Error = err.Error()
				}
				for _, h := range hosts {
					if h.State == "up" {
						c.HostsUp++
					}
				}

				mu.Lock()
				if err == nil {
					p.done(len(targets), d)
				}
				out.Hosts = append(out.Hosts, hosts...)
				out.Chunks = append(out.Chunks, c)
				done += len(targets)
				if s.Progress != nil {
					s.Progress(Progress{Chunk: c, Targets: targets, Hosts: hosts, Done: done, Total: len(items),
						Elapsed: now().Sub(out.StartedAt), ETA: p.eta(len(items) - done)})
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	out.FinishedAt = now()
	out.Duration = result.Duration(out.FinishedAt.Sub(out.StartedAt))
	out.Sort()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if done < len(items) {
		return out, ErrDeadline
	}
	return out, nil
}

func (s *Scanner) planner() *planner {
	p := &planner{size: s.ChunkSize, target: s.ChunkTarget, min: s.MinChunk, max: s.MaxChunk, parallel: s.Parallel}
	if p.parallel <= 0 {
		p.parallel = 4
	}
	shrink := func() {
		for range s.Shrink {
			p.size = max(1, p.size/2)
		}
	}
	if p.target <= 0 {
		p.target = 0
		if p.size <= 0 {
			p.size = fixedChunk
		}
		shrink()
		return p
	}
	if p.min <= 0 {
		p.min = DefaultMinChunk
	}
	if p.max <= 0 {
		p.max = DefaultMaxChunk
	}
	p.max = max(p.max, p.min)
	if p.size <= 0 {
		p.size = firstChunk
	}
	p.size = min(p.size, p.max)
	if s.Speed > 0 {
		p.perTarget = s.Speed.Seconds()
	} else {
		p.perTarget = s.Options.estimate().Seconds()
	}
	shrink()
	return p
}

func (s *Scanner) settings(p *planner) result.Settings {
	set := result.Settings{NmapArgs: s.Options.Args(), ChunkSize: p.size, Parallel: p.parallel,
		VersionMode: string(s.Options.versionMode())}
	if p.target > 0 {
		set.ChunkTarget, set.ChunkMin, set.ChunkMax = result.Duration(p.target), p.min, p.max
	}
	if s.Options.versionMode() != VersionFull {
		set.VersionWait = result.Duration(s.Options.versionWait())
	}
	return set
}

// Settings returns what a scan with this configuration records in its
// result.
func (s *Scanner) Settings() result.Settings { return s.settings(s.planner()) }
