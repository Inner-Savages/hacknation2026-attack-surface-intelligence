package scan

import (
	"fmt"
	"time"
)

// Defaults for adaptive chunking.
const (
	DefaultMinChunk = 4
	DefaultMaxChunk = 4096
	// fixedChunk is the chunk size without adaptive chunking.
	fixedChunk = 256
	// firstChunk is the probing size of an adaptive scan: small enough to
	// learn the speed soon.
	firstChunk = 32
	// maxStep bounds how much larger than the largest measured chunk the
	// next one may be, so one lucky (empty) chunk does not cause a huge jump.
	maxStep = 4
)

// planner decides how many targets the next chunk gets. It is not safe for
// concurrent use; Scanner guards it.
type planner struct {
	size     int           // the fixed size, or the limit until the speed is measured
	target   time.Duration // duration chunks aim for; 0 = fixed size
	min, max int
	parallel int

	perTarget float64 // smoothed seconds of one worker per target, 0 = unknown
	measured  bool    // perTarget comes from this scan, not from a rate limit or an earlier one
	largest   int     // largest chunk measured so far
	handed    int     // targets handed out so far
}

// next returns the size of the next chunk and why. remaining is the number
// of targets not handed out yet, left the time until the soft deadline.
// Size 0 means nothing more fits before it.
func (p *planner) next(remaining int, left time.Duration, hasDeadline bool) (int, string) {
	n, why := p.plan(remaining, left, hasDeadline)
	n = min(n, remaining)
	p.handed += n
	return n, why
}

func (p *planner) plan(remaining int, left time.Duration, hasDeadline bool) (int, string) {
	if remaining <= 0 {
		return 0, ""
	}
	if hasDeadline && left <= 0 {
		return 0, "window closed"
	}
	if p.target <= 0 {
		if remaining < p.size {
			return remaining, "fixed, last"
		}
		return p.size, "fixed"
	}
	n, why := p.size, "first, speed unknown"
	if p.perTarget > 0 {
		want := max(1, int(p.target.Seconds()/p.perTarget))
		limit := p.size
		if p.largest > 0 {
			limit = p.largest * maxStep
		}
		n = min(want, limit)
		// The minimum applies to measured speeds only: an expectation that asks
		// for less comes from a rate limit that leaves no other way.
		if p.measured {
			n = max(p.min, min(n, p.max))
		}
		why = fmt.Sprintf("%.3gs/target", p.perTarget)
		if !p.measured {
			why += " expected"
		}
		why += fmt.Sprintf(", aiming for %v", p.target)
		if n != want {
			why += fmt.Sprintf(", %d limited to %d", want, n)
		}
		if hasDeadline {
			fits := int(left.Seconds() / p.perTarget)
			if fits < 1 {
				// Try at least one target per window, or a scan slower than
				// expected would never get anywhere.
				if p.handed > 0 {
					return 0, "window closed"
				}
				fits = 1
			}
			if fits < n {
				n, why = fits, fmt.Sprintf("%.3gs/target, window closes in %v", p.perTarget, left.Round(time.Second))
			}
		}
	}
	// Share the tail between the workers instead of leaving one of them
	// with a full-size last chunk.
	if share := max(p.min, (remaining+p.parallel-1)/p.parallel); share < n {
		n, why = share, "tail shared between workers"
	}
	return n, why
}

// done learns from a finished chunk.
func (p *planner) done(targets int, d time.Duration) {
	if targets <= 0 || d <= 0 {
		return
	}
	per := d.Seconds() / float64(targets)
	if !p.measured {
		p.perTarget, p.measured = per, true
	} else {
		p.perTarget = 0.6*p.perTarget + 0.4*per
	}
	p.largest = max(p.largest, targets)
}

// eta estimates the time to finish the given number of targets, 0 while the
// speed is unknown.
func (p *planner) eta(targets int) time.Duration {
	if p.perTarget == 0 || targets <= 0 {
		return 0
	}
	return time.Duration(p.perTarget * float64(targets) / float64(p.parallel) * float64(time.Second))
}
