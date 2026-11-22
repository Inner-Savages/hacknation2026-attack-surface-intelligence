// Package trigger turns passive sensor events into targeted active scans.
// The policy here is pure (time is passed in) so every rule is testable:
//
//   - which events lead to which kind of scan,
//   - an allow list: nothing outside it is ever scanned,
//   - the scanner's own addresses are ignored (its traffic makes the sensor
//     report the scanning host itself),
//   - debounce: events for one target within a few seconds become one scan,
//   - quiet window: events for a target while it is being scanned and shortly
//     after are dropped, because the scan itself causes them (new ports seen
//     in SYN-ACKs, different responses to probe paths),
//   - cooldown: later events postpone the next scan of that target instead
//     of starting one right away (longer after "closed", which is already
//     hard evidence),
//   - a global rate limit and a cap on pending jobs.
package trigger

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/sensor"
)

// Kind of scan a job asks for.
type Kind string

const (
	ScanService   Kind = "scan-service"   // something new or changed on a port: scan that port
	ScanHost      Kind = "scan-host"      // a new or returning host: scan its common ports
	VerifyService Kind = "verify-service" // the port went quiet or closed: is it really gone?
	VerifyHost    Kind = "verify-host"    // the host went quiet: is it really down?
)

// Target is what a job scans: a host (Port 0) or one port.
type Target struct {
	IP   netip.Addr `json:"ip"`
	Port uint16     `json:"port,omitempty"`
}

func (t Target) String() string {
	if t.Port == 0 {
		return t.IP.String()
	}
	return fmt.Sprintf("%s:%d", t.IP, t.Port)
}

// Job is a scan waiting to run.
type Job struct {
	Target Target         `json:"target"`
	Kind   Kind           `json:"kind"`
	Events []sensor.Event `json:"events"` // what caused it, oldest first
	Due    time.Time      `json:"due"`
	Score  float64        `json:"score,omitempty"`  // highest score among the events
	Reason string         `json:"reason,omitempty"` // reason of that event
	closed bool           // only service_closed so far: longer cooldown
}

// Policy decides when to scan. Not safe for concurrent use; the service
// guards it with a mutex.
type Policy struct {
	Allow          []netip.Prefix // required: targets outside are never scanned
	Self           []netip.Addr   // our own addresses: events about them are ignored
	Debounce       time.Duration  // default 5s
	Quiet          time.Duration  // default 15s after a scan of the target ends
	Cooldown       time.Duration  // default 60s between scans of one target
	ClosedCooldown time.Duration  // default 5m when only "closed" events arrived
	MaxPerMinute   int            // default 10 scans started per minute
	MaxPending     int            // default 1000 waiting jobs
	// VerifyBackoff: after a verification found the target alive, further
	// "it went quiet" events for it are ignored this long (default 30m).
	// Otherwise a host nobody talks to is re-verified forever: the scan
	// wakes it up, a minute later it is silent again.
	VerifyBackoff time.Duration

	pending  map[Target]*Job
	running  map[Target]bool
	lastEnd  map[Target]time.Time     // per target: cooldown
	busyIP   map[netip.Addr]int       // scans in progress per address: quiet
	quietIP  map[netip.Addr]time.Time // last scan end per address: quiet
	aliveAt  map[Target]time.Time     // verified alive: skip silence checks
	started  []time.Time
	Counters map[string]int // accepted, and drop reasons
}

func (p *Policy) init() {
	if p.pending == nil {
		p.pending = map[Target]*Job{}
		p.running = map[Target]bool{}
		p.lastEnd = map[Target]time.Time{}
		p.busyIP = map[netip.Addr]int{}
		p.quietIP = map[netip.Addr]time.Time{}
		p.aliveAt = map[Target]time.Time{}
		p.Counters = map[string]int{}
	}
}

func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// kindFor maps a sensor event to a scan.
func kindFor(e sensor.Event) (Kind, Target, bool) {
	host := Target{IP: e.IP}
	svc := Target{IP: e.IP, Port: e.Port}
	switch e.Type {
	case sensor.ServiceNew, sensor.ServiceChanged, sensor.ServiceBack:
		return ScanService, svc, true
	case sensor.HostNew, sensor.HostBack:
		return ScanHost, host, true
	case sensor.ServiceSilent, sensor.ServiceClosed:
		return VerifyService, svc, true
	case sensor.HostSilent:
		return VerifyHost, host, true
	}
	return "", Target{}, false
}

// Offer considers one event. It returns false and a reason when the event
// does not lead to a scan.
func (p *Policy) Offer(e sensor.Event, now time.Time) (bool, string) {
	p.init()
	kind, t, ok := kindFor(e)
	if !ok {
		return p.drop("unknown event type")
	}
	if !t.IP.IsValid() || !p.allowed(t.IP) {
		return p.drop("outside allow list")
	}
	for _, a := range p.Self {
		if a == t.IP {
			return p.drop("scanner's own address")
		}
	}
	// Quiet is per address: scanning one port also wakes the host up in the
	// sensor's eyes, and a host scan finds ports the sensor never saw.
	if p.busyIP[t.IP] > 0 {
		return p.drop("quiet: address is being scanned")
	}
	if end, ok := p.quietIP[t.IP]; ok && now.Sub(end) < or(p.Quiet, 15*time.Second) {
		return p.drop("quiet: address just scanned")
	}
	if kind == VerifyService || kind == VerifyHost {
		if at, ok := p.aliveAt[t]; ok && now.Sub(at) < or(p.VerifyBackoff, 30*time.Minute) {
			return p.drop("verified alive recently")
		}
	}

	// A pending host scan covers every port of that host: let service
	// events ride along instead of queueing a second scan.
	if t.Port != 0 {
		if hj := p.pending[Target{IP: t.IP}]; hj != nil && (hj.Kind == ScanHost || kind == VerifyService) {
			hj.Events = append(hj.Events, e)
			hj.rate(e)
			p.Counters["accepted"]++
			return true, ""
		}
	}
	job := p.pending[t]
	if job == nil {
		if len(p.pending) >= or(p.MaxPending, 1000) {
			return p.drop("too many pending jobs")
		}
		job = &Job{Target: t, closed: true}
		p.pending[t] = job
	}
	job.Kind = kind // the latest event describes the current state
	job.Events = append(job.Events, e)
	job.rate(e)
	if e.Type != sensor.ServiceClosed {
		job.closed = false
	}
	due := now.Add(or(p.Debounce, 5*time.Second))
	if end, ok := p.lastEnd[t]; ok {
		cd := or(p.Cooldown, time.Minute)
		if job.closed {
			cd = or(p.ClosedCooldown, 5*time.Minute)
		}
		if after := end.Add(cd); after.After(due) {
			due = after
		}
	}
	// Recomputed from scratch on every event: the latest event pushes the
	// debounce forward, and the cooldown depends on what the events say now
	// (a service_back after service_closed shortens it again).
	job.Due = due
	p.Counters["accepted"]++
	return true, ""
}

// rate keeps the highest score seen among a job's events.
func (j *Job) rate(e sensor.Event) {
	if e.Score > j.Score {
		j.Score, j.Reason = e.Score, e.Reason
	}
}

func (p *Policy) drop(reason string) (bool, string) {
	p.Counters["dropped: "+reason]++
	return false, reason
}

func (p *Policy) allowed(a netip.Addr) bool {
	for _, pr := range p.Allow {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

// Take returns up to free jobs that are due, oldest first, within the rate
// limit, and marks their targets as running.
func (p *Policy) Take(now time.Time, free int) []Job {
	p.init()
	minute := now.Add(-time.Minute)
	kept := p.started[:0]
	for _, t := range p.started {
		if t.After(minute) {
			kept = append(kept, t)
		}
	}
	p.started = kept
	budget := min(free, or(p.MaxPerMinute, 10)-len(p.started))

	var due []*Job
	for _, j := range p.pending {
		if !j.Due.After(now) && !p.running[j.Target] {
			due = append(due, j)
		}
	}
	// With a limited budget the most interesting jobs go first; unrated
	// jobs (score 0) keep their order by due time.
	sort.Slice(due, func(i, k int) bool {
		if due[i].Score != due[k].Score {
			return due[i].Score > due[k].Score
		}
		if !due[i].Due.Equal(due[k].Due) {
			return due[i].Due.Before(due[k].Due)
		}
		return due[i].Target.String() < due[k].Target.String()
	})
	var out []Job
	for _, j := range due {
		if len(out) >= budget {
			break
		}
		delete(p.pending, j.Target)
		p.running[j.Target] = true
		p.busyIP[j.Target.IP]++
		p.started = append(p.started, now)
		out = append(out, *j)
	}
	return out
}

// Done records that a target's scan finished. alive is true when a
// verification found the target still there.
func (p *Policy) Done(t Target, now time.Time, alive bool) {
	p.init()
	if alive {
		p.aliveAt[t] = now
	} else {
		delete(p.aliveAt, t)
	}
	if p.running[t] {
		delete(p.running, t)
		if p.busyIP[t.IP]--; p.busyIP[t.IP] <= 0 {
			delete(p.busyIP, t.IP)
		}
	}
	p.lastEnd[t] = now
	p.quietIP[t.IP] = now
}

// Pending returns the number of waiting jobs.
func (p *Policy) Pending() int { return len(p.pending) }

// Running returns the number of scans in progress.
func (p *Policy) Running() int { return len(p.running) }
