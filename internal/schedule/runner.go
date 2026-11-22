package schedule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// Clock tells the time; tests inject their own.
type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Update is what an Engine reports after each chunk.
type Update struct {
	Record Record
	ETA    time.Duration // estimated scanning time left for this call, 0 = unknown
}

// Engine scans targets.
type Engine interface {
	// Scan scans the targets of a job chunk by chunk, calling report after
	// each chunk (one call at a time). It should not start chunks that
	// cannot finish before the deadline and must stop quickly when ctx is
	// cancelled, without reporting chunks that were cut short. Targets that
	// were not reached are no error; a chunk that failed is reported with
	// Chunk.Error. The error is for problems that make going on pointless.
	Scan(ctx context.Context, j Job, report func(Update)) error
}

// Job is the work of one session.
type Job struct {
	Targets  []string
	Deadline time.Time // when the window closes; zero = never
	// Speed is the time per target measured in earlier sessions of the
	// run, 0 = unknown.
	Speed time.Duration
	// Fruitless counts the sessions before this one that closed without a
	// single finished chunk: the engine should use smaller ones.
	Fruitless int
}

// maxAttempts is how many times a target is tried when its chunk fails.
const maxAttempts = 2

// errWindowClosed is the cancellation cause at the end of a window.
var errWindowClosed = errors.New(stopWindow)

const stopWindow = "window closed" // Session.Stopped

// Runner runs one scheduled scan.
type Runner struct {
	// Targets are all targets of a run. They must already be checked
	// against any allow list: nothing is read back from the checkpoint
	// except which of them are done.
	Targets []string
	// Config describes what is scanned (ports, options). An unfinished run
	// is resumed only if Targets and Config are the same as when it began.
	Config string
	// Settings are recorded in the result.
	Settings result.Settings

	Windows   Windows
	Frequency Frequency
	Engine    Engine
	Store     Store
	Clock     Clock // default: system clock

	// OnResult receives each completed run. It may be called again with the
	// same run after a crash.
	OnResult func(Run, *result.Scan) error
	// Logf, if set, receives progress lines.
	Logf func(format string, args ...any)

	mu     sync.Mutex
	status Status
}

// Status is a snapshot of what a Runner is doing.
type Status struct {
	State   string    `json:"state"` // "waiting", "scanning", "finished"
	Run     *Run      `json:"run,omitempty"`
	Done    int       `json:"done"` // targets finished in this run
	Total   int       `json:"total"`
	NextAt  time.Time `json:"next_at,omitzero"`  // waiting: when scanning starts
	Closes  time.Time `json:"closes,omitzero"`   // scanning: when the window closes
	Expects time.Time `json:"expects,omitzero"`  // scanning: estimated end of the run, across windows
	Session int       `json:"session,omitempty"` // which stretch of the run this is
}

// Status may be called from any goroutine.
func (r *Runner) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *Runner) setStatus(f func(*Status)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(&r.status)
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Runner) clock() Clock {
	if r.Clock == nil {
		return systemClock{}
	}
	return r.Clock
}

// RunKey identifies what a run scans, regardless of target order.
func RunKey(targets []string, config string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n", config)
	for _, t := range slices.Sorted(slices.Values(targets)) {
		fmt.Fprintf(h, "%s\n", t)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Run scans according to the schedule until ctx is cancelled or the
// frequency allows no further run. Progress survives in the Store: calling
// Run again (also in a new process) continues where it stopped.
func (r *Runner) Run(ctx context.Context) error {
	if len(r.Targets) == 0 {
		return errors.New("no targets")
	}
	key := RunKey(r.Targets, r.Config)
	for {
		cp, err := r.Store.Load(ctx)
		if err != nil {
			return err
		}
		if cp != nil && cp.Run.Key != key {
			if cp.FinishedAt.IsZero() {
				r.logf("targets or options changed: dropping unfinished run %s", cp.Run.ID)
			}
			cp = nil
		}
		if cp == nil || !cp.FinishedAt.IsZero() {
			var last time.Time
			if cp != nil {
				last = cp.Run.StartedAt
			}
			due, ok := r.Frequency.Next(last, r.clock().Now())
			if !ok {
				if r.Status().Run == nil { // nothing was done by this call
					r.logf("run %s already finished at %s", cp.Run.ID, cp.FinishedAt.Format(time.RFC3339))
				}
				r.setStatus(func(s *Status) { s.State = "finished" })
				return nil
			}
			if err := r.waitForWindow(ctx, due); err != nil {
				return err
			}
			now := r.clock().Now()
			run := Run{ID: now.UTC().Format("20060102T150405Z"), Key: key, StartedAt: now, Targets: len(r.Targets)}
			if err := r.Store.Begin(ctx, run); err != nil {
				return err
			}
			cp = &Checkpoint{Run: run}
			r.logf("run %s: %d targets", run.ID, len(r.Targets))
		} else {
			r.recoverSession(cp)
			r.logf("resuming run %s: %d of %d targets left", cp.Run.ID, len(r.pending(cp)), len(r.Targets))
		}
		if err := r.finish(ctx, cp); err != nil {
			return err
		}
	}
}

// waitForWindow waits until due and then for a window to be open.
func (r *Runner) waitForWindow(ctx context.Context, due time.Time) error {
	for {
		now := r.clock().Now()
		at := now
		if due.After(now) {
			at = due
		}
		at = r.Windows.Next(at)
		if at.IsZero() {
			return errors.New("no window ever opens")
		}
		if !at.After(now) {
			return ctx.Err()
		}
		r.setStatus(func(s *Status) { s.State, s.NextAt, s.Closes, s.Expects = "waiting", at, time.Time{}, time.Time{} })
		r.logf("next scan at %s", at.Format("2006-01-02 15:04:05 MST"))
		if err := r.waitUntil(ctx, at); err != nil {
			return err
		}
	}
}

// waitUntil sleeps in short steps, so a changed system clock or a suspended
// machine does not move the moment.
func (r *Runner) waitUntil(ctx context.Context, t time.Time) error {
	for {
		d := t.Sub(r.clock().Now())
		if d <= 0 {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.clock().After(min(d, time.Minute)):
		}
	}
}

// pending returns the targets that still have to be scanned.
func (r *Runner) pending(cp *Checkpoint) []string {
	failures := map[string]int{}
	for _, rec := range cp.Records {
		for _, t := range rec.Targets {
			if rec.Chunk.Error == "" {
				failures[t] = maxAttempts
			} else {
				failures[t]++
			}
		}
	}
	var out []string
	for _, t := range r.Targets {
		if failures[t] < maxAttempts {
			out = append(out, t)
		}
	}
	return out
}

// job prepares a session, with what earlier sessions taught.
func (r *Runner) job(cp *Checkpoint, pending []string, closes time.Time) Job {
	j := Job{Targets: pending, Deadline: closes}
	for _, s := range slices.Backward(cp.Sessions) {
		if s.Chunks > 0 {
			break
		}
		if s.Stopped == stopWindow {
			j.Fruitless++
		}
	}
	// The latest chunks say the most; a handful evens out odd ones.
	var took time.Duration
	n, chunks := 0, 0
	for _, rec := range slices.Backward(cp.Records) {
		if rec.Chunk.Error != "" {
			continue
		}
		took += time.Duration(rec.Chunk.Duration)
		n += len(rec.Targets)
		if chunks++; chunks == 8 {
			break
		}
	}
	if n > 0 {
		j.Speed = took / time.Duration(n)
	}
	return j
}

// recoverSession adds the session of a process that died before saving it.
func (r *Runner) recoverSession(cp *Checkpoint) {
	n := 0
	for _, s := range cp.Sessions {
		n += s.Chunks
	}
	if n >= len(cp.Records) {
		return
	}
	lost := result.Session{Stopped: "process died"}
	for _, rec := range cp.Records[n:] {
		end := rec.Chunk.StartedAt.Add(time.Duration(rec.Chunk.Duration))
		if lost.StartedAt.IsZero() || rec.Chunk.StartedAt.Before(lost.StartedAt) {
			lost.StartedAt = rec.Chunk.StartedAt
		}
		if end.After(lost.FinishedAt) {
			lost.FinishedAt = end
		}
		lost.Chunks++
		lost.Targets += len(rec.Targets)
	}
	lost.Duration = result.Duration(lost.FinishedAt.Sub(lost.StartedAt))
	cp.Sessions = append(cp.Sessions, lost)
	if err := r.Store.SaveSession(context.Background(), lost); err != nil {
		r.logf("checkpoint: %v", err)
	}
}

// finish scans what is left of a run, in as many windows as it takes.
func (r *Runner) finish(ctx context.Context, cp *Checkpoint) error {
	for {
		pending := r.pending(cp)
		if len(pending) == 0 {
			break
		}
		if err := r.waitForWindow(ctx, time.Time{}); err != nil {
			return err
		}
		if err := r.session(ctx, cp, pending); err != nil {
			return err
		}
	}
	now := r.clock().Now()
	if r.OnResult != nil {
		if err := r.OnResult(cp.Run, r.assemble(cp, now)); err != nil {
			return fmt.Errorf("run %s: %w", cp.Run.ID, err)
		}
	}
	return r.Store.Finish(ctx, now)
}

// session scans until the run is complete or the window closes.
func (r *Runner) session(ctx context.Context, cp *Checkpoint, pending []string) error {
	start := r.clock().Now()
	closes, open := r.Windows.Open(start)
	if !open {
		return nil
	}
	sctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if !closes.IsZero() {
		go func() {
			if r.waitUntil(sctx, closes) == nil {
				cancel(errWindowClosed)
			}
		}()
	}

	total := len(r.Targets)
	run := cp.Run
	r.setStatus(func(s *Status) {
		*s = Status{State: "scanning", Run: &run, Done: total - len(pending), Total: total,
			Closes: closes, Session: len(cp.Sessions) + 1}
	})
	if closes.IsZero() {
		r.logf("session %d: %d targets", len(cp.Sessions)+1, len(pending))
	} else {
		r.logf("session %d: %d targets, window closes at %s", len(cp.Sessions)+1, len(pending), closes.Format("15:04:05 MST"))
	}

	var saveErr error
	sess := result.Session{StartedAt: start}
	failed := 0
	// Saving must work while the window or the process is closing.
	sctxSave := context.WithoutCancel(ctx)
	err := r.Engine.Scan(sctx, r.job(cp, pending, closes), func(u Update) {
		rec := u.Record
		if saveErr != nil {
			return
		}
		rec.Chunk.Index = len(cp.Records)
		if saveErr = r.Store.SaveRecord(sctxSave, rec); saveErr != nil {
			cancel(saveErr)
			return
		}
		cp.Records = append(cp.Records, rec)
		sess.Chunks++
		sess.Targets += len(rec.Targets)
		if rec.Chunk.Error != "" {
			failed += len(rec.Targets)
		}
		r.setStatus(func(s *Status) {
			s.Done = total - len(pending) + sess.Targets - failed
			if u.ETA > 0 {
				s.Expects = r.Windows.Finish(r.clock().Now(), u.ETA)
			}
		})
	})
	if saveErr != nil {
		return fmt.Errorf("checkpoint: %w", saveErr)
	}

	sess.FinishedAt = r.clock().Now()
	sess.Duration = result.Duration(sess.FinishedAt.Sub(start))
	left := len(r.pending(cp))
	skipped := len(pending) - sess.Targets
	switch {
	case left == 0:
		sess.Stopped = "completed"
	case context.Cause(sctx) == errWindowClosed:
		sess.Stopped = stopWindow
	case ctx.Err() != nil:
		sess.Stopped = "interrupted"
	case err != nil:
		sess.Stopped = "error: " + err.Error()
	case skipped > 0 && !closes.IsZero():
		sess.Stopped = "window closing, next chunk would not fit"
	case skipped > 0:
		sess.Stopped = "engine stopped early"
	default:
		sess.Stopped = "retrying failed chunks"
	}
	cp.Sessions = append(cp.Sessions, sess)
	if serr := r.Store.SaveSession(sctxSave, sess); serr != nil {
		return fmt.Errorf("checkpoint: %w", serr)
	}
	r.logf("session %d: %s after %v, %d chunks, %d/%d targets done", len(cp.Sessions), sess.Stopped,
		time.Duration(sess.Duration).Round(time.Millisecond), sess.Chunks, total-left, total)

	switch {
	case left == 0 || context.Cause(sctx) == errWindowClosed:
		return nil
	case ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		return err
	case skipped > 0 && closes.IsZero():
		return errors.New("engine stopped before all targets were scanned")
	case skipped > 0:
		return r.waitUntil(ctx, closes)
	}
	return nil
}

// assemble merges everything the run recorded into one result.
func (r *Runner) assemble(cp *Checkpoint, now time.Time) *result.Scan {
	out := &result.Scan{StartedAt: cp.Run.StartedAt, FinishedAt: now, Targets: r.Targets,
		Settings: r.Settings, Sessions: cp.Sessions}
	for _, s := range cp.Sessions {
		out.Duration += s.Duration
	}
	for _, rec := range cp.Records {
		out.Chunks = append(out.Chunks, rec.Chunk)
		out.Hosts = append(out.Hosts, rec.Hosts...)
	}
	out.Sort()
	return out
}
