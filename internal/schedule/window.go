// Package schedule decides when scans run and keeps long scans inside their
// time windows: a scan cut off when its window closes resumes in the next
// one with only the targets that are left.
//
// Runner is the entry point. It knows nothing about nmap: it drives an
// Engine, reads the time from a Clock and keeps its progress in a Store, so
// each of them can be replaced (a server may keep checkpoints in a database).
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Window is a daily time span, e.g. 22:00-05:00. A span that ends at or
// before its start crosses midnight and belongs to the day it starts on.
type Window struct {
	start, end int // minutes since midnight; end may be 1440
	days       uint8
}

const allDays = 1<<7 - 1

// Windows is a set of time spans in one time zone. Without spans it is
// always open.
type Windows struct {
	list []Window
	loc  *time.Location
}

// ParseWindows parses comma-separated windows with optional weekdays:
//
//	22:00-05:00
//	mon-fri 22:00-05:00, sat+sun 00:00-24:00
//
// An empty string is always open. A nil location means local time.
func ParseWindows(s string, loc *time.Location) (Windows, error) {
	if loc == nil {
		loc = time.Local
	}
	w := Windows{loc: loc}
	if strings.TrimSpace(s) == "" {
		return w, nil
	}
	for _, part := range strings.Split(s, ",") {
		f := strings.Fields(part)
		days, span := "", ""
		switch len(f) {
		case 1:
			span = f[0]
		case 2:
			days, span = f[0], f[1]
		default:
			return Windows{}, fmt.Errorf("window %q: use [days] HH:MM-HH:MM", strings.TrimSpace(part))
		}
		from, to, ok := strings.Cut(span, "-")
		if !ok {
			return Windows{}, fmt.Errorf("window %q: use HH:MM-HH:MM", span)
		}
		var v Window
		var err error
		if v.start, err = parseClock(from); err != nil {
			return Windows{}, fmt.Errorf("window %q: %w", span, err)
		}
		if v.end, err = parseClock(to); err != nil {
			return Windows{}, fmt.Errorf("window %q: %w", span, err)
		}
		if v.start == 1440 {
			return Windows{}, fmt.Errorf("window %q: 24:00 is only valid as an end", span)
		}
		if v.start == v.end {
			return Windows{}, fmt.Errorf("window %q is empty; use 00:00-24:00 for a whole day", span)
		}
		if v.days, err = parseDays(days); err != nil {
			return Windows{}, fmt.Errorf("window %q: %w", strings.TrimSpace(part), err)
		}
		w.list = append(w.list, v)
	}
	return w, nil
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || len(m) != 2 || hh < 0 || mm < 0 || mm > 59 || hh*60+mm > 1440 {
		return 0, fmt.Errorf("time %q: use HH:MM", s)
	}
	return hh*60 + mm, nil
}

var dayNames = map[string]time.Weekday{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

// parseDays parses "mon", "mon-fri", "sat+sun" into a bit set; empty is
// every day.
func parseDays(s string) (uint8, error) {
	if s == "" {
		return allDays, nil
	}
	var set uint8
	for _, part := range strings.Split(strings.ToLower(s), "+") {
		from, to, isRange := strings.Cut(part, "-")
		a, ok := dayNames[from]
		if !ok {
			return 0, fmt.Errorf("day %q: use mon, tue, ... or ranges like mon-fri", from)
		}
		b := a
		if isRange {
			if b, ok = dayNames[to]; !ok {
				return 0, fmt.Errorf("day %q: use mon, tue, ... or ranges like mon-fri", to)
			}
		}
		for d := a; ; d = (d + 1) % 7 {
			set |= 1 << d
			if d == b {
				break
			}
		}
	}
	return set, nil
}

// span returns the window that starts on t's day, shifted by days.
// time.Date normalizes the date and follows daylight saving changes.
func (w Windows) span(v Window, t time.Time, shift int) (from, to time.Time, ok bool) {
	y, m, d := t.In(w.loc).Date()
	from = time.Date(y, m, d+shift, v.start/60, v.start%60, 0, 0, w.loc)
	if v.days&(1<<time.Date(y, m, d+shift, 12, 0, 0, 0, w.loc).Weekday()) == 0 {
		return from, from, false
	}
	endDay := d + shift
	if v.end <= v.start {
		endDay++
	}
	to = time.Date(y, m, endDay, v.end/60, v.end%60, 0, 0, w.loc)
	return from, to, to.After(from)
}

// Always reports whether there is no restriction.
func (w Windows) Always() bool { return len(w.list) == 0 }

// Open reports whether t is inside a window and when it closes. Overlapping
// and adjacent windows count as one. The closing time is zero when the
// schedule never closes.
func (w Windows) Open(t time.Time) (closes time.Time, open bool) {
	if w.Always() {
		return time.Time{}, true
	}
	at := t
	for range 8*len(w.list) + 1 { // a week of back-to-back windows
		end, ok := w.closing(at)
		if !ok {
			break
		}
		closes, open, at = end, true, end
		if closes.Sub(t) > 7*24*time.Hour {
			return time.Time{}, true
		}
	}
	return closes, open
}

// closing returns the latest end of the windows containing t.
func (w Windows) closing(t time.Time) (end time.Time, ok bool) {
	for _, v := range w.list {
		for shift := -1; shift <= 0; shift++ {
			from, to, valid := w.span(v, t, shift)
			if valid && !t.Before(from) && t.Before(to) && to.After(end) {
				end, ok = to, true
			}
		}
	}
	return end, ok
}

// Next returns the first moment at or after t inside a window.
func (w Windows) Next(t time.Time) time.Time {
	if _, open := w.Open(t); open {
		return t
	}
	var best time.Time
	for _, v := range w.list {
		for shift := 0; shift <= 8; shift++ {
			from, _, valid := w.span(v, t, shift)
			if valid && !from.Before(t) && (best.IsZero() || from.Before(best)) {
				best = from
			}
		}
	}
	return best
}

// Finish returns when work that needs the given scanning time would be done
// if it started at t and paused outside the windows.
func (w Windows) Finish(t time.Time, work time.Duration) time.Time {
	for range 10000 {
		t = w.Next(t)
		closes, _ := w.Open(t)
		if closes.IsZero() || closes.Sub(t) >= work {
			return t.Add(work)
		}
		work -= closes.Sub(t)
		t = closes
	}
	return time.Time{} // years away
}
