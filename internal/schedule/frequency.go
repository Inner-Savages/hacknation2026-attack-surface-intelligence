package schedule

import (
	"fmt"
	"strings"
	"time"
)

// Frequency says how often a scan starts. The zero value is "once".
type Frequency struct {
	every time.Duration
	at    int // minutes since midnight
	days  uint8
	loc   *time.Location
}

// minInterval guards against schedules that would scan non-stop by mistake.
const minInterval = time.Second

// ParseFrequency parses how often to scan:
//
//	once (or empty)
//	24h, 90m                interval between the starts of two scans
//	daily, daily@22:00      every day
//	mon@22:00, mon-fri@22:00, mon+thu
//
// Without a time the scan is due at midnight, so it starts when the first
// window of the day opens. A nil location means local time.
func ParseFrequency(s string, loc *time.Location) (Frequency, error) {
	if loc == nil {
		loc = time.Local
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "once" {
		return Frequency{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d < minInterval {
			return Frequency{}, fmt.Errorf("frequency %q: at least %v", s, minInterval)
		}
		return Frequency{every: d}, nil
	}
	f := Frequency{loc: loc, days: allDays}
	days, at, hasAt := strings.Cut(s, "@")
	var err error
	if days != "daily" {
		if days == "" {
			return Frequency{}, fmt.Errorf("frequency %q: use 24h, daily@22:00 or mon+thu@22:00", s)
		}
		if f.days, err = parseDays(days); err != nil {
			return Frequency{}, fmt.Errorf("frequency %q: use 24h, daily@22:00 or mon+thu@22:00", s)
		}
	}
	if hasAt {
		if f.at, err = parseClock(at); err != nil || f.at == 1440 {
			return Frequency{}, fmt.Errorf("frequency %q: bad time %q", s, at)
		}
	}
	return f, nil
}

// Once reports whether the scan runs a single time.
func (f Frequency) Once() bool { return f.every == 0 && f.days == 0 }

// Next returns when the next scan is due after one that started at last
// (zero = never scanned, which is due at once unless the frequency names a
// time of day). ok is false when there is nothing more to run.
//
// Starts missed while a long scan was running are skipped, not queued: the
// result may be in the past, and then the scan is simply overdue.
func (f Frequency) Next(last, now time.Time) (due time.Time, ok bool) {
	switch {
	case last.IsZero() && (f.Once() || f.every > 0):
		return now, true
	case f.Once():
		return time.Time{}, false
	case f.every > 0:
		return last.Add(f.every), true
	}
	from := last
	if last.IsZero() {
		// Due today even if the moment has passed: the window decides.
		y, m, d := now.In(f.loc).Date()
		from = time.Date(y, m, d, 0, 0, 0, 0, f.loc).Add(-time.Nanosecond)
	}
	y, m, d := from.In(f.loc).Date()
	for shift := 0; shift <= 8; shift++ {
		t := time.Date(y, m, d+shift, f.at/60, f.at%60, 0, 0, f.loc)
		if t.After(from) && f.days&(1<<t.Weekday()) != 0 {
			return t, true
		}
	}
	return time.Time{}, false
}
