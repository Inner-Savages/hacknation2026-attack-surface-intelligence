package schedule

import (
	"testing"
	"time"
)

func warsaw(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skip("no time zone database")
	}
	return loc
}

func at(loc *time.Location, s string) time.Time {
	v, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
	if err != nil {
		panic(err)
	}
	return v
}

func windows(t *testing.T, s string, loc *time.Location) Windows {
	t.Helper()
	w, err := ParseWindows(s, loc)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWindowsOpenAndNext(t *testing.T) {
	loc := warsaw(t)
	// 2026-11-22 is a Sunday.
	for _, c := range []struct{ spec, now, closes, next string }{
		{"22:00-05:00", "2026-11-22 21:59", "", "2026-11-22 22:00"},
		{"22:00-05:00", "2026-11-22 22:00", "2026-11-23 05:00", ""},
		{"22:00-05:00", "2026-11-23 04:59", "2026-11-23 05:00", ""},
		{"22:00-05:00", "2026-11-23 05:00", "", "2026-11-23 22:00"},
		{"08:00-16:00", "2026-11-22 12:00", "2026-11-22 16:00", ""},
		{"08:00-16:00", "2026-11-22 17:00", "", "2026-11-23 08:00"},
		// A window belongs to the day it starts on.
		{"fri 22:00-05:00", "2026-11-21 03:00", "2026-11-21 05:00", ""},
		{"fri 22:00-05:00", "2026-11-22 03:00", "", "2026-11-27 22:00"},
		{"mon-fri 22:00-05:00, sat+sun 00:00-24:00", "2026-11-22 12:00", "2026-11-23 00:00", ""},
		{"fri-mon 01:00-02:00", "2026-11-24 00:00", "", "2026-11-27 01:00"},
		// Overlapping and adjacent windows are one.
		{"22:00-01:00,00:30-05:00,05:00-06:00", "2026-11-22 22:30", "2026-11-23 06:00", ""},
		{"mon 10:00-11:00", "2026-11-23 11:00", "", "2026-11-30 10:00"},
	} {
		w, now := windows(t, c.spec, loc), at(loc, c.now)
		closes, open := w.Open(now)
		if open != (c.closes != "") || open && !closes.Equal(at(loc, c.closes)) {
			t.Errorf("%s at %s: open %v until %v, want %q", c.spec, c.now, open, closes, c.closes)
		}
		if c.next != "" {
			if n := w.Next(now); !n.Equal(at(loc, c.next)) {
				t.Errorf("%s after %s: next %v, want %s", c.spec, c.now, n, c.next)
			}
		}
	}
}

func TestWindowsAlwaysOpen(t *testing.T) {
	for _, spec := range []string{"", "00:00-24:00", "00:00-12:00,12:00-24:00"} {
		w := windows(t, spec, time.UTC)
		now := at(time.UTC, "2026-11-22 13:00")
		if closes, open := w.Open(now); !open || !closes.IsZero() {
			t.Errorf("%q: %v %v", spec, closes, open)
		}
		if !w.Next(now).Equal(now) {
			t.Errorf("%q: next %v", spec, w.Next(now))
		}
	}
}

func TestWindowsFollowTheirTimeZone(t *testing.T) {
	loc := warsaw(t)
	w := windows(t, "22:00-05:00", loc)
	// 21:30 UTC is 22:30 in Warsaw in winter, 23:30 in summer.
	if _, open := w.Open(time.Date(2026, 11, 22, 21, 30, 0, 0, time.UTC)); !open {
		t.Error("window must use its own time zone")
	}
	// Night of the spring change: 22:00-05:00 is an hour shorter.
	closes, open := w.Open(at(loc, "2026-03-28 22:00"))
	if !open || closes.Sub(at(loc, "2026-03-28 22:00")) != 6*time.Hour {
		t.Errorf("DST: open %v, closes %v", open, closes)
	}
}

func TestWindowsFinishSpansWindows(t *testing.T) {
	w := windows(t, "22:00-05:00", time.UTC)
	for _, c := range []struct {
		start, want string
		work        time.Duration
	}{
		{"2026-11-22 22:00", "2026-11-23 03:00", 5 * time.Hour},
		{"2026-11-22 22:00", "2026-11-23 23:00", 8 * time.Hour},
		{"2026-11-22 12:00", "2026-11-24 22:30", 14*time.Hour + 30*time.Minute},
	} {
		if got := w.Finish(at(time.UTC, c.start), c.work); !got.Equal(at(time.UTC, c.want)) {
			t.Errorf("%v from %s: %v, want %s", c.work, c.start, got, c.want)
		}
	}
}

func TestParseWindowsRejects(t *testing.T) {
	for _, s := range []string{"22:00", "22-05", "25:00-26:00", "22:60-23:00", "10:00-10:00", "24:00-05:00",
		"foo 10:00-11:00", "mon-xyz 10:00-11:00", "mon 10:00-11:00 x", "10:00-11:00,", "-1:00-05:00", "10:0-11:00"} {
		if _, err := ParseWindows(s, time.UTC); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestFrequencyNext(t *testing.T) {
	now := at(time.UTC, "2026-11-22 13:00") // Sunday
	for _, c := range []struct{ spec, last, want string }{
		{"", "", "2026-11-22 13:00"},
		{"once", "2026-11-20 10:00", ""},
		{"24h", "", "2026-11-22 13:00"},
		{"24h", "2026-11-22 10:00", "2026-11-23 10:00"},
		{"6h", "2026-11-20 10:00", "2026-11-20 16:00"}, // overdue: one run, not a backlog
		{"daily@22:00", "", "2026-11-22 22:00"},
		{"daily@22:00", "2026-11-22 22:00", "2026-11-23 22:00"},
		{"daily@10:00", "", "2026-11-22 10:00"}, // due today already
		{"daily", "2026-11-22 00:00", "2026-11-23 00:00"},
		{"mon@22:00", "", "2026-11-23 22:00"},
		{"mon+thu@22:00", "2026-11-23 22:00", "2026-11-26 22:00"},
		{"sun@09:00", "2026-11-22 09:00", "2026-11-29 09:00"},
	} {
		f, err := ParseFrequency(c.spec, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		var last time.Time
		if c.last != "" {
			last = at(time.UTC, c.last)
		}
		got, ok := f.Next(last, now)
		if ok != (c.want != "") || ok && !got.Equal(at(time.UTC, c.want)) {
			t.Errorf("%q after %q: %v %v, want %q", c.spec, c.last, got, ok, c.want)
		}
	}
	for _, s := range []string{"1ms", "-1h", "0s", "@22:00", "daily@25:00", "daily@24:00", "often", "mon@"} {
		if _, err := ParseFrequency(s, time.UTC); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
