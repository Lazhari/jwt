// Package timeparse parses human-friendly durations and timestamps used by
// JWT time claims, and formats durations for display.
package timeparse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// unitRE matches the short forms documented in the README: 7d, 2h, 30m,
// 30min, 45s, 45sec. Anything else falls through to time.ParseDuration.
var unitRE = regexp.MustCompile(`^(\d+)(d|h|m|min|s|sec)$`)

// Duration parses a positive duration. Accepted forms: "7d", "2h", "30m",
// "30min", "45s", "45sec", and any Go duration such as "1h30m" or "1.5h".
func Duration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if m := unitRE.FindStringSubmatch(s); m != nil {
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		switch m[2] {
		case "d":
			return time.Duration(n) * 24 * time.Hour, nil
		case "h":
			return time.Duration(n) * time.Hour, nil
		case "m", "min":
			return time.Duration(n) * time.Minute, nil
		default: // s, sec
			return time.Duration(n) * time.Second, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q: use forms like 7d, 2h, 30m, 45s, or 1h30m", s)
	}
	return d, nil
}

// At resolves a point in time. Accepted forms: "now", a relative offset such
// as "+1h" or "-30m" (relative to now), a Unix timestamp in seconds, or an
// RFC 3339 timestamp. The result is in UTC.
func At(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return time.Time{}, fmt.Errorf("empty time")
	case s == "now":
		return now.UTC(), nil
	case s[0] == '+' || s[0] == '-':
		d, err := Duration(s[1:])
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid relative time %q: %w", s, err)
		}
		if s[0] == '-' {
			d = -d
		}
		return now.Add(d).UTC(), nil
	}
	if unix, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(unix, 0).UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q: use now, +1h, a Unix timestamp, or RFC 3339", s)
}

// Relative describes t against now: "in 2h13m", "3d ago", or "now".
func Relative(t, now time.Time) string {
	d := t.Sub(now).Round(time.Second)
	switch {
	case d > 0:
		return "in " + Short(d)
	case d < 0:
		return Short(-d) + " ago"
	default:
		return "now"
	}
}

// Short formats a non-negative duration using its two most significant
// units out of d, h, m, s: "3d2h", "2h13m", "13m5s", "45s".
func Short(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	days := int64(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int64(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int64(d / time.Minute)
	secs := int64((d - time.Duration(mins)*time.Minute) / time.Second)

	parts := []struct {
		n    int64
		unit string
	}{{days, "d"}, {hours, "h"}, {mins, "m"}, {secs, "s"}}

	var out []string
	for _, p := range parts {
		if len(out) == 2 {
			break
		}
		if p.n == 0 && len(out) == 0 {
			continue
		}
		if p.n == 0 {
			// Leading unit already emitted; stop at the next zero so
			// "3d" stays "3d" rather than "3d0h".
			break
		}
		out = append(out, fmt.Sprintf("%d%s", p.n, p.unit))
	}
	if len(out) == 0 {
		return "0s"
	}
	return strings.Join(out, "")
}
