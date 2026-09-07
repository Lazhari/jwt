package timeparse

import (
	"testing"
	"time"
)

var now = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

func TestDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"2h", 2 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"45min", 45 * time.Minute, false},
		{"60s", time.Minute, false},
		{"90sec", 90 * time.Second, false},
		{"1h30m", 90 * time.Minute, false},
		{"1.5h", 90 * time.Minute, false},
		{" 5m ", 5 * time.Minute, false},
		{"", 0, true},
		{"h", 0, true},
		{"5x", 0, true},
		{"-5m", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Duration(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Duration(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Duration(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestAt(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		{"now", now, false},
		{"+1h", now.Add(time.Hour), false},
		{"-30m", now.Add(-30 * time.Minute), false},
		{"+7d", now.Add(7 * 24 * time.Hour), false},
		{"1609459200", time.Unix(1609459200, 0).UTC(), false},
		{"2021-01-01T00:00:00Z", time.Unix(1609459200, 0).UTC(), false},
		{"2021-01-01T01:00:00+01:00", time.Unix(1609459200, 0).UTC(), false},
		{"", time.Time{}, true},
		{"not-a-date", time.Time{}, true},
		{"+", time.Time{}, true},
		{"+5x", time.Time{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := At(tt.in, now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("At(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !got.Equal(tt.want) {
				t.Errorf("At(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestShort(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{45 * time.Second, "45s"},
		{13*time.Minute + 5*time.Second, "13m5s"},
		{2*time.Hour + 13*time.Minute, "2h13m"},
		{2*time.Hour + 13*time.Minute + 9*time.Second, "2h13m"},
		{3 * 24 * time.Hour, "3d"},
		{3*24*time.Hour + 2*time.Hour + 5*time.Minute, "3d2h"},
	}
	for _, tt := range tests {
		if got := Short(tt.d); got != tt.want {
			t.Errorf("Short(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestRelative(t *testing.T) {
	if got := Relative(now.Add(2*time.Hour+13*time.Minute), now); got != "in 2h13m" {
		t.Errorf("future: got %q", got)
	}
	if got := Relative(now.Add(-3*24*time.Hour), now); got != "3d ago" {
		t.Errorf("past: got %q", got)
	}
	if got := Relative(now, now); got != "now" {
		t.Errorf("same: got %q", got)
	}
}
