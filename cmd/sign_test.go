package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "parse days",
			input:    "7d",
			expected: 7 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "parse hours",
			input:    "2h",
			expected: 2 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "parse minutes",
			input:    "30m",
			expected: 30 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "parse minutes with min suffix",
			input:    "45min",
			expected: 45 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "parse seconds",
			input:    "60s",
			expected: 60 * time.Second,
			wantErr:  false,
		},
		{
			name:     "parse seconds with sec suffix",
			input:    "90sec",
			expected: 90 * time.Second,
			wantErr:  false,
		},
		{
			name:     "invalid format - no number",
			input:    "h",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "invalid format - unknown unit",
			input:    "5x",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "invalid format - empty string",
			input:    "",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("parseDuration() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
		wantErr  bool
	}{
		{
			name:     "parse unix timestamp",
			input:    "1609459200",
			expected: 1609459200,
			wantErr:  false,
		},
		{
			name:     "parse ISO 8601 format",
			input:    "2021-01-01T00:00:00Z",
			expected: 1609459200,
			wantErr:  false,
		},
		{
			name:     "parse ISO 8601 with timezone",
			input:    "2021-01-01T01:00:00+01:00",
			expected: 1609459200,
			wantErr:  false,
		},
		{
			name:     "invalid format",
			input:    "not-a-date",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTime() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("parseTime() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenerateJTI(t *testing.T) {
	// Test that JTI is generated and has correct format
	jti := generateJTI()

	if jti == "" {
		t.Error("generateJTI() returned empty string")
	}

	// Should have UUID-like format with hyphens
	parts := strings.Split(jti, "-")
	if len(parts) != 5 {
		t.Errorf("generateJTI() = %v, expected 5 parts separated by hyphens", jti)
	}

	// Test that multiple calls generate different JTIs
	jti2 := generateJTI()
	if jti == jti2 {
		t.Error("generateJTI() generated same JTI twice (should be unique)")
	}
}

func TestGenerateJTIFormat(t *testing.T) {
	// Test JTI format is consistent
	for i := 0; i < 10; i++ {
		jti := generateJTI()
		parts := strings.Split(jti, "-")

		// Check expected lengths: 8-4-4-4-12 hex characters
		expectedLengths := []int{8, 4, 4, 4, 12}
		for j, part := range parts {
			if len(part) != expectedLengths[j] {
				t.Errorf("generateJTI() part %d has length %d, expected %d", j, len(part), expectedLengths[j])
			}

			// Check all characters are hex
			for _, c := range part {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("generateJTI() contains non-hex character: %c", c)
				}
			}
		}
	}
}
