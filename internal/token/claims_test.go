package token

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

func TestBuildClaimsPrecedence(t *testing.T) {
	got, err := BuildClaims(ClaimsInput{
		Payload: map[string]any{"role": "user", "sub": "from-payload", "keep": true},
		Claims:  map[string]any{"role": "admin", "sub": "from-claim"},
		Subject: "from-flag",
		Now:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["role"] != "admin" || got["sub"] != "from-flag" || got["keep"] != true {
		t.Errorf("got %v", got)
	}
	if got["iat"] != now.Unix() {
		t.Errorf("iat = %v, want %d", got["iat"], now.Unix())
	}
}

func TestBuildClaimsStandard(t *testing.T) {
	got, err := BuildClaims(ClaimsInput{
		Issuer:   "iss",
		Audience: []string{"a", "b"},
		Exp:      "+1h",
		Nbf:      "-5m",
		Iat:      "1609459200",
		JTI:      "id1",
		Now:      now,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"iss": "iss",
		"aud": []string{"a", "b"},
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-5 * time.Minute).Unix(),
		"iat": int64(1609459200),
		"jti": "id1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v\nwant %#v", got, want)
	}
}

func TestBuildClaimsSingleAudienceIsString(t *testing.T) {
	got, _ := BuildClaims(ClaimsInput{Audience: []string{"only"}, NoIat: true, Now: now})
	if got["aud"] != "only" {
		t.Errorf("aud = %#v", got["aud"])
	}
	if _, ok := got["iat"]; ok {
		t.Error("iat should be omitted with NoIat")
	}
}

func TestBuildClaimsRelativeExpIsFromNowNotIat(t *testing.T) {
	got, _ := BuildClaims(ClaimsInput{Iat: "1609459200", Exp: "+1h", Now: now})
	if got["exp"] != now.Add(time.Hour).Unix() {
		t.Errorf("exp = %v, want relative to now", got["exp"])
	}
}

func TestBuildClaimsJTIAuto(t *testing.T) {
	got, err := BuildClaims(ClaimsInput{JTIAuto: true, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	jti, _ := got["jti"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(jti) {
		t.Errorf("jti = %q, not a UUID v4", jti)
	}
}

func TestBuildClaimsErrors(t *testing.T) {
	tests := []struct {
		name string
		in   ClaimsInput
		want string
	}{
		{"jti conflict", ClaimsInput{JTI: "x", JTIAuto: true}, "--jti"},
		{"iat conflict", ClaimsInput{Iat: "now", NoIat: true}, "--iat"},
		{"bad exp", ClaimsInput{Exp: "soon"}, "--exp"},
		{"bad nbf", ClaimsInput{Nbf: "5x"}, "--nbf"},
		{"bad iat", ClaimsInput{Iat: "yesterday"}, "--iat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.in.Now = now
			_, err := BuildClaims(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseValue(t *testing.T) {
	tests := []struct {
		in   string
		want any
	}{
		{"admin", "admin"},
		{"123", json.Number("123")},
		{"1.5", json.Number("1.5")},
		{"true", true},
		{"null", nil},
		{`"123"`, "123"},
		{`["a","b"]`, []any{"a", "b"}},
		{`{"x":1}`, map[string]any{"x": json.Number("1")}},
		{"not json {", "not json {"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := ParseValue(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseValue(%q) = %#v, want %#v", tt.in, got, tt.want)
		}
	}
}

func TestParseKVs(t *testing.T) {
	got, err := ParseKVs([]string{"role=admin", "id=7", "url=https://x/?a=b"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"role": "admin", "id": json.Number("7"), "url": "https://x/?a=b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v", got)
	}
	for _, bad := range []string{"novalue", "=x", ""} {
		if _, err := ParseKVs([]string{bad}); err == nil {
			t.Errorf("ParseKVs(%q) should fail", bad)
		}
	}
}
