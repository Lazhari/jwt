package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func hs256Token(t *testing.T, claims jwt.MapClaims, secret string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"  a.b.c \n":    "a.b.c",
		"Bearer a.b.c":  "a.b.c",
		"bearer  a.b.c": "a.b.c",
		"BEARER a.b.c":  "a.b.c",
		"Bearerx.y.z":   "Bearerx.y.z",
		"a.b.c":         "a.b.c",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeValid(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"sub": "u1", "n": 12345678901234, "nested": map[string]any{"a": 1}}, "s")
	d, err := Decode("Bearer " + tok)
	if err != nil {
		t.Fatal(err)
	}
	if d.Header["alg"] != "HS256" || d.Header["typ"] != "JWT" {
		t.Errorf("header = %v", d.Header)
	}
	if d.Payload["sub"] != "u1" {
		t.Errorf("sub = %v", d.Payload["sub"])
	}
	if n, ok := d.Payload["n"].(json.Number); !ok || n.String() != "12345678901234" {
		t.Errorf("large number lost precision: %v (%T)", d.Payload["n"], d.Payload["n"])
	}
	parts := strings.Split(tok, ".")
	if d.Signature != parts[2] || d.Raw != [3]string(parts) {
		t.Errorf("signature/raw mismatch")
	}
}

func TestDecodePaddedSegments(t *testing.T) {
	hdr := base64.URLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pl := base64.URLEncoding.EncodeToString([]byte(`{"a":1}`))
	if !strings.Contains(hdr+pl, "=") {
		t.Skip("segments not padded; adjust inputs")
	}
	d, err := Decode(hdr + "." + pl + ".")
	if err != nil {
		t.Fatal(err)
	}
	if d.Header["alg"] != "none" {
		t.Errorf("alg = %v", d.Header["alg"])
	}
}

func TestDecodeTwoSegments(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`))
	d, err := Decode(hdr + "." + pl)
	if err != nil {
		t.Fatal(err)
	}
	if d.Signature != "" || d.Raw[2] != "" {
		t.Errorf("expected empty signature, got %q", d.Signature)
	}
}

func TestDecodeErrors(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "empty token"},
		{"one segment", "abc", "got 1"},
		{"four segments", "a.b.c.d", "got 4"},
		{"bad base64 header", "!!.e30.x", "header is not base64url"},
		{"header not object", base64.RawURLEncoding.EncodeToString([]byte(`[1]`)) + ".e30.x", "header is not a JSON object"},
		{"payload not object", hdr + "." + base64.RawURLEncoding.EncodeToString([]byte(`"str"`)) + ".x", "payload is not a JSON object"},
		{"payload null", hdr + "." + base64.RawURLEncoding.EncodeToString([]byte(`null`)) + ".x", "payload is null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestNumericDate(t *testing.T) {
	want := time.Unix(1735689600, 0).UTC()
	for _, v := range []any{json.Number("1735689600"), json.Number("1735689600.5"), float64(1735689600), int64(1735689600), int(1735689600)} {
		got, present, err := NumericDate(v)
		if err != nil || !present || got.Unix() != want.Unix() {
			t.Errorf("NumericDate(%v %T) = %v %v %v", v, v, got, present, err)
		}
	}
	if _, present, err := NumericDate(nil); present || err != nil {
		t.Errorf("nil: present=%v err=%v", present, err)
	}
	if _, _, err := NumericDate("soon"); err == nil {
		t.Error("string should error")
	}
}
