package output

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lazhari/jwt/internal/token"
)

var now = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

func sample() *token.Result {
	return &token.Result{
		Decoded: &token.Decoded{
			Header: map[string]any{"typ": "JWT", "alg": "HS256"},
			Payload: map[string]any{
				"sub":    "u1",
				"exp":    json.Number("1735740780"), // now + 2h13m
				"iat":    json.Number("1735732800"), // now
				"nested": map[string]any{"b": json.Number("2"), "a": "x"},
				"list":   []any{"a", json.Number("1")},
				"flag":   true,
				"none":   nil,
				"big":    json.Number("12345678901234567890"),
			},
			Signature: "abc123",
		},
	}
}

func TestJSONDecodeOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("not a single JSON document: %v\n%s", err, buf.String())
	}
	if _, ok := m["verification"]; ok {
		t.Error("verification must be omitted for decode")
	}
	if !strings.Contains(buf.String(), `"big": 12345678901234567890`) {
		t.Errorf("big number not preserved:\n%s", buf.String())
	}
	if strings.Index(buf.String(), `"alg"`) > strings.Index(buf.String(), `"typ"`) {
		t.Error("keys should be sorted")
	}
}

func TestJSONWithVerification(t *testing.T) {
	r := sample()
	r.Verification = &token.Verification{Valid: false, Algorithm: "HS256", KeySource: "secret", Checks: []token.Check{{Name: "signature", Passed: true, Detail: "ok"}, {Name: "exp", Detail: "expired"}}}
	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Verification struct {
			Valid     bool   `json:"valid"`
			KeySource string `json:"key_source"`
			Checks    []struct {
				Name string `json:"name"`
			} `json:"checks"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Verification.Valid || doc.Verification.KeySource != "secret" || len(doc.Verification.Checks) != 2 {
		t.Errorf("got %+v", doc)
	}
}

func TestWriteJSONNoHTMLEscape(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteJSON(&buf, map[string]string{"url": "https://x/?a=1&b=2"})
	// SetEscapeHTML(false) keeps the literal ampersand instead of turning
	// it into the & escape sequence Go's encoder otherwise emits.
	if !strings.Contains(buf.String(), "a=1&b=2") {
		t.Error("ampersand should not be escaped")
	}
	if strings.Contains(buf.String(), "\\u0026") {
		t.Error("ampersand should have been left unescaped, not turned into \\u0026")
	}
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestTableDecodeOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, sample(), Options{Width: 100, Now: now}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if ansi.MatchString(out) {
		t.Errorf("no ANSI expected with Color false:\n%s", out)
	}
	for _, want := range []string{
		"Header", "Payload", "Signature",
		"HS256", "JWT",
		"1735740780  2025-01-01 14:13:00 UTC  (expires in 2h13m)",
		"1735732800  2025-01-01 12:00:00 UTC  (issued now)",
		`{"a":"x","b":2}`,
		`["a",1]`,
		"true", "null", "12345678901234567890",
		"abc123",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Verification") {
		t.Error("no verification section expected")
	}
	// Keys sorted: "big" before "exp" before "sub".
	if strings.Index(out, "big") > strings.Index(out, "exp") || strings.Index(out, "exp") > strings.Index(out, "sub") {
		t.Errorf("payload keys not sorted:\n%s", out)
	}
	// Header keys sorted: alg before typ.
	if strings.Index(out, "alg") > strings.Index(out, "typ") {
		t.Errorf("header keys not sorted:\n%s", out)
	}
}

func TestTableExpiredAndVerification(t *testing.T) {
	r := sample()
	r.Payload["exp"] = json.Number("1735473600") // now - 3d
	r.Payload["nbf"] = json.Number("1735733100") // now + 5m
	r.Signature = ""
	r.Verification = &token.Verification{
		Valid:     false,
		Algorithm: "HS256",
		KeySource: "secret",
		Checks: []token.Check{
			{Name: "alg", Passed: true, Detail: "HS256"},
			{Name: "signature", Passed: true, Detail: "verified with secret"},
			{Name: "exp", Passed: false, Detail: "expired 3d ago"},
			{Name: "nbf", Skipped: true, Detail: "ignored"},
		},
	}
	var buf bytes.Buffer
	if err := Table(&buf, r, Options{Width: 100, Now: now}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"(expired 3d ago)",
		"(not valid for 5m)",
		"(none)",
		"Verification",
		"✓ alg", "✓ signature", "✗ exp", "- nbf",
		"expired 3d ago",
		"INVALID",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	r.Verification.Valid = true
	buf.Reset()
	_ = Table(&buf, r, Options{Width: 100, Now: now})
	if !strings.Contains(buf.String(), "VALID") || strings.Contains(buf.String(), "INVALID") {
		t.Errorf("expected VALID:\n%s", buf.String())
	}
}

func TestTableWrapsLongValuesWithinWidth(t *testing.T) {
	r := sample()
	r.Payload = map[string]any{"long": strings.Repeat("x", 300)}
	var buf bytes.Buffer
	_ = Table(&buf, r, Options{Width: 60, Now: now})
	for _, line := range strings.Split(buf.String(), "\n") {
		if len([]rune(line)) > 60 {
			t.Errorf("line wider than 60: %q", line)
		}
	}
	if strings.Count(buf.String(), "x") != 300 {
		t.Error("long value was truncated")
	}
}

func TestTableEmptyPayload(t *testing.T) {
	r := sample()
	r.Payload = map[string]any{}
	var buf bytes.Buffer
	if err := Table(&buf, r, Options{Now: now}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(empty)") {
		t.Errorf("expected (empty) marker:\n%s", buf.String())
	}
}

func TestTableSanitizesHostileValues(t *testing.T) {
	r := sample()
	r.Payload = map[string]any{
		// U+202E is a bidi override (Cf) and U+2028 a line separator (Zl):
		// both are invisible and must not reach the terminal.
		"x\x1b[31m": "\x1b[2J\x1b[31mFAKE\x1b[0m\nline2\u202eevil\u2028tail",
	}
	r.Signature = "abc\x1bdef"
	r.Verification = &token.Verification{
		Valid:     true,
		Algorithm: "HS256",
		KeySource: "secret",
		Checks: []token.Check{
			{Name: "signature", Passed: true, Detail: "hostile \x1b[1m detail"},
		},
	}
	var buf bytes.Buffer
	if err := Table(&buf, r, Options{Width: 100, Now: now}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if ansi.MatchString(out) {
		t.Errorf("no ANSI expected with Color false:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("raw ESC byte leaked into output:\n%s", out)
	}
	if !strings.Contains(out, `\x1b[2J\x1b[31mFAKE\x1b[0m\nline2\u202eevil\u2028tail`) {
		t.Errorf("expected escaped value on one line:\n%s", out)
	}
	if strings.ContainsAny(out, "\u202e\u2028") {
		t.Errorf("raw bidi override or line separator leaked into output:\n%s", out)
	}
	if !strings.Contains(out, "FAKE") {
		t.Errorf("expected FAKE to survive sanitization:\n%s", out)
	}
}
