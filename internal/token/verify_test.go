package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lazhari/jwt/internal/keys"
)

const secret = "0123456789abcdef0123456789abcdef"

func clock() time.Time { return now }

func check(t *testing.T, v *Verification, name string) Check {
	t.Helper()
	for _, c := range v.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, v.Checks)
	return Check{}
}

func hmacKey(t *testing.T) *keys.Key { return mustKey(t, []byte(secret)) }

func TestVerifyValidHS256(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"sub": "u1", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()}, secret)
	r, err := Verify(tok, VerifyOptions{Key: hmacKey(t), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verification.Valid {
		t.Errorf("expected valid: %+v", r.Verification.Checks)
	}
	if r.Verification.Algorithm != "HS256" || r.Verification.KeySource != "test" {
		t.Errorf("alg=%s source=%s", r.Verification.Algorithm, r.Verification.KeySource)
	}
	if c := check(t, r.Verification, "exp"); !c.Passed || c.Detail != "expires in 1h" {
		t.Errorf("exp check = %+v", c)
	}
	if c := check(t, r.Verification, "iat"); !c.Passed || c.Detail != "issued now" {
		t.Errorf("iat check = %+v", c)
	}
	if r.Payload["sub"] != "u1" {
		t.Error("payload missing")
	}
}

func TestVerifyWrongSecretStillShowsPayload(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"sub": "u1"}, "other-secret-other-secret-other-")
	r, err := Verify(tok, VerifyOptions{Key: hmacKey(t), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verification.Valid {
		t.Error("expected invalid")
	}
	if c := check(t, r.Verification, "signature"); c.Passed || !strings.Contains(c.Detail, "does not match") {
		t.Errorf("signature check = %+v", c)
	}
	if r.Payload["sub"] != "u1" {
		t.Error("payload should still be decoded")
	}
}

func TestVerifyAlgorithmConfusionRejected(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Attacker signs an HS256 token; verifier has an RSA public key.
	tok := hs256Token(t, jwt.MapClaims{"sub": "evil"}, secret)
	r, err := Verify(tok, VerifyOptions{Key: mustKey(t, &rsaKey.PublicKey), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verification.Valid {
		t.Fatal("HS256 token must not verify against an RSA key")
	}
	if c := check(t, r.Verification, "alg"); c.Passed || !strings.Contains(c.Detail, "HS256") {
		t.Errorf("alg check = %+v", c)
	}
	if c := check(t, r.Verification, "signature"); !c.Skipped {
		t.Errorf("signature should be skipped when alg fails: %+v", c)
	}
}

func TestVerifyAlgAllowlist(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{}, secret)
	r, _ := Verify(tok, VerifyOptions{Key: hmacKey(t), Algs: []string{"HS512"}, Now: clock})
	if r.Verification.Valid {
		t.Error("HS256 should be rejected when only HS512 is allowed")
	}
	if c := check(t, r.Verification, "alg"); !strings.Contains(c.Detail, "HS512") {
		t.Errorf("alg detail = %q", c.Detail)
	}
}

func TestVerifyTimeClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		opt    VerifyOptions
		valid  bool
		check  string
		detail string
	}{
		{"expired", jwt.MapClaims{"exp": now.Add(-3 * 24 * time.Hour).Unix()}, VerifyOptions{}, false, "exp", "expired 3d ago"},
		{"expired within leeway", jwt.MapClaims{"exp": now.Add(-10 * time.Second).Unix()}, VerifyOptions{Leeway: 30 * time.Second}, true, "exp", "expired 10s ago"},
		{"expired ignored", jwt.MapClaims{"exp": now.Add(-time.Hour).Unix()}, VerifyOptions{IgnoreExp: true}, true, "exp", "ignored"},
		{"no exp", jwt.MapClaims{}, VerifyOptions{}, true, "exp", "no exp claim (never expires)"},
		{"exp not numeric", jwt.MapClaims{"exp": "tomorrow"}, VerifyOptions{}, false, "exp", "not a number (string)"},
		{"nbf future", jwt.MapClaims{"nbf": now.Add(5 * time.Minute).Unix()}, VerifyOptions{}, false, "nbf", "not valid for 5m"},
		{"nbf future within leeway", jwt.MapClaims{"nbf": now.Add(5 * time.Second).Unix()}, VerifyOptions{Leeway: 10 * time.Second}, true, "nbf", "not valid for 5s"},
		{"nbf past", jwt.MapClaims{"nbf": now.Add(-5 * time.Minute).Unix()}, VerifyOptions{}, true, "nbf", "valid since 5m ago"},
		{"nbf ignored", jwt.MapClaims{"nbf": now.Add(time.Hour).Unix()}, VerifyOptions{IgnoreNbf: true}, true, "nbf", "ignored"},
		{"iat future", jwt.MapClaims{"iat": now.Add(time.Hour).Unix()}, VerifyOptions{}, false, "iat", "issued in 1h, clock skew?"},
		{"iat past", jwt.MapClaims{"iat": now.Add(-time.Hour).Unix()}, VerifyOptions{}, true, "iat", "issued 1h ago"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := hs256Token(t, tt.claims, secret)
			tt.opt.Key = hmacKey(t)
			tt.opt.Now = clock
			r, err := Verify(tok, tt.opt)
			if err != nil {
				t.Fatal(err)
			}
			if r.Verification.Valid != tt.valid {
				t.Errorf("valid = %v, want %v: %+v", r.Verification.Valid, tt.valid, r.Verification.Checks)
			}
			if c := check(t, r.Verification, tt.check); c.Detail != tt.detail {
				t.Errorf("%s detail = %q, want %q", tt.check, c.Detail, tt.detail)
			}
		})
	}
}

func TestVerifyNbfAbsentNotReported(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{}, secret)
	r, _ := Verify(tok, VerifyOptions{Key: hmacKey(t), Now: clock})
	for _, c := range r.Verification.Checks {
		if c.Name == "nbf" || c.Name == "iat" {
			t.Errorf("absent %s should not produce a check", c.Name)
		}
	}
}

func TestVerifyExpectedClaims(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"iss": "auth", "sub": "u1", "aud": []string{"api", "web"}}, secret)
	r, _ := Verify(tok, VerifyOptions{Key: hmacKey(t), Issuer: "auth", Subject: "u1", Audience: "web", Now: clock})
	if !r.Verification.Valid {
		t.Errorf("expected valid: %+v", r.Verification.Checks)
	}
	r, _ = Verify(tok, VerifyOptions{Key: hmacKey(t), Issuer: "other", Subject: "u2", Audience: "mobile", Now: clock})
	if r.Verification.Valid {
		t.Error("expected invalid")
	}
	if c := check(t, r.Verification, "iss"); c.Detail != `iss is "auth", expected "other"` {
		t.Errorf("iss detail = %q", c.Detail)
	}
	if c := check(t, r.Verification, "sub"); c.Detail != `sub is "u1", expected "u2"` {
		t.Errorf("sub detail = %q", c.Detail)
	}
	if c := check(t, r.Verification, "aud"); c.Detail != `aud is ["api", "web"], expected "mobile"` {
		t.Errorf("aud detail = %q", c.Detail)
	}

	tok = hs256Token(t, jwt.MapClaims{"aud": "single"}, secret)
	r, _ = Verify(tok, VerifyOptions{Key: hmacKey(t), Audience: "single", Issuer: "x", Now: clock})
	if c := check(t, r.Verification, "aud"); !c.Passed {
		t.Errorf("string aud should match: %+v", c)
	}
	if c := check(t, r.Verification, "iss"); c.Passed || c.Detail != `no iss claim, expected "x"` {
		t.Errorf("missing iss = %+v", c)
	}
}

func TestVerifyRequire(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"jti": "1"}, secret)
	r, _ := Verify(tok, VerifyOptions{Key: hmacKey(t), Require: []string{"jti", "exp"}, Now: clock})
	if r.Verification.Valid {
		t.Error("missing exp should fail")
	}
	if c := check(t, r.Verification, "require:jti"); !c.Passed {
		t.Errorf("jti = %+v", c)
	}
	if c := check(t, r.Verification, "require:exp"); c.Passed || c.Detail != "claim exp is missing" {
		t.Errorf("exp = %+v", c)
	}
}

func TestVerifyNone(t *testing.T) {
	tok, _ := Sign(SignInput{Payload: map[string]any{"a": 1}, Alg: "none"})

	r, err := Verify(tok, VerifyOptions{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verification.Valid {
		t.Error("none must be rejected by default")
	}
	if c := check(t, r.Verification, "alg"); !strings.Contains(c.Detail, "--insecure-allow-none") {
		t.Errorf("alg detail = %q", c.Detail)
	}

	r, err = Verify(tok, VerifyOptions{AllowNone: true, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verification.Valid {
		t.Errorf("none with AllowNone should be valid: %+v", r.Verification.Checks)
	}
	if r.Verification.KeySource != "none" {
		t.Errorf("key source = %q", r.Verification.KeySource)
	}

	// A none token with an HMAC key present must still be refused.
	r, _ = Verify(tok, VerifyOptions{Key: hmacKey(t), Now: clock})
	if r.Verification.Valid {
		t.Error("none must be rejected even with a key")
	}

	// AllowNone plus a supplied key must still report key_source "none",
	// not the key's own source label.
	r, err = Verify(tok, VerifyOptions{AllowNone: true, Key: hmacKey(t), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verification.KeySource != "none" {
		t.Errorf("key source with AllowNone and a key = %q, want %q", r.Verification.KeySource, "none")
	}

	// AllowNone does not bypass an explicit --alg allowlist that excludes none.
	r, err = Verify(tok, VerifyOptions{AllowNone: true, Algs: []string{"RS256"}, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verification.Valid {
		t.Error("none must be rejected when the alg allowlist excludes it")
	}
	if c := check(t, r.Verification, "alg"); c.Passed || !strings.Contains(c.Detail, "RS256") {
		t.Errorf("alg check with excluding allowlist = %+v", c)
	}

	// AllowNone with an allowlist that explicitly includes none is valid.
	r, err = Verify(tok, VerifyOptions{AllowNone: true, Algs: []string{"none"}, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verification.Valid {
		t.Errorf("none with AllowNone and an allowlist containing none should be valid: %+v", r.Verification.Checks)
	}
}

func TestVerifyInputErrors(t *testing.T) {
	if _, err := Verify("garbage", VerifyOptions{Key: hmacKey(t), Now: clock}); err == nil {
		t.Error("malformed token should be an error")
	}
	tok := hs256Token(t, jwt.MapClaims{}, secret)
	if _, err := Verify(tok, VerifyOptions{Now: clock}); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Errorf("missing key err = %v", err)
	}
}

func TestResultJSONShape(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"sub": "u"}, secret)
	r, _ := Verify(tok, VerifyOptions{Key: hmacKey(t), Now: clock})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"header", "payload", "signature", "verification"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %q in %s", k, b)
		}
	}
	if _, ok := m["Raw"]; ok {
		t.Error("Raw must not be serialised")
	}
}

// TestVerifyJWKAlgNarrowsAllowlist covers a JWK that declares "alg": that
// one algorithm becomes the default allowlist, so a PS256 token signed with
// the same RSA key is refused unless --alg says otherwise.
func TestVerifyJWKAlgNarrowsAllowlist(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodPS256, jwt.MapClaims{"sub": "u1"}).SignedString(rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	k := mustKey(t, &rsaKey.PublicKey)
	k.Alg = "RS256"
	r, err := Verify(tok, VerifyOptions{Key: k, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verification.Valid {
		t.Fatal("PS256 must be refused when the JWK declares alg RS256")
	}
	if c := check(t, r.Verification, "alg"); c.Passed || !strings.Contains(c.Detail, "RS256") {
		t.Errorf("alg check = %+v", c)
	}

	// An explicit allowlist overrides the JWK's declaration.
	r, err = Verify(tok, VerifyOptions{Key: k, Algs: []string{"PS256"}, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verification.Valid {
		t.Errorf("explicit --alg PS256 should win: %+v", r.Verification.Checks)
	}
}

// TestVerifyRejectsPaddedSignature pins the ruling that verify does not
// tolerate base64 padding, the way RFC 7515-strict servers do not.
func TestVerifyRejectsPaddedSignature(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"sub": "u1"}, secret)
	padded := tok + "="
	r, err := Verify(padded, VerifyOptions{Key: hmacKey(t), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verification.Valid {
		t.Fatal("a padded signature segment must not verify")
	}
	if c := check(t, r.Verification, "signature"); c.Passed || c.Skipped {
		t.Errorf("signature check = %+v", c)
	}
}

func TestVerifyCritHeaderRejected(t *testing.T) {
	tests := []struct {
		name   string
		crit   any
		detail string
	}{
		{"unknown extension", []string{"exp"}, "unsupported critical header extensions"},
		{"empty array", []string{}, "crit must be a non-empty array"},
		{"not an array", "exp", "crit must be a non-empty array"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tk := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "u1"})
			tk.Header["crit"] = tt.crit
			tok, err := tk.SignedString([]byte(secret))
			if err != nil {
				t.Fatal(err)
			}
			r, err := Verify(tok, VerifyOptions{Key: hmacKey(t), Now: clock})
			if err != nil {
				t.Fatal(err)
			}
			if r.Verification.Valid {
				t.Fatal("a token with crit must not be valid")
			}
			c := check(t, r.Verification, "crit")
			if c.Passed || !strings.Contains(c.Detail, tt.detail) {
				t.Errorf("crit check = %+v", c)
			}
		})
	}
}

func TestVerifyNoCritCheckWhenHeaderAbsent(t *testing.T) {
	tok := hs256Token(t, jwt.MapClaims{"sub": "u1"}, secret)
	r, err := Verify(tok, VerifyOptions{Key: hmacKey(t), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Verification.Checks {
		if c.Name == "crit" {
			t.Fatalf("no crit check should be emitted without the header: %+v", c)
		}
	}
	if !r.Verification.Valid {
		t.Errorf("expected valid: %+v", r.Verification.Checks)
	}
}
