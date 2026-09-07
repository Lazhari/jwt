package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lazhari/jwt/internal/jwk"
)

func parseHS(t *testing.T, tok, secret string) jwt.MapClaims {
	t.Helper()
	parsed, err := jwt.NewParser(jwt.WithoutClaimsValidation()).Parse(strings.TrimSpace(tok), func(*jwt.Token) (any, error) { return []byte(secret), nil })
	if err != nil {
		t.Fatalf("library could not parse %q: %v", tok, err)
	}
	return parsed.Claims.(jwt.MapClaims)
}

func TestSignHS256Basic(t *testing.T) {
	r := runJWT(t, "", nil, "sign", "--secret", testSecret, "--payload", `{"user_id":123}`, "--exp", "+1h")
	if r.code != 0 || r.err != "" {
		t.Fatalf("got %+v", r)
	}
	if strings.Count(r.out, "\n") != 1 {
		t.Errorf("stdout must be exactly one line: %q", r.out)
	}
	claims := parseHS(t, r.out, testSecret)
	if claims["user_id"] != float64(123) {
		t.Errorf("user_id = %v", claims["user_id"])
	}
	if claims["iat"] != float64(testNow.Unix()) || claims["exp"] != float64(testNow.Add(time.Hour).Unix()) {
		t.Errorf("iat/exp = %v/%v", claims["iat"], claims["exp"])
	}
}

func TestSignClaimFlagsAndPrecedence(t *testing.T) {
	r := runJWT(t, "", nil, "sign", "--secret", testSecret,
		"--payload", `{"role":"user","sub":"p"}`,
		"--claim", "role=admin", "--claim", "n=7", "--claim", "tags=[\"a\"]", "--claim", `s="7"`,
		"--sub", "flag", "--iss", "me", "--aud", "a", "--aud", "b,c", "--nbf", "-5m", "--jti", "id1", "--no-iat")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	c := parseHS(t, r.out, testSecret)
	if c["role"] != "admin" || c["sub"] != "flag" || c["iss"] != "me" || c["n"] != float64(7) || c["s"] != "7" || c["jti"] != "id1" {
		t.Errorf("claims = %v", c)
	}
	if aud, ok := c["aud"].([]any); !ok || len(aud) != 2 || aud[1] != "b,c" {
		t.Errorf("aud = %#v (commas inside a value must be kept)", c["aud"])
	}
	if _, ok := c["iat"]; ok {
		t.Error("iat should be absent with --no-iat")
	}
	if c["nbf"] != float64(testNow.Add(-5*time.Minute).Unix()) {
		t.Errorf("nbf = %v", c["nbf"])
	}
}

func TestSignPayloadFromFileAndStdin(t *testing.T) {
	path := writeTemp(t, "p.json", []byte(`{"a":1}`))
	r := runJWT(t, "", nil, "sign", "--secret", testSecret, "--payload", "@"+path)
	if r.code != 0 || parseHS(t, r.out, testSecret)["a"] != float64(1) {
		t.Errorf("file: %+v", r)
	}
	r = runJWT(t, `{"b":2}`, nil, "sign", "--secret", testSecret, "--payload", "-")
	if r.code != 0 || parseHS(t, r.out, testSecret)["b"] != float64(2) {
		t.Errorf("stdin: %+v", r)
	}
}

func TestSignHeaders(t *testing.T) {
	r := runJWT(t, "", nil, "sign", "--secret", testSecret, "--kid", "k1", "--typ", "at+jwt", "--header", "cty=json", "--json")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	var doc struct {
		Token   string         `json:"token"`
		Header  map[string]any `json:"header"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.out)
	}
	if doc.Header["kid"] != "k1" || doc.Header["typ"] != "at+jwt" || doc.Header["cty"] != "json" || doc.Header["alg"] != "HS256" {
		t.Errorf("header = %v", doc.Header)
	}
	if doc.Payload["iat"] == nil || doc.Token == "" {
		t.Errorf("doc = %+v", doc)
	}
}

func TestSignAsymmetricAndDefaultAlg(t *testing.T) {
	rsaPriv, _, rsaKey := rsaPair(t)
	ecPriv, _, ecKey := ecPair(t, ellipticP384())
	edPriv, _, edKey := edPair(t)

	tests := []struct {
		name, keyPath, alg, wantAlg string
		pub                         any
	}{
		{"rsa default", rsaPriv, "", "RS256", &rsaKey.PublicKey},
		{"rsa ps512", rsaPriv, "PS512", "PS512", &rsaKey.PublicKey},
		{"ec default", ecPriv, "", "ES384", &ecKey.PublicKey},
		{"ed default", edPriv, "", "EdDSA", edKey.Public()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"sign", "--key", tt.keyPath, "--claim", "x=1"}
			if tt.alg != "" {
				args = append(args, "--alg", tt.alg)
			}
			r := runJWT(t, "", nil, args...)
			if r.code != 0 {
				t.Fatalf("got %+v", r)
			}
			parsed, err := jwt.NewParser(jwt.WithValidMethods([]string{tt.wantAlg})).Parse(strings.TrimSpace(r.out), func(*jwt.Token) (any, error) { return tt.pub, nil })
			if err != nil {
				t.Fatalf("library rejected: %v", err)
			}
			if parsed.Header["alg"] != tt.wantAlg {
				t.Errorf("alg = %v", parsed.Header["alg"])
			}
		})
	}
}

func TestSignNoneAndEnv(t *testing.T) {
	r := runJWT(t, "", nil, "sign", "--alg", "none", "--claim", "a=b")
	if r.code != 0 || !strings.HasSuffix(strings.TrimSpace(r.out), ".") {
		t.Errorf("none: %+v", r)
	}
	r = runJWT(t, "", map[string]string{"JWT_SECRET": testSecret}, "sign", "--claim", "a=b")
	if r.code != 0 {
		t.Errorf("env secret: %+v", r)
	}
	parseHS(t, r.out, testSecret)
}

func TestSignShortSecretWarnsOnStderr(t *testing.T) {
	r := runJWT(t, "", nil, "sign", "--secret", "tiny")
	if r.code != 0 || !strings.Contains(r.err, "warning") || strings.Count(r.out, "\n") != 1 {
		t.Errorf("got %+v", r)
	}
}

func TestSignErrors(t *testing.T) {
	_, rsaPub, _ := rsaPair(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no key", []string{"sign"}, "no key provided"},
		{"bad payload", []string{"sign", "--secret", testSecret, "--payload", "{bad"}, "--payload"},
		{"payload not object", []string{"sign", "--secret", testSecret, "--payload", "[1]"}, "--payload"},
		{"bad claim", []string{"sign", "--secret", testSecret, "--claim", "novalue"}, "--claim"},
		{"jti conflict", []string{"sign", "--secret", testSecret, "--jti", "a", "--jti-auto"}, "--jti"},
		{"bad exp", []string{"sign", "--secret", testSecret, "--exp", "later"}, "--exp"},
		{"alg header", []string{"sign", "--secret", testSecret, "--header", "alg=none"}, "--alg"},
		{"public key", []string{"sign", "--key", rsaPub}, "private key"},
		{"wrong alg for key", []string{"sign", "--secret", testSecret, "--alg", "RS256"}, "RSA"},
		{"two sources", []string{"sign", "--secret", "a", "--key", rsaPub}, "only one key source"},
		{"unsupported alg", []string{"sign", "--secret", testSecret, "--alg", "HS1"}, "unsupported algorithm"},
		{"positional", []string{"sign", "extra"}, "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runJWT(t, "", nil, tt.args...)
			if r.code != 2 {
				t.Errorf("code = %d, want 2: %+v", r.code, r)
			}
			if r.out != "" {
				t.Errorf("stdout must be empty on error: %q", r.out)
			}
			if !strings.HasPrefix(r.err, "jwt: ") || !strings.Contains(r.err, tt.want) {
				t.Errorf("stderr = %q, want %q", r.err, tt.want)
			}
		})
	}
}

// TestSignSelectsKeyFromJWKSByKid covers --key pointing at a JWKS that holds
// several private keys: --kid names both the header kid and the key to sign
// with, so the loader must see it.
func TestSignSelectsKeyFromJWKSByKid(t *testing.T) {
	k1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j1, err := jwk.FromKey(k1, "k1")
	if err != nil {
		t.Fatal(err)
	}
	j2, err := jwk.FromKey(k2, "k2")
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jwk.Set{Keys: []jwk.Key{*j1, *j2}})
	if err != nil {
		t.Fatal(err)
	}
	setPath := writeTemp(t, "set.json", set)

	s := runJWT(t, "", nil, "sign", "--key", setPath, "--kid", "k2", "--claim", "x=1")
	if s.code != 0 {
		t.Fatalf("sign: %+v", s)
	}
	tok := strings.TrimSpace(s.out)
	v := runJWT(t, "", nil, "verify", tok, "--jwks-file", setPath)
	if v.code != 0 || !strings.Contains(v.out, "jwks:k2") {
		t.Errorf("verify: %+v", v)
	}
}
