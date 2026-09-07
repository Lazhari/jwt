package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lazhari/jwt/internal/jwk"
)

type verifyDoc struct {
	Payload      map[string]any `json:"payload"`
	Verification struct {
		Valid     bool   `json:"valid"`
		Algorithm string `json:"algorithm"`
		KeySource string `json:"key_source"`
		Checks    []struct {
			Name    string `json:"name"`
			Passed  bool   `json:"passed"`
			Skipped bool   `json:"skipped"`
			Detail  string `json:"detail"`
		} `json:"checks"`
	} `json:"verification"`
}

func verifyJSON(t *testing.T, r runResult) verifyDoc {
	t.Helper()
	var doc verifyDoc
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%+v", err, r)
	}
	return doc
}

func TestVerifyValid(t *testing.T) {
	tok := signedToken(t, "--claim", "sub=u1", "--exp", "+1h")
	r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret)
	if r.code != 0 || r.err != "" {
		t.Fatalf("got %+v", r)
	}
	for _, want := range []string{"Verification", "✓ alg", "✓ signature", "✓ exp", "expires in 1h", "VALID"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q in:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "INVALID") {
		t.Error("should be VALID")
	}
}

func TestVerifyWrongSecretExit1(t *testing.T) {
	tok := signedToken(t, "--claim", "sub=u1")
	r := runJWT(t, "", nil, "verify", tok, "--secret", "another-secret-another-secret-xx")
	if r.code != 1 {
		t.Errorf("code = %d, want 1", r.code)
	}
	if r.err != "" {
		t.Errorf("stderr should be empty, report explains the failure: %q", r.err)
	}
	for _, want := range []string{"u1", "✗ signature", "does not match", "INVALID"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q in:\n%s", want, r.out)
		}
	}
}

func TestVerifyJSON(t *testing.T) {
	tok := signedToken(t, "--claim", "sub=u1", "--exp", "-1h")
	r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--json")
	if r.code != 1 {
		t.Errorf("code = %d", r.code)
	}
	doc := verifyJSON(t, r)
	if doc.Verification.Valid || doc.Verification.Algorithm != "HS256" || doc.Verification.KeySource != "secret" {
		t.Errorf("verification = %+v", doc.Verification)
	}
	found := false
	for _, c := range doc.Verification.Checks {
		if c.Name == "exp" && !c.Passed && strings.Contains(c.Detail, "expired 1h ago") {
			found = true
		}
	}
	if !found {
		t.Errorf("exp check missing: %+v", doc.Verification.Checks)
	}
}

func TestVerifyExpiryControls(t *testing.T) {
	tok := signedToken(t, "--exp", "-10s")
	if r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret); r.code != 1 {
		t.Errorf("expired should be 1: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--leeway", "30s"); r.code != 0 {
		t.Errorf("leeway should pass: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--ignore-exp"); r.code != 0 || !strings.Contains(r.out, "- exp") {
		t.Errorf("ignore-exp: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--leeway", "soon"); r.code != 2 || !strings.Contains(r.err, "--leeway") {
		t.Errorf("bad leeway: %+v", r)
	}
	nbf := signedToken(t, "--nbf", "+1h")
	if r := runJWT(t, "", nil, "verify", nbf, "--secret", testSecret); r.code != 1 {
		t.Errorf("nbf future should be 1: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", nbf, "--secret", testSecret, "--ignore-nbf"); r.code != 0 {
		t.Errorf("ignore-nbf: %+v", r)
	}
}

func TestVerifyExpectedClaimsAndRequire(t *testing.T) {
	tok := signedToken(t, "--iss", "auth", "--sub", "u1", "--aud", "api", "--aud", "web")
	ok := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--iss", "auth", "--sub", "u1", "--aud", "web", "--require", "iat,sub")
	if ok.code != 0 {
		t.Errorf("expected valid: %+v", ok)
	}
	bad := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--iss", "other", "--require", "exp")
	if bad.code != 1 || !strings.Contains(bad.out, `✗ iss`) || !strings.Contains(bad.out, "✗ require:exp") {
		t.Errorf("expected failures: %+v", bad)
	}
}

func TestVerifyTrailingCommaFlags(t *testing.T) {
	tok := signedToken(t, "--claim", "sub=u1")
	r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--require", "iat,sub,", "--json")
	if r.code != 0 {
		t.Errorf("trailing comma in --require should not fail: %+v", r)
	}
	doc := verifyJSON(t, r)
	for _, c := range doc.Verification.Checks {
		if c.Name == "require:" {
			t.Errorf("empty require entry leaked into checks: %+v", doc.Verification.Checks)
		}
	}

	r = runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--alg", "HS256,")
	if r.code != 0 {
		t.Errorf("trailing comma in --alg should not fail: %+v", r)
	}
}

func TestVerifyAsymmetric(t *testing.T) {
	rsaPriv, rsaPub, _ := rsaPair(t)
	ecPriv, ecPub, _ := ecPair(t, ellipticP384())
	edPriv, edPub, _ := edPair(t)

	for _, tt := range []struct{ name, priv, pub, alg string }{
		{"rs256", rsaPriv, rsaPub, "RS256"},
		{"ps384", rsaPriv, rsaPub, "PS384"},
		{"es384", ecPriv, ecPub, "ES384"},
		{"eddsa", edPriv, edPub, "EdDSA"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := runJWT(t, "", nil, "sign", "--key", tt.priv, "--alg", tt.alg, "--claim", "x=1")
			if s.code != 0 {
				t.Fatalf("sign: %+v", s)
			}
			tok := strings.TrimSpace(s.out)
			if r := runJWT(t, "", nil, "verify", tok, "--key", tt.pub); r.code != 0 {
				t.Errorf("public key: %+v", r)
			}
			if r := runJWT(t, "", nil, "verify", tok, "--key", tt.priv); r.code != 0 {
				t.Errorf("private key should verify too: %+v", r)
			}
			if r := runJWT(t, "", nil, "verify", tok, "--key", tt.pub, "--alg", "HS256"); r.code != 2 {
				t.Errorf("incompatible allowlist should be a usage error: %+v", r)
			}
		})
	}
}

func TestVerifyAlgorithmConfusion(t *testing.T) {
	_, rsaPub, _ := rsaPair(t)
	// An HS256 token presented to a verifier that holds an RSA public key.
	tok := signedToken(t, "--claim", "sub=evil")
	r := runJWT(t, "", nil, "verify", tok, "--key", rsaPub)
	if r.code != 1 || !strings.Contains(r.out, "✗ alg") || !strings.Contains(r.out, "- signature") {
		t.Errorf("HS256 token must be rejected against an RSA key: %+v", r)
	}
}

func TestVerifyJWKS(t *testing.T) {
	ecPriv, _, ecKey := ecPair(t, ellipticP384())
	_, _, rsaKey := rsaPair(t)
	j1, _ := jwk.FromKey(&ecKey.PublicKey, "ec1")
	j2, _ := jwk.FromKey(&rsaKey.PublicKey, "rsa1")
	set, _ := json.Marshal(jwk.Set{Keys: []jwk.Key{*j2, *j1}})
	setPath := writeTemp(t, "jwks.json", set)

	s := runJWT(t, "", nil, "sign", "--key", ecPriv, "--kid", "ec1", "--claim", "x=1")
	tok := strings.TrimSpace(s.out)

	if r := runJWT(t, "", nil, "verify", tok, "--jwks-file", setPath); r.code != 0 || !strings.Contains(r.out, "jwks:ec1") {
		t.Errorf("jwks-file: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", tok, "--jwks-file", setPath, "--kid", "rsa1"); r.code != 1 || !strings.Contains(r.out, "✗ alg") {
		t.Errorf("wrong kid should fail alg check (ES384 vs RSA key): %+v", r)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(set)
	}))
	defer srv.Close()
	if r := runJWTHTTP(t, "", nil, srv.Client(), "verify", tok, "--jwks-url", srv.URL+"/jwks"); r.code != 0 || !strings.Contains(r.out, "jwks:ec1") {
		t.Errorf("jwks-url: %+v", r)
	}
	if r := runJWTHTTP(t, "", nil, srv.Client(), "verify", tok, "--jwks-url", "http://example.com/jwks"); r.code != 2 || !strings.Contains(r.err, "https") {
		t.Errorf("plain http: %+v", r)
	}
}

func TestVerifyNone(t *testing.T) {
	s := runJWT(t, "", nil, "sign", "--alg", "none", "--claim", "a=b")
	tok := strings.TrimSpace(s.out)
	if r := runJWT(t, "", nil, "verify", tok); r.code != 1 || !strings.Contains(r.out, "--insecure-allow-none") {
		t.Errorf("none default: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", tok, "--insecure-allow-none"); r.code != 0 || !strings.Contains(r.out, "VALID") {
		t.Errorf("none allowed: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret); r.code != 1 {
		t.Errorf("none with key: %+v", r)
	}
}

func TestVerifyUsageErrors(t *testing.T) {
	tok := signedToken(t)
	if r := runJWT(t, "", nil, "verify", tok); r.code != 2 || !strings.Contains(r.err, "no key provided") {
		t.Errorf("missing key: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", "garbage", "--secret", testSecret); r.code != 2 {
		t.Errorf("garbage: %+v", r)
	}
	if r := runJWT(t, "", map[string]string{"JWT_SECRET": testSecret}, "verify", tok); r.code != 0 {
		t.Errorf("env secret: %+v", r)
	}
}

// TestVerifyJWKAlgAndUse covers the two JWK members that constrain a key:
// "alg" narrows the default allowlist, and "use": "enc" disqualifies the
// key for signature verification entirely.
func TestVerifyJWKAlgAndUse(t *testing.T) {
	priv, _, rsaKey := rsaPair(t)
	s := runJWT(t, "", nil, "sign", "--key", priv, "--alg", "PS256", "--kid", "r1", "--claim", "x=1")
	if s.code != 0 {
		t.Fatalf("sign: %+v", s)
	}
	tok := strings.TrimSpace(s.out)

	j, err := jwk.FromKey(&rsaKey.PublicKey, "r1")
	if err != nil {
		t.Fatal(err)
	}
	j.Alg = "RS256"
	set, _ := json.Marshal(jwk.Set{Keys: []jwk.Key{*j}})
	setPath := writeTemp(t, "alg.json", set)

	if r := runJWT(t, "", nil, "verify", tok, "--jwks-file", setPath); r.code != 1 || !strings.Contains(r.out, "✗ alg") {
		t.Errorf("alg RS256 must refuse a PS256 token: %+v", r)
	}
	if r := runJWT(t, "", nil, "verify", tok, "--jwks-file", setPath, "--alg", "PS256"); r.code != 0 {
		t.Errorf("explicit --alg PS256 should win: %+v", r)
	}

	encJ, err := jwk.FromKey(&rsaKey.PublicKey, "r1")
	if err != nil {
		t.Fatal(err)
	}
	encJ.Use = "enc"
	encSet, _ := json.Marshal(jwk.Set{Keys: []jwk.Key{*encJ}})
	encPath := writeTemp(t, "enc.json", encSet)
	if r := runJWT(t, "", nil, "verify", tok, "--jwks-file", encPath); r.code != 2 || !strings.Contains(r.err, "use=enc") {
		t.Errorf("use=enc key must be refused: %+v", r)
	}
}

func TestVerifyKidRequiresJWKSSource(t *testing.T) {
	s := runJWT(t, "", nil, "sign", "--secret", testSecret, "--claim", "x=1")
	tok := strings.TrimSpace(s.out)
	r := runJWT(t, "", nil, "verify", tok, "--secret", testSecret, "--kid", "k1")
	if r.code != 2 || !strings.Contains(r.err, "--kid applies only to JWKS sources") || r.out != "" {
		t.Errorf("got %+v", r)
	}
}
