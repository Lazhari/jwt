package token

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lazhari/jwt/internal/keys"
)

func mustKey(t *testing.T, m any) *keys.Key {
	t.Helper()
	k, err := keys.FromMaterial(m, "test")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignAllAlgorithmsVerifyWithLibrary(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	secret := []byte(strings.Repeat("s", 64))

	cases := []struct {
		alg  string
		priv any
		pub  any
	}{
		{"HS256", secret, secret}, {"HS384", secret, secret}, {"HS512", secret, secret},
		{"RS256", rsaKey, &rsaKey.PublicKey}, {"RS384", rsaKey, &rsaKey.PublicKey}, {"RS512", rsaKey, &rsaKey.PublicKey},
		{"PS256", rsaKey, &rsaKey.PublicKey}, {"PS384", rsaKey, &rsaKey.PublicKey}, {"PS512", rsaKey, &rsaKey.PublicKey},
		{"ES256", p256, &p256.PublicKey}, {"ES384", p384, &p384.PublicKey}, {"ES512", p521, &p521.PublicKey},
		{"EdDSA", edKey, edKey.Public()},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			tok, err := Sign(SignInput{
				Payload: map[string]any{"sub": "u", "n": json.Number("42")},
				Header:  map[string]any{"kid": "k1"},
				Alg:     c.alg,
				Key:     mustKey(t, c.priv),
			})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := jwt.NewParser(jwt.WithValidMethods([]string{c.alg})).Parse(tok, func(*jwt.Token) (any, error) { return c.pub, nil })
			if err != nil {
				t.Fatalf("library rejected our token: %v", err)
			}
			if parsed.Header["kid"] != "k1" || parsed.Header["typ"] != "JWT" {
				t.Errorf("header = %v", parsed.Header)
			}
			if parsed.Claims.(jwt.MapClaims)["n"] != float64(42) {
				t.Errorf("claims = %v", parsed.Claims)
			}
		})
	}
}

func TestSignDefaultAlgFromKey(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tok, err := Sign(SignInput{Payload: map[string]any{}, Key: mustKey(t, p384)})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := Decode(tok)
	if d.Header["alg"] != "ES384" {
		t.Errorf("alg = %v", d.Header["alg"])
	}
}

func TestSignNone(t *testing.T) {
	tok, err := Sign(SignInput{Payload: map[string]any{"a": "b"}, Alg: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(tok, ".") {
		t.Errorf("none token should end with a dot: %s", tok)
	}
	d, _ := Decode(tok)
	if d.Header["alg"] != "none" {
		t.Errorf("alg = %v", d.Header["alg"])
	}
}

func TestSignErrors(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := mustKey(t, &rsaKey.PublicKey)
	priv := mustKey(t, rsaKey)
	tests := []struct {
		name string
		in   SignInput
		want string
	}{
		{"unsupported alg", SignInput{Alg: "XX1", Key: priv}, "unsupported algorithm"},
		{"no key", SignInput{Alg: "HS256"}, "needs a key"},
		{"no key no alg", SignInput{}, "no key"},
		{"public key", SignInput{Alg: "RS256", Key: pub}, "private key"},
		{"incompatible", SignInput{Alg: "HS256", Key: priv}, "HMAC"},
		{"alg in header", SignInput{Alg: "RS256", Key: priv, Header: map[string]any{"alg": "none"}}, "--alg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.in.Payload == nil {
				tt.in.Payload = map[string]any{}
			}
			_, err := Sign(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
