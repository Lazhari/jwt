package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// RFC 7517 Appendix A.2, first key (EC P-256 private).
const rfc7517ECPrivate = `{"kty":"EC","crv":"P-256",
  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
  "use":"enc","kid":"1"}`

// RFC 7515 Appendix A.1 HMAC key and the JWS it signs.
const rfc7515OctKey = `{"kty":"oct",
  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`

const rfc7515JWS = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func TestParseECPrivateFromRFC(t *testing.T) {
	k, err := Parse([]byte(rfc7517ECPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if !k.IsPrivate() {
		t.Fatal("expected private key")
	}
	priv, err := k.Private()
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("got %T", priv)
	}
	if ecPriv.Curve != elliptic.P256() {
		t.Errorf("curve = %v", ecPriv.Curve.Params().Name)
	}
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !ecPriv.PublicKey.Equal(pub) {
		t.Error("public key derived from d does not match x,y")
	}
}

func TestOctKeyVerifiesRFC7515Token(t *testing.T) {
	k, err := Parse([]byte(rfc7515OctKey))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := k.Private()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewParser(jwt.WithoutClaimsValidation()).Parse(rfc7515JWS, func(*jwt.Token) (any, error) {
		return secret, nil
	})
	if err != nil {
		t.Fatalf("RFC 7515 A.1 token failed to verify with RFC key: %v", err)
	}
	if !tok.Valid {
		t.Error("token not valid")
	}
}

func TestRoundTripAllTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKeys := map[string]*ecdsa.PrivateKey{}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecKeys[c.Params().Name] = k
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")

	inputs := map[string]any{
		"rsa-private":     rsaKey,
		"rsa-public":      &rsaKey.PublicKey,
		"ec-p256-private": ecKeys["P-256"],
		"ec-p384-private": ecKeys["P-384"],
		"ec-p521-private": ecKeys["P-521"],
		"ec-p256-public":  &ecKeys["P-256"].PublicKey,
		"ed-private":      edPriv,
		"ed-public":       edPub,
		"oct":             secret,
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			j, err := FromKey(in, "kid-"+name)
			if err != nil {
				t.Fatal(err)
			}
			if j.Kid != "kid-"+name {
				t.Errorf("kid = %q", j.Kid)
			}
			b, err := json.Marshal(j)
			if err != nil {
				t.Fatal(err)
			}
			back, err := Parse(b)
			if err != nil {
				t.Fatalf("Parse(marshalled) failed: %v\n%s", err, b)
			}
			wantPrivate := strings.HasSuffix(name, "private") || name == "oct"
			if back.IsPrivate() != wantPrivate {
				t.Errorf("IsPrivate = %v, want %v", back.IsPrivate(), wantPrivate)
			}
			var got any
			if wantPrivate {
				got, err = back.Private()
			} else {
				got, err = back.Public()
			}
			if err != nil {
				t.Fatal(err)
			}
			if !equalKeys(t, in, got) {
				t.Errorf("round trip mismatch for %s", name)
			}
		})
	}
}

func equalKeys(t *testing.T, a, b any) bool {
	t.Helper()
	switch x := a.(type) {
	case []byte:
		y, ok := b.([]byte)
		return ok && string(x) == string(y)
	case *rsa.PrivateKey:
		y, ok := b.(*rsa.PrivateKey)
		return ok && x.Equal(y)
	case *rsa.PublicKey:
		y, ok := b.(*rsa.PublicKey)
		return ok && x.Equal(y)
	case *ecdsa.PrivateKey:
		y, ok := b.(*ecdsa.PrivateKey)
		return ok && x.Equal(y)
	case *ecdsa.PublicKey:
		y, ok := b.(*ecdsa.PublicKey)
		return ok && x.Equal(y)
	case ed25519.PrivateKey:
		y, ok := b.(ed25519.PrivateKey)
		return ok && x.Equal(y)
	case ed25519.PublicKey:
		y, ok := b.(ed25519.PublicKey)
		return ok && x.Equal(y)
	}
	t.Fatalf("unexpected type %T", a)
	return false
}

func TestParseRejectsBadKeys(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // substring of error
	}{
		{"not json", `nope`, "invalid JWK JSON"},
		{"unknown kty", `{"kty":"XYZ"}`, `unsupported kty "XYZ"`},
		{"missing kty", `{"n":"a"}`, "missing kty"},
		{"ec bad curve", `{"kty":"EC","crv":"P-999","x":"AA","y":"AA"}`, `unsupported crv "P-999"`},
		{"ec point off curve", `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"}`, "not on curve"},
		{"ec missing y", `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"}`, "missing y"},
		{"okp bad curve", `{"kty":"OKP","crv":"X25519","x":"AA"}`, `unsupported crv "X25519"`},
		{"okp short x", `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`, "32 bytes"},
		{"rsa missing e", `{"kty":"RSA","n":"AQAB"}`, "missing e"},
		{"rsa small modulus", `{"kty":"RSA","n":"AQAB","e":"AQAB"}`, "2048"},
		{"oct missing k", `{"kty":"oct"}`, "missing k"},
		{"bad base64", `{"kty":"oct","k":"!!!"}`, "base64url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.in))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestRSAPrivateWithoutPrimesRejected(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	j, err := FromKey(&rsaKey.PublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	j.D = "AQAB" // private member present, primes absent
	b, _ := json.Marshal(j)
	_, err = Parse(b)
	if err == nil || !strings.Contains(err.Error(), "p and q") {
		t.Errorf("err = %v, want mention of p and q", err)
	}
}

func TestPublicOnPrivateKeyStripsPrivateMembers(t *testing.T) {
	k, err := Parse([]byte(rfc7517ECPrivate))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("got %T", pub)
	}
	if _, err := Parse([]byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`)); err != nil {
		t.Fatal(err)
	}
	pubOnly, _ := Parse([]byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`))
	if _, err := pubOnly.Private(); err == nil {
		t.Error("Private() on a public-only key should fail")
	}
}

func TestSet(t *testing.T) {
	set := `{"keys":[` + rfc7517ECPrivate + `,` + rfc7515OctKey + `]}`
	if !IsSet([]byte(set)) {
		t.Error("IsSet should be true")
	}
	if IsSet([]byte(rfc7517ECPrivate)) {
		t.Error("IsSet should be false for a single key")
	}
	s, err := ParseSet([]byte(set))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Keys) != 2 {
		t.Fatalf("got %d keys", len(s.Keys))
	}
	if got := s.KIDs(); len(got) != 2 || got[0] != "1" || got[1] != "" {
		t.Errorf("KIDs = %q", got)
	}
	if _, err := s.Lookup("1"); err != nil {
		t.Error(err)
	}
	if _, err := s.Lookup("nope"); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("Lookup(nope) err = %v", err)
	}
	if _, err := ParseSet([]byte(`{"nokeys":[]}`)); err == nil {
		t.Error("ParseSet without keys should fail")
	}
	if _, err := ParseSet([]byte(`{"keys":[{"kty":"XYZ"}]}`)); err == nil {
		t.Error("ParseSet with a bad key should fail")
	}
}

// TestSetDuplicateKidRejected pins the ruling that a repeated kid makes
// lookup ambiguous, so the whole set is refused. An empty kid may repeat.
func TestSetDuplicateKidRejected(t *testing.T) {
	dup := `{"keys":[` + rfc7517ECPrivate + `,` + rfc7517ECPrivate + `]}`
	_, err := ParseSet([]byte(dup))
	if err == nil || !strings.Contains(err.Error(), `duplicate kid "1"`) {
		t.Errorf("err = %v", err)
	}
	noKid := strings.ReplaceAll(rfc7517ECPrivate, `"kid":"1"`, `"kid":""`)
	if _, err := ParseSet([]byte(`{"keys":[` + noKid + `,` + noKid + `]}`)); err != nil {
		t.Errorf("keys without a kid may repeat: %v", err)
	}
}

func TestPaddedBase64Accepted(t *testing.T) {
	k, err := Parse([]byte(`{"kty":"oct","k":"c2VjcmV0MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Private(); err != nil {
		t.Fatal(err)
	}
}

// TestFromKeyRejectsMalformedInputWithoutPanicking exercises the malformed
// Go crypto key vectors identified in review: a two-prime but degenerate RSA
// key (Precompute silently fails, leaving Precomputed.Dp nil), an
// *ecdsa.PublicKey with a nil Curve, and ed25519 public/private keys of the
// wrong length. FromKey must return an error, not panic, for each.
func TestFromKeyRejectsMalformedInputWithoutPanicking(t *testing.T) {
	t.Run("rsa degenerate primes", func(t *testing.T) {
		k := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17},
			D:         big.NewInt(413),
			Primes:    []*big.Int{big.NewInt(0), big.NewInt(0)},
		}
		if _, err := FromKey(k, "k"); err == nil {
			t.Error("expected error, got nil")
		}
	})
	t.Run("ec nil curve", func(t *testing.T) {
		if _, err := FromKey(&ecdsa.PublicKey{}, "k"); err == nil {
			t.Error("expected error, got nil")
		}
	})
	t.Run("ed25519 public wrong length", func(t *testing.T) {
		if _, err := FromKey(ed25519.PublicKey([]byte{1, 2, 3}), "k"); err == nil {
			t.Error("expected error, got nil")
		}
	})
	t.Run("ed25519 private wrong length", func(t *testing.T) {
		if _, err := FromKey(ed25519.PrivateKey([]byte{1, 2, 3}), "k"); err == nil {
			t.Error("expected error, got nil")
		}
	})
}

// TestParseRejectsMismatchedECKeyMaterial builds a JWK whose x,y come from
// one EC key and whose d comes from an unrelated EC key on the same curve,
// and checks that Parse rejects it via the d-does-not-match-x,y consistency
// check in ecPrivate.
func TestParseRejectsMismatchedECKeyMaterial(t *testing.T) {
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aj, err := FromKey(a, "")
	if err != nil {
		t.Fatal(err)
	}
	bj, err := FromKey(b, "")
	if err != nil {
		t.Fatal(err)
	}
	mixed := *aj
	mixed.D = bj.D
	data, err := json.Marshal(&mixed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(data)
	if err == nil || !strings.Contains(err.Error(), "d does not match x,y") {
		t.Errorf("err = %v, want mention of d does not match x,y", err)
	}
}

// TestParseRejectsMismatchedOKPKeyMaterial builds a JWK whose x comes from
// one Ed25519 key and whose d comes from an unrelated Ed25519 key, and
// checks that Parse rejects it via the d-does-not-match-x consistency check
// in okpPrivate.
func TestParseRejectsMismatchedOKPKeyMaterial(t *testing.T) {
	aPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aj, err := FromKey(aPub, "")
	if err != nil {
		t.Fatal(err)
	}
	bj, err := FromKey(bPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	mixed := *aj
	mixed.D = bj.D
	data, err := json.Marshal(&mixed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(data)
	if err == nil || !strings.Contains(err.Error(), "d does not match x") {
		t.Errorf("err = %v, want mention of d does not match x", err)
	}
}

// TestParseRejectsMismatchedRSAKeyMaterial builds a JWK whose n, e, d come
// from one RSA key and whose p, q come from an unrelated RSA key, and checks
// that Parse rejects it via rsa.PrivateKey.Validate (p * q != n).
func TestParseRejectsMismatchedRSAKeyMaterial(t *testing.T) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	aj, err := FromKey(a, "")
	if err != nil {
		t.Fatal(err)
	}
	bj, err := FromKey(b, "")
	if err != nil {
		t.Fatal(err)
	}
	mixed := *aj
	mixed.P = bj.P
	mixed.Q = bj.Q
	mixed.DP = ""
	mixed.DQ = ""
	mixed.QI = ""
	data, err := json.Marshal(&mixed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(data)
	if err == nil || !strings.Contains(err.Error(), "p * q != n") {
		t.Errorf("err = %v, want mention of p * q != n", err)
	}
}
