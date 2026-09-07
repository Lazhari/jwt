// Package keys resolves signing and verification key material from every
// source the CLI accepts and knows which JWS algorithms each key type
// supports.
package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"
)

// Kind classifies key material by the algorithm family it can serve.
type Kind int

// The key kinds the CLI supports. Each maps to one family of JWS
// algorithms; see algsByKind.
const (
	HMAC Kind = iota + 1
	RSA
	EC
	Ed25519
)

// String names the kind for messages. The receiver is kd so it does not
// clash with the k used by the *Key methods below.
func (kd Kind) String() string {
	switch kd {
	case HMAC:
		return "HMAC"
	case RSA:
		return "RSA"
	case EC:
		return "EC"
	case Ed25519:
		return "Ed25519"
	}
	return "unknown"
}

// Key is resolved key material plus where it came from.
type Key struct {
	// Material is []byte, *rsa.PrivateKey, *rsa.PublicKey, *ecdsa.PrivateKey,
	// *ecdsa.PublicKey, ed25519.PrivateKey, or ed25519.PublicKey.
	Material any
	Kind     Kind
	Private  bool
	// Alg is the algorithm declared by a JWK, if any.
	Alg string
	// Source is a label for messages: "secret", "env:JWT_SECRET",
	// "pem:key.pem", "jwks:kid".
	Source string
}

// FromMaterial wraps a Go crypto key.
func FromMaterial(m any, source string) (*Key, error) {
	k := &Key{Material: m, Source: source}
	switch m.(type) {
	case []byte:
		k.Kind, k.Private = HMAC, true
	case *rsa.PrivateKey:
		k.Kind, k.Private = RSA, true
	case *rsa.PublicKey:
		k.Kind = RSA
	case *ecdsa.PrivateKey:
		k.Kind, k.Private = EC, true
	case *ecdsa.PublicKey:
		k.Kind = EC
	case ed25519.PrivateKey:
		k.Kind, k.Private = Ed25519, true
	case ed25519.PublicKey:
		k.Kind = Ed25519
	default:
		return nil, fmt.Errorf("%s: unsupported key type %T", source, m)
	}
	return k, nil
}

// PublicMaterial returns the material to verify with. For HMAC that is the
// secret itself; for asymmetric private keys it is the public half.
func (k *Key) PublicMaterial() any {
	switch m := k.Material.(type) {
	case *rsa.PrivateKey:
		return &m.PublicKey
	case *ecdsa.PrivateKey:
		return &m.PublicKey
	case ed25519.PrivateKey:
		return m.Public().(ed25519.PublicKey)
	}
	return k.Material
}

// curve returns the curve of an EC key, or nil.
func (k *Key) curve() elliptic.Curve {
	switch m := k.Material.(type) {
	case *ecdsa.PrivateKey:
		return m.Curve
	case *ecdsa.PublicKey:
		return m.Curve
	}
	return nil
}

var algsByKind = map[Kind][]string{
	HMAC:    {"HS256", "HS384", "HS512"},
	RSA:     {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"},
	EC:      {"ES256", "ES384", "ES512"},
	Ed25519: {"EdDSA"},
}

var kindOrder = []Kind{HMAC, RSA, EC, Ed25519}

// AllAlgs lists every supported signing algorithm, HMAC first.
func AllAlgs() []string {
	var out []string
	for _, k := range kindOrder {
		out = append(out, algsByKind[k]...)
	}
	return out
}

// AlgsFor lists the algorithms a key kind can serve.
func AlgsFor(kind Kind) []string {
	return append([]string(nil), algsByKind[kind]...)
}

// KindOf maps an algorithm name to its key kind. "none" has no kind.
func KindOf(alg string) (Kind, bool) {
	for kind, algs := range algsByKind {
		for _, a := range algs {
			if a == alg {
				return kind, true
			}
		}
	}
	return 0, false
}

// esCurve maps ES algorithms to the curve RFC 7518 requires.
var esCurve = map[string]elliptic.Curve{
	"ES256": elliptic.P256(),
	"ES384": elliptic.P384(),
	"ES512": elliptic.P521(),
}

// DefaultAlg picks the conventional algorithm for a key.
func DefaultAlg(k *Key) string {
	switch k.Kind {
	case HMAC:
		return "HS256"
	case RSA:
		return "RS256"
	case EC:
		switch k.curve() {
		case elliptic.P384():
			return "ES384"
		case elliptic.P521():
			return "ES512"
		default:
			return "ES256"
		}
	case Ed25519:
		return "EdDSA"
	}
	return ""
}

// article returns the indefinite article that reads correctly before a kind
// name. Every current kind is either spelled out letter by letter (HMAC,
// RSA, EC) or starts with a vowel sound (Ed25519), so they all take "an".
func article(kd Kind) string {
	switch kd {
	case HMAC, RSA, EC, Ed25519:
		return "an"
	}
	return "a"
}

// Compatible reports whether the key can be used with alg. "none" is always
// compatible since it uses no key.
func Compatible(k *Key, alg string) error {
	if alg == "none" {
		return nil
	}
	kind, ok := KindOf(alg)
	if !ok {
		return fmt.Errorf("unsupported algorithm %q (supported: %s, none)", alg, strings.Join(AllAlgs(), ", "))
	}
	if kind != k.Kind {
		return fmt.Errorf("algorithm %s needs %s %s key, but %s is %s %s key", alg, article(kind), kind, k.Source, article(k.Kind), k.Kind)
	}
	if want, isES := esCurve[alg]; isES && k.curve() != want {
		return fmt.Errorf("algorithm %s needs curve %s, but %s uses %s", alg, want.Params().Name, k.Source, k.curve().Params().Name)
	}
	return nil
}
