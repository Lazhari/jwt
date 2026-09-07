// Package jwk parses and produces JSON Web Keys (RFC 7517) and JWK Sets for
// the key types the CLI supports: RSA, EC (P-256, P-384, P-521), OKP
// (Ed25519), and oct. It uses only the standard library.
package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Key is a JSON Web Key. Only the members the CLI understands are modelled;
// unknown members are ignored on parse and never emitted.
type Key struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	DP  string `json:"dp,omitempty"`
	DQ  string `json:"dq,omitempty"`
	QI  string `json:"qi,omitempty"`
	K   string `json:"k,omitempty"`
}

// Set is a JWK Set (RFC 7517 section 5).
type Set struct {
	Keys []Key `json:"keys"`
}

// minRSABits is the smallest RSA modulus accepted, per current guidance.
const minRSABits = 2048

// IsSet reports whether b looks like a JWK Set rather than a single key.
func IsSet(b []byte) bool {
	var probe struct {
		Keys json.RawMessage `json:"keys"`
	}
	return json.Unmarshal(b, &probe) == nil && probe.Keys != nil
}

// Parse decodes and validates a single JWK.
func Parse(b []byte) (*Key, error) {
	var k Key
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("invalid JWK JSON: %w", err)
	}
	if err := k.validate(); err != nil {
		return nil, err
	}
	return &k, nil
}

// ParseSet decodes and validates a JWK Set.
func ParseSet(b []byte) (*Set, error) {
	var s Set
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("invalid JWKS JSON: %w", err)
	}
	if s.Keys == nil {
		return nil, fmt.Errorf("invalid JWKS: missing \"keys\" array")
	}
	seen := make(map[string]bool, len(s.Keys))
	for i := range s.Keys {
		if err := s.Keys[i].validate(); err != nil {
			return nil, fmt.Errorf("JWKS key %d: %w", i, err)
		}
		// A repeated kid makes lookup ambiguous, so refuse the set rather
		// than silently picking the first match.
		if kid := s.Keys[i].Kid; kid != "" {
			if seen[kid] {
				return nil, fmt.Errorf("duplicate kid %q in JWKS", kid)
			}
			seen[kid] = true
		}
	}
	return &s, nil
}

// Lookup returns the key with the given kid.
func (s *Set) Lookup(kid string) (*Key, error) {
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("kid %q not found in JWKS (available: %s)", kid, strings.Join(s.KIDs(), ", "))
}

// KIDs lists the kid of every key, in order. Keys without a kid yield "".
func (s *Set) KIDs() []string {
	out := make([]string, len(s.Keys))
	for i, k := range s.Keys {
		out[i] = k.Kid
	}
	return out
}

// IsPrivate reports whether the key carries private material.
func (k *Key) IsPrivate() bool {
	switch k.Kty {
	case "oct":
		return true
	default:
		return k.D != ""
	}
}

// validate checks structure and key material without building Go keys that
// the caller may not need. It calls Public (and Private when present) so a
// key that parses is guaranteed to convert.
func (k *Key) validate() error {
	switch k.Kty {
	case "":
		return fmt.Errorf("invalid JWK: missing kty")
	case "RSA", "EC", "OKP", "oct":
	default:
		return fmt.Errorf("invalid JWK: unsupported kty %q", k.Kty)
	}
	if _, err := k.Public(); err != nil {
		return err
	}
	if k.IsPrivate() {
		if _, err := k.Private(); err != nil {
			return err
		}
	}
	return nil
}

// Public returns the public half as a Go crypto type. For oct keys it
// returns the secret bytes, since HMAC has no public half.
func (k *Key) Public() (any, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaPublic()
	case "EC":
		return k.ecPublic()
	case "OKP":
		return k.okpPublic()
	case "oct":
		return k.octBytes()
	}
	return nil, fmt.Errorf("invalid JWK: unsupported kty %q", k.Kty)
}

// Private returns the private key as a Go crypto type.
func (k *Key) Private() (any, error) {
	if !k.IsPrivate() {
		return nil, fmt.Errorf("JWK has no private members (kty %s)", k.Kty)
	}
	switch k.Kty {
	case "RSA":
		return k.rsaPrivate()
	case "EC":
		return k.ecPrivate()
	case "OKP":
		return k.okpPrivate()
	case "oct":
		return k.octBytes()
	}
	return nil, fmt.Errorf("invalid JWK: unsupported kty %q", k.Kty)
}

// FromKey builds a JWK from a Go crypto key. Accepted types: *rsa.PublicKey,
// *rsa.PrivateKey, *ecdsa.PublicKey, *ecdsa.PrivateKey, ed25519.PublicKey,
// ed25519.PrivateKey, []byte (oct).
func FromKey(key any, kid string) (*Key, error) {
	j := &Key{Kid: kid}
	switch x := key.(type) {
	case *rsa.PublicKey:
		j.Kty = "RSA"
		j.N = encBig(x.N)
		j.E = encBig(big.NewInt(int64(x.E)))
	case *rsa.PrivateKey:
		if len(x.Primes) != 2 {
			return nil, fmt.Errorf("RSA private key must have exactly two primes, got %d", len(x.Primes))
		}
		if err := x.Validate(); err != nil {
			return nil, fmt.Errorf("invalid RSA private key: %w", err)
		}
		x.Precompute()
		if x.Precomputed.Dp == nil || x.Precomputed.Dq == nil || x.Precomputed.Qinv == nil {
			return nil, fmt.Errorf("invalid RSA private key: precompute failed")
		}
		j.Kty = "RSA"
		j.N = encBig(x.N)
		j.E = encBig(big.NewInt(int64(x.E)))
		j.D = encBig(x.D)
		j.P = encBig(x.Primes[0])
		j.Q = encBig(x.Primes[1])
		j.DP = encBig(x.Precomputed.Dp)
		j.DQ = encBig(x.Precomputed.Dq)
		j.QI = encBig(x.Precomputed.Qinv)
	case *ecdsa.PublicKey:
		crv, err := curveName(x.Curve)
		if err != nil {
			return nil, err
		}
		j.Kty, j.Crv = "EC", crv
		if err := j.setECPoint(x); err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		crv, err := curveName(x.Curve)
		if err != nil {
			return nil, err
		}
		j.Kty, j.Crv = "EC", crv
		if err := j.setECPoint(&x.PublicKey); err != nil {
			return nil, err
		}
		d, err := x.Bytes()
		if err != nil {
			return nil, err
		}
		j.D = enc(d)
	case ed25519.PublicKey:
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(x))
		}
		j.Kty, j.Crv = "OKP", "Ed25519"
		j.X = enc(x)
	case ed25519.PrivateKey:
		if len(x) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(x))
		}
		j.Kty, j.Crv = "OKP", "Ed25519"
		j.X = enc(x.Public().(ed25519.PublicKey))
		j.D = enc(x.Seed())
	case []byte:
		j.Kty = "oct"
		j.K = enc(x)
	default:
		return nil, fmt.Errorf("cannot build JWK from %T", key)
	}
	return j, nil
}

// setECPoint fills x and y from the uncompressed public point.
func (k *Key) setECPoint(pub *ecdsa.PublicKey) error {
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil {
		return err
	}
	size := (len(raw) - 1) / 2
	k.X = enc(raw[1 : 1+size])
	k.Y = enc(raw[1+size:])
	return nil
}

// ---- RSA ----

func (k *Key) rsaPublic() (*rsa.PublicKey, error) {
	if k.N == "" {
		return nil, fmt.Errorf("invalid RSA JWK: missing n")
	}
	if k.E == "" {
		return nil, fmt.Errorf("invalid RSA JWK: missing e")
	}
	n, err := decBig("n", k.N)
	if err != nil {
		return nil, err
	}
	e, err := decBig("e", k.E)
	if err != nil {
		return nil, err
	}
	if n.BitLen() < minRSABits {
		return nil, fmt.Errorf("invalid RSA JWK: modulus is %d bits, minimum is %d", n.BitLen(), minRSABits)
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > int64(^uint32(0)) {
		return nil, fmt.Errorf("invalid RSA JWK: exponent out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func (k *Key) rsaPrivate() (*rsa.PrivateKey, error) {
	pub, err := k.rsaPublic()
	if err != nil {
		return nil, err
	}
	if k.P == "" || k.Q == "" {
		return nil, fmt.Errorf("invalid RSA JWK: private key without p and q is not supported")
	}
	d, err := decBig("d", k.D)
	if err != nil {
		return nil, err
	}
	p, err := decBig("p", k.P)
	if err != nil {
		return nil, err
	}
	q, err := decBig("q", k.Q)
	if err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{PublicKey: *pub, D: d, Primes: []*big.Int{p, q}}
	priv.Precompute()
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RSA JWK: %w", err)
	}
	return priv, nil
}

// ---- EC ----

func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("invalid EC JWK: unsupported crv %q (use P-256, P-384, or P-521)", name)
}

func curveName(c elliptic.Curve) (string, error) {
	if c == nil {
		return "", fmt.Errorf("unsupported elliptic curve: nil")
	}
	switch c {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	}
	return "", fmt.Errorf("unsupported elliptic curve %q", c.Params().Name)
}

func (k *Key) ecPublic() (*ecdsa.PublicKey, error) {
	curve, err := curveByName(k.Crv)
	if err != nil {
		return nil, err
	}
	if k.X == "" {
		return nil, fmt.Errorf("invalid EC JWK: missing x")
	}
	if k.Y == "" {
		return nil, fmt.Errorf("invalid EC JWK: missing y")
	}
	x, err := dec("x", k.X)
	if err != nil {
		return nil, err
	}
	y, err := dec("y", k.Y)
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size {
		return nil, fmt.Errorf("invalid EC JWK: coordinate longer than %d bytes for %s", size, k.Crv)
	}
	raw := make([]byte, 1+2*size)
	raw[0] = 4
	copy(raw[1+size-len(x):], x)
	copy(raw[1+2*size-len(y):], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid EC JWK: point is not on curve %s: %w", k.Crv, err)
	}
	return pub, nil
}

func (k *Key) ecPrivate() (*ecdsa.PrivateKey, error) {
	pub, err := k.ecPublic()
	if err != nil {
		return nil, err
	}
	d, err := dec("d", k.D)
	if err != nil {
		return nil, err
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(d) > size {
		return nil, fmt.Errorf("invalid EC JWK: d longer than %d bytes for %s", size, k.Crv)
	}
	padded := make([]byte, size)
	copy(padded[size-len(d):], d)
	priv, err := ecdsa.ParseRawPrivateKey(pub.Curve, padded)
	if err != nil {
		return nil, fmt.Errorf("invalid EC JWK: %w", err)
	}
	if !priv.PublicKey.Equal(pub) {
		return nil, fmt.Errorf("invalid EC JWK: d does not match x,y")
	}
	return priv, nil
}

// ---- OKP ----

func (k *Key) okpPublic() (ed25519.PublicKey, error) {
	if k.Crv != "Ed25519" {
		return nil, fmt.Errorf("invalid OKP JWK: unsupported crv %q (only Ed25519)", k.Crv)
	}
	if k.X == "" {
		return nil, fmt.Errorf("invalid OKP JWK: missing x")
	}
	x, err := dec("x", k.X)
	if err != nil {
		return nil, err
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid OKP JWK: x must be 32 bytes, got %d", len(x))
	}
	return ed25519.PublicKey(x), nil
}

func (k *Key) okpPrivate() (ed25519.PrivateKey, error) {
	pub, err := k.okpPublic()
	if err != nil {
		return nil, err
	}
	d, err := dec("d", k.D)
	if err != nil {
		return nil, err
	}
	if len(d) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid OKP JWK: d must be 32 bytes, got %d", len(d))
	}
	priv := ed25519.NewKeyFromSeed(d)
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		return nil, fmt.Errorf("invalid OKP JWK: d does not match x")
	}
	return priv, nil
}

// ---- oct ----

func (k *Key) octBytes() ([]byte, error) {
	if k.K == "" {
		return nil, fmt.Errorf("invalid oct JWK: missing k")
	}
	return dec("k", k.K)
}

// ---- encoding helpers ----

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func encBig(n *big.Int) string { return enc(n.Bytes()) }

// dec decodes base64url, tolerating padding and the standard alphabet since
// keys in the wild are often produced by tools that pad.
func dec(member, s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid JWK: member %q is not base64url", member)
	}
	return b, nil
}

func decBig(member, s string) (*big.Int, error) {
	b, err := dec(member, s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
