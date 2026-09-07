package keys

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/lazhari/jwt/internal/jwk"
)

// Source describes where to get key material. At most one of the string
// fields other than KID may be set. Env, Stdin, HTTP, and Warn are injected
// so the package is testable; nil values fall back to os.Getenv, os.Stdin,
// a default client, and io.Discard.
type Source struct {
	Secret     string
	SecretB64  string
	SecretFile string
	KeyPath    string // PEM or JWK file, or "-" for stdin
	JWKSFile   string
	JWKSURL    string
	KID        string // overrides the token header kid for JWKS lookup

	Env   func(string) string
	Stdin io.Reader
	HTTP  *http.Client
	Warn  io.Writer
}

// ErrNoKey is returned when no source is set and no env fallback exists.
var ErrNoKey = errors.New("no key provided: use --secret, --secret-b64, --secret-file, --key, --jwks-file, or --jwks-url, or set JWT_SECRET or JWT_KEY")

// minSecretBytes is the RFC 7518 minimum for HS256. Longer hashes need more,
// but 32 is the floor every HMAC token should meet.
const minSecretBytes = 32

// Load resolves the key. hdr is the decoded token header (may be nil) and is
// used only for JWKS kid lookup.
func Load(src Source, hdr map[string]any) (*Key, error) {
	src.defaults()

	var sources []string
	for _, f := range []struct{ name, val string }{
		{"--secret", src.Secret},
		{"--secret-b64", src.SecretB64},
		{"--secret-file", src.SecretFile},
		{"--key", src.KeyPath},
		{"--jwks-file", src.JWKSFile},
		{"--jwks-url", src.JWKSURL},
	} {
		if f.val != "" {
			sources = append(sources, f.name)
		}
	}
	if len(sources) > 1 {
		return nil, fmt.Errorf("use only one key source, got %s", strings.Join(sources, " and "))
	}

	switch {
	case src.Secret != "":
		return src.secret([]byte(src.Secret), "secret")
	case src.SecretB64 != "":
		b, err := DecodeSecretB64(src.SecretB64)
		if err != nil {
			return nil, fmt.Errorf("--secret-b64: %w", err)
		}
		return src.secret(b, "secret-b64")
	case src.SecretFile != "":
		b, err := os.ReadFile(src.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("--secret-file: %w", err)
		}
		return src.secret(bytes.TrimRight(StripBOM(b), "\r\n"), "secret-file:"+src.SecretFile)
	case src.KeyPath != "":
		data, label, err := src.readKeyInput(src.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("--key: %w", err)
		}
		return ParseMaterial(data, label, src.KID, hdr)
	case src.JWKSFile != "":
		b, err := os.ReadFile(src.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("--jwks-file: %w", err)
		}
		set, err := jwk.ParseSet(b)
		if err != nil {
			return nil, fmt.Errorf("--jwks-file: %w", err)
		}
		return selectFromSet(set, src.KID, hdr)
	case src.JWKSURL != "":
		b, err := Fetch(context.Background(), src.HTTP, src.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("--jwks-url: %w", err)
		}
		set, err := jwk.ParseSet(b)
		if err != nil {
			return nil, fmt.Errorf("--jwks-url: %w", err)
		}
		return selectFromSet(set, src.KID, hdr)
	}

	if v := src.Env("JWT_SECRET"); v != "" {
		return src.secret([]byte(v), "env:JWT_SECRET")
	}
	if v := src.Env("JWT_KEY"); v != "" {
		data, label, err := src.readKeyInput(v)
		if err != nil {
			return nil, fmt.Errorf("JWT_KEY: %w", err)
		}
		return ParseMaterial(data, label, src.KID, hdr)
	}
	return nil, ErrNoKey
}

func (src *Source) defaults() {
	if src.Env == nil {
		src.Env = os.Getenv
	}
	if src.Stdin == nil {
		src.Stdin = os.Stdin
	}
	if src.Warn == nil {
		src.Warn = io.Discard
	}
}

func (src *Source) secret(b []byte, source string) (*Key, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%s: secret is empty", source)
	}
	if len(b) < minSecretBytes {
		_, _ = fmt.Fprintf(src.Warn, "jwt: warning: secret is %d bytes; RFC 7518 requires at least %d bytes for HS256\n", len(b), minSecretBytes)
	}
	return FromMaterial(b, source)
}

// readKeyInput returns file or stdin contents plus a label for messages.
func (src *Source) readKeyInput(path string) ([]byte, string, error) {
	if path == "-" {
		b, err := io.ReadAll(src.Stdin)
		if err != nil {
			return nil, "", fmt.Errorf("reading stdin: %w", err)
		}
		return b, "stdin", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	return b, path, nil
}

// StripBOM removes a leading UTF-8 byte order mark (EF BB BF), which tools
// on Windows commonly write and which unicode.IsSpace does not treat as
// whitespace. Content sniffing and secret bytes must not include it.
func StripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}

// DecodeSecretB64 decodes standard or URL-safe base64, padded or not.
func DecodeSecretB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("not valid base64")
}

// ParseMaterial detects PEM, JWK, or JWKS content and returns the key. For a
// JWKS, kid (or hdr["kid"]) selects the key. label names the source in
// messages and in Key.Source.
func ParseMaterial(data []byte, label, kid string, hdr map[string]any) (*Key, error) {
	trimmed := bytes.TrimSpace(StripBOM(data))
	switch {
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN")):
		return parsePEM(trimmed, label)
	case bytes.HasPrefix(trimmed, []byte("{")):
		if jwk.IsSet(trimmed) {
			set, err := jwk.ParseSet(trimmed)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}
			return selectFromSet(set, kid, hdr)
		}
		j, err := jwk.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		return fromJWK(j, "jwk:"+label)
	}
	return nil, fmt.Errorf("%s: content is not PEM or JWK", label)
}

func parsePEM(data []byte, label string) (*Key, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		var (
			key any
			err error
		)
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "PUBLIC KEY":
			key, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		case "CERTIFICATE":
			var cert *x509.Certificate
			cert, err = x509.ParseCertificate(block.Bytes)
			if err == nil {
				key = cert.PublicKey
			}
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: parsing %s block: %w", label, block.Type, err)
		}
		return FromMaterial(key, "pem:"+label)
	}
	return nil, fmt.Errorf("%s: no supported PEM block found (expected RSA PRIVATE KEY, EC PRIVATE KEY, PRIVATE KEY, PUBLIC KEY, RSA PUBLIC KEY, or CERTIFICATE)", label)
}

func fromJWK(j *jwk.Key, source string) (*Key, error) {
	if j.Use == "enc" {
		return nil, fmt.Errorf("%s: key is marked use=enc and cannot verify signatures", source)
	}
	var (
		m   any
		err error
	)
	if j.IsPrivate() {
		m, err = j.Private()
	} else {
		m, err = j.Public()
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	k, err := FromMaterial(m, source)
	if err != nil {
		return nil, err
	}
	// A JWK may declare the one algorithm it is for (RFC 7517 section 4.4);
	// that narrows the default allowlist during verification.
	k.Alg = j.Alg
	return k, nil
}

// selectFromSet picks the key named by kid, then by the token header, then
// the only key present.
func selectFromSet(set *jwk.Set, kid string, hdr map[string]any) (*Key, error) {
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}
	if kid == "" {
		if v, ok := hdr["kid"].(string); ok {
			kid = v
		}
	}
	if kid == "" {
		if len(set.Keys) == 1 {
			return fromJWK(&set.Keys[0], "jwks:"+set.Keys[0].Kid)
		}
		return nil, fmt.Errorf("JWKS has %d keys and the token has no kid; pass --kid (available: %s)", len(set.Keys), strings.Join(set.KIDs(), ", "))
	}
	j, err := set.Lookup(kid)
	if err != nil {
		return nil, err
	}
	return fromJWK(j, "jwks:"+kid)
}
