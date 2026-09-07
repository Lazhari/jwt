package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

// testSecret is 32 bytes so no short-secret warning is printed.
const testSecret = "0123456789abcdef0123456789abcdef"

type runResult struct {
	code     int
	out, err string
}

// runJWT executes the CLI in-process with captured streams, a fixed clock,
// and a fake environment. Set env["__http__"] to nothing; use runJWTHTTP
// when a test needs an HTTP client.
func runJWT(t *testing.T, stdin string, env map[string]string, args ...string) runResult {
	t.Helper()
	return runJWTHTTP(t, stdin, env, nil, args...)
}

func runJWTHTTP(t *testing.T, stdin string, env map[string]string, client *http.Client, args ...string) runResult {
	t.Helper()
	var out, errb bytes.Buffer
	streams := &ioStreams{
		in:   strings.NewReader(stdin),
		out:  &out,
		err:  &errb,
		env:  func(k string) string { return env[k] },
		now:  func() time.Time { return testNow },
		http: client,
	}
	code := run(args, streams)
	return runResult{code: code, out: out.String(), err: errb.String()}
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil { //nolint:gosec // test helper builds paths under t.TempDir()
		t.Fatal(err)
	}
	return p
}

func pemFile(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	return writeTemp(t, name, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// rsaPair writes PKCS#8 private and PKIX public PEM files and returns both paths.
func rsaPair(t *testing.T) (priv, pub string, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return pemFile(t, "rsa.pem", "PRIVATE KEY", privDER), pemFile(t, "rsa.pub", "PUBLIC KEY", pubDER), key
}

func ecPair(t *testing.T, curve elliptic.Curve) (priv, pub string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return pemFile(t, "ec.pem", "PRIVATE KEY", privDER), pemFile(t, "ec.pub", "PUBLIC KEY", pubDER), key
}

func edPair(t *testing.T) (priv, pub string, key ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(key.Public())
	return pemFile(t, "ed.pem", "PRIVATE KEY", privDER), pemFile(t, "ed.pub", "PUBLIC KEY", pubDER), key
}

func ellipticP384() elliptic.Curve { return elliptic.P384() }
