package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lazhari/jwt/internal/jwk"
	"github.com/lazhari/jwt/internal/keys"
)

func TestKeygenHMAC(t *testing.T) {
	for alg, n := range map[string]int{"HS256": 32, "HS384": 48, "HS512": 64} {
		r := runJWT(t, "", nil, "keygen", "--alg", alg)
		if r.code != 0 || r.err != "" {
			t.Fatalf("%s: %+v", alg, r)
		}
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(r.out))
		if err != nil || len(b) != n {
			t.Errorf("%s: secret = %q (%d bytes, %v)", alg, r.out, len(b), err)
		}
	}
	r := runJWT(t, "", nil, "keygen", "--alg", "HS256", "--format", "jwk", "--kid", "s1")
	k, err := jwk.Parse([]byte(r.out))
	if err != nil || k.Kty != "oct" || k.Kid != "s1" {
		t.Errorf("jwk: %v %+v", err, r)
	}
}

func TestKeygenAsymmetricPEM(t *testing.T) {
	for _, alg := range []string{"RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			dir := t.TempDir()
			priv := filepath.Join(dir, "key.pem")
			pub := filepath.Join(dir, "key.pub")
			r := runJWT(t, "", nil, "keygen", "--alg", alg, "--out", priv, "--pub", pub)
			if r.code != 0 || r.out != "" {
				t.Fatalf("got %+v", r)
			}
			// Windows has no POSIX mode bits: Go reports 0666 for any
			// writable file, so the 0600 promise is Unix-only.
			if runtime.GOOS != "windows" {
				info, _ := os.Stat(priv)
				if info.Mode().Perm() != 0o600 {
					t.Errorf("private key mode = %o", info.Mode().Perm())
				}
			}
			pk, err := keys.Load(keys.Source{KeyPath: priv, Env: func(string) string { return "" }}, nil)
			if err != nil || !pk.Private || keys.DefaultAlg(pk) != strings.Replace(alg, "PS", "RS", 1) {
				t.Errorf("private: %v %+v", err, pk)
			}
			pubKey, err := keys.Load(keys.Source{KeyPath: pub, Env: func(string) string { return "" }}, nil)
			if err != nil || pubKey.Private || pubKey.Kind != pk.Kind {
				t.Errorf("public: %v %+v", err, pubKey)
			}
			// Round trip through the CLI.
			s := runJWT(t, "", nil, "sign", "--key", priv, "--alg", alg, "--claim", "x=1")
			if v := runJWT(t, "", nil, "verify", strings.TrimSpace(s.out), "--key", pub); v.code != 0 {
				t.Errorf("round trip: %+v", v)
			}
		})
	}
}

func TestKeygenJWKToStdout(t *testing.T) {
	r := runJWT(t, "", nil, "keygen", "--alg", "ES256", "--format", "jwk", "--kid", "k1")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	k, err := jwk.Parse([]byte(r.out))
	if err != nil || k.Kty != "EC" || k.Crv != "P-256" || !k.IsPrivate() || k.Kid != "k1" {
		t.Errorf("jwk = %+v err = %v", k, err)
	}
	pub := filepath.Join(t.TempDir(), "pub.json")
	r = runJWT(t, "", nil, "keygen", "--alg", "RS256", "--format", "jwk", "--pub", pub)
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	if _, err := jwk.Parse([]byte(r.out)); err != nil {
		t.Errorf("stdout private jwk: %v", err)
	}
	b, _ := os.ReadFile(pub)
	pk, err := jwk.Parse(b)
	if err != nil || pk.IsPrivate() {
		t.Errorf("pub jwk: %v %+v", err, pk)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, hasD := m["d"]; hasD {
		t.Error("public JWK must not contain d")
	}
}

func TestKeygenErrors(t *testing.T) {
	existing := writeTemp(t, "exists.pem", []byte("x"))
	for name, tt := range map[string]struct {
		args []string
		want string
	}{
		"bad alg":          {[]string{"keygen", "--alg", "none"}, "--alg"},
		"small rsa":        {[]string{"keygen", "--alg", "RS256", "--bits", "1024"}, "2048"},
		"bad format":       {[]string{"keygen", "--format", "der"}, "--format"},
		"pub for hmac":     {[]string{"keygen", "--alg", "HS256", "--pub", "x"}, "--pub"},
		"no overwrite":     {[]string{"keygen", "--alg", "ES256", "--out", existing}, "already exists"},
		"pub no overwrite": {[]string{"keygen", "--alg", "ES256", "--pub", existing}, "already exists"},
	} {
		t.Run(name, func(t *testing.T) {
			r := runJWT(t, "", nil, tt.args...)
			if r.code != 2 || !strings.Contains(r.err, tt.want) {
				t.Errorf("got %+v, want %q", r, tt.want)
			}
			if r.out != "" {
				t.Errorf("stdout must stay empty on error, got %q", r.out)
			}
		})
	}
	if b, _ := os.ReadFile(existing); string(b) != "x" {
		t.Error("existing file was overwritten")
	}
}

// TestKeygenBitsRejectedForNonRSA pins the ruling that a flag which cannot
// apply is a usage error rather than something silently ignored.
func TestKeygenBitsRejectedForNonRSA(t *testing.T) {
	r := runJWT(t, "", nil, "keygen", "--alg", "ES256", "--bits", "4096")
	if r.code != 2 || !strings.Contains(r.err, "--bits applies only to RSA algorithms") || r.out != "" {
		t.Fatalf("got %+v", r)
	}
	// The default value is not "set", so EC generation still works.
	if ok := runJWT(t, "", nil, "keygen", "--alg", "ES256"); ok.code != 0 {
		t.Errorf("unset --bits must not block EC keygen: %+v", ok)
	}
}

// TestKeygenKidRejectedForPEM covers the other inapplicable keygen flag:
// PEM output has nowhere to put a kid.
func TestKeygenKidRejectedForPEM(t *testing.T) {
	r := runJWT(t, "", nil, "keygen", "--alg", "ES256", "--kid", "k1")
	if r.code != 2 || !strings.Contains(r.err, "--kid applies only to --format jwk") || r.out != "" {
		t.Fatalf("got %+v", r)
	}
	if ok := runJWT(t, "", nil, "keygen", "--alg", "ES256", "--format", "jwk", "--kid", "k1"); ok.code != 0 {
		t.Errorf("--kid with --format jwk must work: %+v", ok)
	}
}

// TestWriteNewFileCleansUpOnFailure exercises the OpenFile failure path
// (missing parent directory) and asserts no file is left behind. The
// write/close failure path is covered by a code comment in writeNewFile
// since it is impractical to force a write or close error in a unit test.
func TestWriteNewFileCleansUpOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing-parent", "key.pem")
	if err := writeNewFile(path, []byte("data")); err == nil {
		t.Fatal("expected an error for a missing parent directory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should not exist, stat err = %v", err)
	}
}
