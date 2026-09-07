package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazhari/jwt/internal/jwk"
)

func noEnv(string) string { return "" }

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func pemBytes(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestLoadSecretSources(t *testing.T) {
	long := strings.Repeat("x", 32)
	raw := []byte(long)
	std := base64.StdEncoding.EncodeToString(raw)
	url := base64.RawURLEncoding.EncodeToString(raw)
	file := writeFile(t, "secret.txt", []byte(long+"\n"))

	tests := []struct {
		name   string
		src    Source
		source string
	}{
		{"secret", Source{Secret: long}, "secret"},
		{"secret-b64 std", Source{SecretB64: std}, "secret-b64"},
		{"secret-b64 url", Source{SecretB64: url}, "secret-b64"},
		{"secret-file", Source{SecretFile: file}, "secret-file:" + file},
		{"env", Source{Env: func(n string) string {
			if n == "JWT_SECRET" {
				return long
			}
			return ""
		}}, "env:JWT_SECRET"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.src.Env == nil {
				tt.src.Env = noEnv
			}
			k, err := Load(tt.src, nil)
			if err != nil {
				t.Fatal(err)
			}
			if k.Kind != HMAC || !k.Private || string(k.Material.([]byte)) != long || k.Source != tt.source {
				t.Errorf("got %+v", k)
			}
		})
	}
}

func TestLoadShortSecretWarns(t *testing.T) {
	var warn bytes.Buffer
	if _, err := Load(Source{Secret: "short", Env: noEnv, Warn: &warn}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn.String(), "5 bytes") {
		t.Errorf("warning = %q", warn.String())
	}
}

func TestLoadConflictsAndMissing(t *testing.T) {
	_, err := Load(Source{Secret: "a", KeyPath: "b", Env: noEnv}, nil)
	if err == nil || !strings.Contains(err.Error(), "--secret") || !strings.Contains(err.Error(), "--key") {
		t.Errorf("conflict err = %v", err)
	}
	_, err = Load(Source{Env: noEnv}, nil)
	if err != ErrNoKey {
		t.Errorf("missing err = %v", err)
	}
	_, err = Load(Source{SecretB64: "!!!", Env: noEnv}, nil)
	if err == nil {
		t.Error("bad base64 should fail")
	}
	_, err = Load(Source{SecretFile: "/nonexistent/file", Env: noEnv}, nil)
	if err == nil {
		t.Error("missing file should fail")
	}
}

func TestLoadPEMBlocks(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	pkcs1Pub := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	pkcs8RSA, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pkcs8EC, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	pkcs8Ed, _ := x509.MarshalPKCS8PrivateKey(edKey)
	pkixRSA, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pkixEC, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	pkixEd, _ := x509.MarshalPKIXPublicKey(edKey.Public())

	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		data    []byte
		kind    Kind
		private bool
	}{
		{"pkcs1 rsa private", pemBytes(t, "RSA PRIVATE KEY", pkcs1), RSA, true},
		{"pkcs1 rsa public", pemBytes(t, "RSA PUBLIC KEY", pkcs1Pub), RSA, false},
		{"sec1 ec private", pemBytes(t, "EC PRIVATE KEY", sec1), EC, true},
		{"pkcs8 rsa", pemBytes(t, "PRIVATE KEY", pkcs8RSA), RSA, true},
		{"pkcs8 ec", pemBytes(t, "PRIVATE KEY", pkcs8EC), EC, true},
		{"pkcs8 ed25519", pemBytes(t, "PRIVATE KEY", pkcs8Ed), Ed25519, true},
		{"pkix rsa", pemBytes(t, "PUBLIC KEY", pkixRSA), RSA, false},
		{"pkix ec", pemBytes(t, "PUBLIC KEY", pkixEC), EC, false},
		{"pkix ed25519", pemBytes(t, "PUBLIC KEY", pkixEd), Ed25519, false},
		{"certificate", pemBytes(t, "CERTIFICATE", certDER), RSA, false},
		{"skips unknown block first", append(pemBytes(t, "EC PARAMETERS", []byte{6, 8}), pemBytes(t, "EC PRIVATE KEY", sec1)...), EC, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, "key.pem", tt.data)
			k, err := Load(Source{KeyPath: path, Env: noEnv}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if k.Kind != tt.kind || k.Private != tt.private {
				t.Errorf("kind=%v private=%v", k.Kind, k.Private)
			}
			if k.Source != "pem:"+path {
				t.Errorf("source = %q", k.Source)
			}
		})
	}

	path := writeFile(t, "bad.pem", pemBytes(t, "EC PARAMETERS", []byte{6, 8}))
	if _, err := Load(Source{KeyPath: path, Env: noEnv}, nil); err == nil || !strings.Contains(err.Error(), "no supported PEM block") {
		t.Errorf("err = %v", err)
	}
	path = writeFile(t, "garbage.txt", []byte("hello"))
	if _, err := Load(Source{KeyPath: path, Env: noEnv}, nil); err == nil || !strings.Contains(err.Error(), "not PEM or JWK") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadKeyFromStdinAndEnv(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	data := pemBytes(t, "PRIVATE KEY", der)

	k, err := Load(Source{KeyPath: "-", Stdin: bytes.NewReader(data), Env: noEnv}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.Kind != EC || k.Source != "pem:stdin" {
		t.Errorf("got %+v", k)
	}

	path := writeFile(t, "k.pem", data)
	k, err = Load(Source{Env: func(n string) string {
		if n == "JWT_KEY" {
			return path
		}
		return ""
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.Source != "pem:"+path {
		t.Errorf("source = %q", k.Source)
	}
}

func TestLoadJWKAndJWKS(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	j1, _ := jwk.FromKey(ecKey, "ec1")
	j2, _ := jwk.FromKey(&rsaKey.PublicKey, "rsa1")
	single, _ := json.Marshal(j1)
	set, _ := json.Marshal(jwk.Set{Keys: []jwk.Key{*j1, *j2}})
	oneKeySet, _ := json.Marshal(jwk.Set{Keys: []jwk.Key{*j2}})

	t.Run("single jwk via --key", func(t *testing.T) {
		path := writeFile(t, "k.json", single)
		k, err := Load(Source{KeyPath: path, Env: noEnv}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if k.Kind != EC || !k.Private || k.Source != "jwk:"+path {
			t.Errorf("got %+v", k)
		}
	})
	t.Run("jwks via --key with header kid", func(t *testing.T) {
		path := writeFile(t, "set.json", set)
		k, err := Load(Source{KeyPath: path, Env: noEnv}, map[string]any{"kid": "rsa1"})
		if err != nil {
			t.Fatal(err)
		}
		if k.Kind != RSA || k.Private || k.Source != "jwks:rsa1" {
			t.Errorf("got %+v", k)
		}
	})
	t.Run("jwks-file with --kid override", func(t *testing.T) {
		path := writeFile(t, "set.json", set)
		k, err := Load(Source{JWKSFile: path, KID: "ec1", Env: noEnv}, map[string]any{"kid": "rsa1"})
		if err != nil {
			t.Fatal(err)
		}
		if k.Kind != EC || k.Source != "jwks:ec1" {
			t.Errorf("got %+v", k)
		}
	})
	t.Run("jwks-file single key without kid", func(t *testing.T) {
		path := writeFile(t, "one.json", oneKeySet)
		k, err := Load(Source{JWKSFile: path, Env: noEnv}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if k.Kind != RSA {
			t.Errorf("got %+v", k)
		}
	})
	t.Run("jwks-file multiple keys without kid", func(t *testing.T) {
		path := writeFile(t, "set.json", set)
		_, err := Load(Source{JWKSFile: path, Env: noEnv}, nil)
		if err == nil || !strings.Contains(err.Error(), "ec1") || !strings.Contains(err.Error(), "rsa1") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("jwks-file unknown kid", func(t *testing.T) {
		path := writeFile(t, "set.json", set)
		_, err := Load(Source{JWKSFile: path, Env: noEnv}, map[string]any{"kid": "zzz"})
		if err == nil || !strings.Contains(err.Error(), `"zzz"`) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("jwks-file with no keys", func(t *testing.T) {
		path := writeFile(t, "empty.json", []byte(`{"keys":[]}`))
		_, err := Load(Source{JWKSFile: path, Env: noEnv}, nil)
		if err == nil || !strings.Contains(err.Error(), "JWKS contains no keys") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("jwk marked use=enc", func(t *testing.T) {
		var one map[string]any
		if err := json.Unmarshal(oneKeySet, &one); err != nil {
			t.Fatal(err)
		}
		one["keys"].([]any)[0].(map[string]any)["use"] = "enc"
		body, err := json.Marshal(one)
		if err != nil {
			t.Fatal(err)
		}
		path := writeFile(t, "enc.json", body)
		_, err = Load(Source{JWKSFile: path, Env: noEnv}, nil)
		if err == nil || !strings.Contains(err.Error(), "use=enc") {
			t.Errorf("err = %v", err)
		}
	})
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func TestLoadStripsBOM(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	pemData := pemBytes(t, "PRIVATE KEY", der)

	t.Run("pem with leading BOM", func(t *testing.T) {
		path := writeFile(t, "key.pem", append(append([]byte{}, utf8BOM...), pemData...))
		k, err := Load(Source{KeyPath: path, Env: noEnv}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if k.Kind != EC || k.Source != "pem:"+path {
			t.Errorf("got %+v", k)
		}
	})

	t.Run("jwk with leading BOM", func(t *testing.T) {
		j, _ := jwk.FromKey(ecKey, "ec1")
		single, _ := json.Marshal(j)
		path := writeFile(t, "k.json", append(append([]byte{}, utf8BOM...), single...))
		k, err := Load(Source{KeyPath: path, Env: noEnv}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if k.Kind != EC || k.Source != "jwk:"+path {
			t.Errorf("got %+v", k)
		}
	})

	t.Run("secret-file with leading BOM strips it", func(t *testing.T) {
		long := strings.Repeat("x", 32)
		file := writeFile(t, "secret.txt", append(append([]byte{}, utf8BOM...), []byte(long+"\n")...))
		k, err := Load(Source{SecretFile: file, Env: noEnv}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(k.Material.([]byte)) != long {
			t.Errorf("secret = %q, want %q", k.Material, long)
		}
	})
}

func TestDecodeSecretB64(t *testing.T) {
	raw := []byte{0xfb, 0xff, 0x01}
	for _, s := range []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	} {
		got, err := DecodeSecretB64(s)
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("DecodeSecretB64(%q) = %x, %v", s, got, err)
		}
	}
	if _, err := DecodeSecretB64("***"); err == nil {
		t.Error("expected error")
	}
}
