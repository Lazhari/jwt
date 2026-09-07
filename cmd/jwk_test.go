package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lazhari/jwt/internal/jwk"
	"github.com/lazhari/jwt/internal/keys"
)

func TestJWKConvertPEMToJWK(t *testing.T) {
	rsaPriv, rsaPub, _ := rsaPair(t)
	r := runJWT(t, "", nil, "jwk", "convert", "--in", rsaPriv, "--kid", "r1")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	k, err := jwk.Parse([]byte(r.out))
	if err != nil || k.Kty != "RSA" || !k.IsPrivate() || k.Kid != "r1" {
		t.Errorf("private jwk: %v %+v", err, k)
	}
	r = runJWT(t, "", nil, "jwk", "convert", "--in", rsaPriv, "--public")
	k, err = jwk.Parse([]byte(r.out))
	if err != nil || k.IsPrivate() {
		t.Errorf("--public should strip private members: %v %+v", err, k)
	}
	r = runJWT(t, "", nil, "jwk", "convert", "--in", rsaPub)
	if k, err := jwk.Parse([]byte(r.out)); err != nil || k.IsPrivate() {
		t.Errorf("public pem: %v", err)
	}
}

func TestJWKConvertJWKToPEM(t *testing.T) {
	ecPriv, _, _ := ecPair(t, ellipticP384())
	toJWK := runJWT(t, "", nil, "jwk", "convert", "--in", ecPriv)
	jwkPath := writeTemp(t, "ec.json", []byte(toJWK.out))

	r := runJWT(t, "", nil, "jwk", "convert", "--in", jwkPath)
	if r.code != 0 || !strings.HasPrefix(r.out, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("got %+v", r)
	}
	back := writeTemp(t, "back.pem", []byte(r.out))
	k, err := keys.Load(keys.Source{KeyPath: back, Env: func(string) string { return "" }}, nil)
	if err != nil || k.Kind != keys.EC || !k.Private {
		t.Errorf("round trip: %v %+v", err, k)
	}
	r = runJWT(t, "", nil, "jwk", "convert", "--in", jwkPath, "--public")
	if r.code != 0 || !strings.HasPrefix(r.out, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("--public: %+v", r)
	}
	// stdin
	r = runJWT(t, toJWK.out, nil, "jwk", "convert", "--in", "-")
	if r.code != 0 || !strings.Contains(r.out, "PRIVATE KEY") {
		t.Errorf("stdin: %+v", r)
	}
}

func TestJWKConvertErrors(t *testing.T) {
	oct := writeTemp(t, "oct.json", []byte(`{"kty":"oct","k":"AAAA"}`))
	set := writeTemp(t, "set.json", []byte(`{"keys":[]}`))
	junk := writeTemp(t, "junk.txt", []byte("hello"))
	for name, tt := range map[string]struct {
		args []string
		want string
	}{
		"oct to pem": {[]string{"jwk", "convert", "--in", oct}, "no PEM form"},
		"jwks input": {[]string{"jwk", "convert", "--in", set}, "single JWK"},
		"junk":       {[]string{"jwk", "convert", "--in", junk}, "not PEM or JWK"},
		"missing in": {[]string{"jwk", "convert"}, "--in"},
	} {
		t.Run(name, func(t *testing.T) {
			r := runJWT(t, "", nil, tt.args...)
			if r.code != 2 || !strings.Contains(r.err, tt.want) {
				t.Errorf("got %+v, want %q", r, tt.want)
			}
		})
	}
}

func TestJWKFetch(t *testing.T) {
	_, _, ecKey := ecPair(t, ellipticP384())
	j, _ := jwk.FromKey(&ecKey.PublicKey, "ec1")
	set, _ := json.Marshal(jwk.Set{Keys: []jwk.Key{*j}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(set)
	}))
	defer srv.Close()

	r := runJWTHTTP(t, "", nil, srv.Client(), "jwk", "fetch", srv.URL)
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	if s, err := jwk.ParseSet([]byte(r.out)); err != nil || len(s.Keys) != 1 {
		t.Errorf("set: %v", err)
	}
	r = runJWTHTTP(t, "", nil, srv.Client(), "jwk", "fetch", srv.URL, "--kid", "ec1")
	if k, err := jwk.Parse([]byte(r.out)); err != nil || k.Kid != "ec1" {
		t.Errorf("kid: %v %+v", err, r)
	}
	r = runJWTHTTP(t, "", nil, srv.Client(), "jwk", "fetch", srv.URL, "--kid", "zzz")
	if r.code != 2 || !strings.Contains(r.err, `"zzz"`) {
		t.Errorf("missing kid: %+v", r)
	}
	r = runJWTHTTP(t, "", nil, srv.Client(), "jwk", "fetch", "http://example.com/jwks")
	if r.code != 2 || !strings.Contains(r.err, "https") {
		t.Errorf("plain http: %+v", r)
	}
	if _, err := os.Stat("jwks.json"); err == nil {
		t.Error("fetch must not write files")
	}
}

func TestJWKConvertPEMWithBOM(t *testing.T) {
	rsaPriv, _, _ := rsaPair(t)
	data, err := os.ReadFile(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	bomData := append([]byte{0xEF, 0xBB, 0xBF}, data...)
	bomPath := writeTemp(t, "rsa-bom.pem", bomData)

	r := runJWT(t, "", nil, "jwk", "convert", "--in", bomPath)
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	if _, err := jwk.Parse([]byte(r.out)); err != nil {
		t.Errorf("BOM-prefixed PEM should convert to a JWK: %v", err)
	}
}

func TestJWKConvertJWKSWithBOMRefused(t *testing.T) {
	_, _, ecKey := ecPair(t, ellipticP384())
	j, err := jwk.FromKey(&ecKey.PublicKey, "ec1")
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jwk.Set{Keys: []jwk.Key{*j}})
	if err != nil {
		t.Fatal(err)
	}
	bomData := append([]byte{0xEF, 0xBB, 0xBF}, set...)
	bomPath := writeTemp(t, "set-bom.json", bomData)

	r := runJWT(t, "", nil, "jwk", "convert", "--in", bomPath)
	if r.code != 2 || !strings.Contains(r.err, "single JWK") {
		t.Errorf("got %+v", r)
	}
}

// TestJWKConvertKidRejectedForPEMOutput pins the ruling that --kid is a
// usage error when the conversion goes the other way: PEM output has no
// place for a key ID.
func TestJWKConvertKidRejectedForPEMOutput(t *testing.T) {
	ecPriv, _, _ := ecPair(t, ellipticP384())
	toJWK := runJWT(t, "", nil, "jwk", "convert", "--in", ecPriv)
	jwkPath := writeTemp(t, "ec.json", []byte(toJWK.out))

	r := runJWT(t, "", nil, "jwk", "convert", "--in", jwkPath, "--kid", "k1")
	if r.code != 2 || !strings.Contains(r.err, "--kid applies only when converting to JWK") || r.out != "" {
		t.Fatalf("got %+v", r)
	}
	if ok := runJWT(t, "", nil, "jwk", "convert", "--in", jwkPath); ok.code != 0 {
		t.Errorf("without --kid the conversion must still work: %+v", ok)
	}
}
