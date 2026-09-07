package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"
)

func TestFromMaterialAndPublicMaterial(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name    string
		in      any
		kind    Kind
		private bool
		pubType string
	}{
		{"hmac", []byte("secret"), HMAC, true, "[]uint8"},
		{"rsa priv", rsaKey, RSA, true, "*rsa.PublicKey"},
		{"rsa pub", &rsaKey.PublicKey, RSA, false, "*rsa.PublicKey"},
		{"ec priv", ecKey, EC, true, "*ecdsa.PublicKey"},
		{"ec pub", &ecKey.PublicKey, EC, false, "*ecdsa.PublicKey"},
		{"ed priv", edPriv, Ed25519, true, "ed25519.PublicKey"},
		{"ed pub", edPub, Ed25519, false, "ed25519.PublicKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := FromMaterial(tt.in, "src")
			if err != nil {
				t.Fatal(err)
			}
			if k.Kind != tt.kind || k.Private != tt.private || k.Source != "src" {
				t.Errorf("got kind=%v private=%v source=%q", k.Kind, k.Private, k.Source)
			}
			if got := reflect.TypeOf(k.PublicMaterial()).String(); got != tt.pubType {
				t.Errorf("PublicMaterial type = %s, want %s", got, tt.pubType)
			}
		})
	}
	if _, err := FromMaterial("nope", "src"); err == nil {
		t.Error("string material should be rejected")
	}
}

func TestAlgorithmTables(t *testing.T) {
	if got := AllAlgs(); len(got) != 13 || got[0] != "HS256" || got[12] != "EdDSA" {
		t.Errorf("AllAlgs = %v", got)
	}
	if got := AlgsFor(RSA); !reflect.DeepEqual(got, []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}) {
		t.Errorf("AlgsFor(RSA) = %v", got)
	}
	for alg, want := range map[string]Kind{"HS512": HMAC, "PS384": RSA, "ES512": EC, "EdDSA": Ed25519} {
		if got, ok := KindOf(alg); !ok || got != want {
			t.Errorf("KindOf(%s) = %v,%v", alg, got, ok)
		}
	}
	if _, ok := KindOf("none"); ok {
		t.Error("none must not map to a kind")
	}
}

func TestDefaultAlgAndCompatible(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	mk := func(m any) *Key { k, _ := FromMaterial(m, "t"); return k }

	if got := DefaultAlg(mk([]byte("s"))); got != "HS256" {
		t.Errorf("hmac default = %s", got)
	}
	if got := DefaultAlg(mk(rsaKey)); got != "RS256" {
		t.Errorf("rsa default = %s", got)
	}
	if got := DefaultAlg(mk(p256)); got != "ES256" {
		t.Errorf("p256 default = %s", got)
	}
	if got := DefaultAlg(mk(p521)); got != "ES512" {
		t.Errorf("p521 default = %s", got)
	}
	if got := DefaultAlg(mk(edPriv)); got != "EdDSA" {
		t.Errorf("ed default = %s", got)
	}

	if err := Compatible(mk(rsaKey), "HS256"); err == nil || !strings.Contains(err.Error(), "HS256") {
		t.Errorf("rsa+HS256 err = %v", err)
	}
	if err := Compatible(mk(rsaKey), "PS512"); err != nil {
		t.Errorf("rsa+PS512 err = %v", err)
	}
	if err := Compatible(mk(p256), "ES384"); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Errorf("p256+ES384 err = %v", err)
	}
	if err := Compatible(mk(p256), "ES256"); err != nil {
		t.Errorf("p256+ES256 err = %v", err)
	}
	if err := Compatible(mk(edPriv), "EdDSA"); err != nil {
		t.Errorf("ed+EdDSA err = %v", err)
	}
	if err := Compatible(mk([]byte("s")), "none"); err != nil {
		t.Errorf("none is always compatible, err = %v", err)
	}
	if err := Compatible(mk([]byte("s")), "XX999"); err == nil {
		t.Error("unknown alg must fail")
	}
}
