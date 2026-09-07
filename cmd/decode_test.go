package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func signedToken(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"sign", "--secret", testSecret}, args...)
	r := runJWT(t, "", nil, full...)
	if r.code != 0 {
		t.Fatalf("sign failed: %+v", r)
	}
	return strings.TrimSpace(r.out)
}

func TestDecodeTable(t *testing.T) {
	tok := signedToken(t, "--claim", "sub=u1", "--exp", "+2h", "--kid", "k1")
	r := runJWT(t, "", nil, "decode", tok)
	if r.code != 0 || r.err != "" {
		t.Fatalf("got %+v", r)
	}
	for _, want := range []string{"Header", "Payload", "Signature", "HS256", "k1", "sub", "u1", "(expires in 2h)", "(issued now)"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q in:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "Verification") {
		t.Error("decode must not verify")
	}
	if strings.Contains(r.out, "\x1b[") {
		t.Error("no ANSI codes expected when stdout is not a terminal")
	}
}

func TestDecodeInputForms(t *testing.T) {
	tok := signedToken(t, "--claim", "sub=u1")
	path := writeTemp(t, "tok.txt", []byte("Bearer "+tok+"\n"))
	for name, r := range map[string]runResult{
		"bearer arg": runJWT(t, "", nil, "decode", "Bearer "+tok),
		"stdin":      runJWT(t, tok+"\n", nil, "decode"),
		"stdin dash": runJWT(t, tok, nil, "decode", "-"),
		"file":       runJWT(t, "", nil, "decode", "@"+path),
		"inspect":    runJWT(t, "", nil, "inspect", tok),
	} {
		if r.code != 0 || !strings.Contains(r.out, "u1") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestDecodeJSONAndPart(t *testing.T) {
	tok := signedToken(t, "--claim", "sub=u1", "--claim", "big=12345678901234567890")
	r := runJWT(t, "", nil, "decode", tok, "--json")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil {
		t.Fatalf("not one JSON document: %v", err)
	}
	if _, ok := doc["verification"]; ok {
		t.Error("verification must be absent")
	}
	if !strings.Contains(r.out, "12345678901234567890") {
		t.Error("big integer lost precision")
	}

	r = runJWT(t, "", nil, "decode", tok, "--part", "payload")
	var payload map[string]any
	if err := json.Unmarshal([]byte(r.out), &payload); err != nil || payload["sub"] != "u1" {
		t.Errorf("--part payload: %+v (%v)", r, err)
	}
	r = runJWT(t, "", nil, "decode", tok, "--part", "header")
	var header map[string]any
	if err := json.Unmarshal([]byte(r.out), &header); err != nil || header["alg"] != "HS256" {
		t.Errorf("--part header: %+v", r)
	}
	r = runJWT(t, "", nil, "decode", tok, "--part", "signature")
	if r.code != 0 || strings.TrimSpace(r.out) != strings.Split(tok, ".")[2] {
		t.Errorf("--part signature: %+v", r)
	}
	r = runJWT(t, "", nil, "decode", tok, "--part", "footer")
	if r.code != 2 || !strings.Contains(r.err, "--part") {
		t.Errorf("bad part: %+v", r)
	}
}

func TestDecodeUnsignedToken(t *testing.T) {
	r := runJWT(t, "", nil, "sign", "--alg", "none", "--claim", "a=b")
	tok := strings.TrimSpace(r.out)
	r = runJWT(t, "", nil, "decode", tok)
	if r.code != 0 || !strings.Contains(r.out, "(none)") {
		t.Errorf("got %+v", r)
	}
}

func TestDecodeErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"garbage":   {"decode", "garbage"},
		"two parts": {"decode", "a.b.c.d"},
		"two args":  {"decode", "a", "b"},
	} {
		r := runJWT(t, "", nil, args...)
		if r.code != 2 || r.out != "" || !strings.HasPrefix(r.err, "jwt: ") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	r := runJWT(t, "", nil, "decode")
	if r.code != 2 || !strings.Contains(r.err, "empty") {
		t.Errorf("empty stdin: %+v", r)
	}
}
