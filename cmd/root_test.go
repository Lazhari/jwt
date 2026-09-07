package cmd

import (
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	r := runJWT(t, "", nil, "version")
	if r.code != 0 || r.out != "jwt dev (none, unknown)\n" || r.err != "" {
		t.Errorf("got %+v", r)
	}
	r = runJWT(t, "", nil, "version", "--json")
	if r.code != 0 || !strings.Contains(r.out, `"version": "dev"`) {
		t.Errorf("got %+v", r)
	}
	SetVersion("1.2.3", "abc", "2025-01-01")
	defer SetVersion("dev", "none", "unknown")
	if r := runJWT(t, "", nil, "version"); r.out != "jwt 1.2.3 (abc, 2025-01-01)\n" {
		t.Errorf("got %q", r.out)
	}
}

func TestHelpAndErrors(t *testing.T) {
	r := runJWT(t, "", nil, "--help")
	if r.code != 0 || !strings.Contains(r.out, "version") {
		t.Errorf("help: %+v", r)
	}
	r = runJWT(t, "", nil, "nope")
	if r.code != 2 || !strings.HasPrefix(r.err, "jwt: ") || !strings.Contains(r.err, "nope") {
		t.Errorf("unknown command: %+v", r)
	}
	r = runJWT(t, "", nil, "version", "--bogus")
	if r.code != 2 || !strings.Contains(r.err, "--bogus") || !strings.Contains(r.err, "--help") {
		t.Errorf("unknown flag: %+v", r)
	}
	r = runJWT(t, "", nil, "version", "extra")
	if r.code != 2 {
		t.Errorf("extra arg: %+v", r)
	}
}

func TestReadInput(t *testing.T) {
	path := writeTemp(t, "in.txt", []byte("from-file"))
	for spec, want := range map[string]string{
		"literal":  "literal",
		"-":        "from-stdin",
		"@" + path: "from-file",
	} {
		got, err := readInput(spec, strings.NewReader("from-stdin"))
		if err != nil || string(got) != want {
			t.Errorf("readInput(%q) = %q, %v", spec, got, err)
		}
	}
	if _, err := readInput("@/nonexistent/x", nil); err == nil {
		t.Error("missing file should fail")
	}
}

func TestTokenArg(t *testing.T) {
	if tok, err := tokenArg([]string{"Bearer a.b.c"}, nil); err != nil || tok != "a.b.c" {
		t.Errorf("arg: %q %v", tok, err)
	}
	if tok, err := tokenArg(nil, strings.NewReader(" a.b.c\n")); err != nil || tok != "a.b.c" {
		t.Errorf("stdin: %q %v", tok, err)
	}
	if _, err := tokenArg(nil, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty: %v", err)
	}
	if _, err := tokenArg([]string{"a", "b"}, nil); err == nil {
		t.Error("two args should fail")
	}
}
