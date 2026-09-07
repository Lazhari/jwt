package keys

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const jwksBody = `{"keys":[]}`

func TestFetchHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(jwksBody))
	}))
	defer srv.Close()

	b, err := Fetch(context.Background(), srv.Client(), srv.URL+"/jwks")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != jwksBody {
		t.Errorf("body = %q", b)
	}
}

func TestFetchLoopbackHTTPAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(jwksBody))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), nil, srv.URL); err != nil {
		t.Fatal(err)
	}
}

func TestFetchRejectsPlainHTTPElsewhere(t *testing.T) {
	_, err := Fetch(context.Background(), nil, "http://example.com/.well-known/jwks.json")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v", err)
	}
	_, err = Fetch(context.Background(), nil, "ftp://example.com/x")
	if err == nil {
		t.Error("ftp should be rejected")
	}
	_, err = Fetch(context.Background(), nil, "::not a url")
	if err == nil {
		t.Error("garbage should be rejected")
	}
}

func TestFetchStatusAndSize(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/404":
			http.NotFound(w, r)
		case "/big":
			_, _ = w.Write(make([]byte, maxJWKSBytes+1))
		}
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.Client(), srv.URL+"/404")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("404 err = %v", err)
	}
	_, err = Fetch(context.Background(), srv.Client(), srv.URL+"/big")
	if err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Errorf("size err = %v", err)
	}
}

func TestFetchRedirectToHTTPRefused(t *testing.T) {
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/jwks", http.StatusFound)
	}))
	defer tls.Close()

	_, err := Fetch(context.Background(), tls.Client(), tls.URL)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("err = %v", err)
	}
}

func TestFetchTimeout(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := Fetch(ctx, srv.Client(), srv.URL); err == nil {
		t.Error("expected timeout error")
	}
}
