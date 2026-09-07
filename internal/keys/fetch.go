package keys

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	fetchTimeout = 10 * time.Second
	maxJWKSBytes = 1 << 20 // 1 MiB
	maxRedirects = 5
)

// Fetch downloads a JWKS document. The URL must be https, or http to a
// loopback address for local development servers. Redirects follow the same
// rule. The body is capped at 1 MiB and the request times out after ten
// seconds unless ctx is shorter.
func Fetch(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if err := allowedURL(u); err != nil {
		return nil, err
	}

	if client == nil {
		client = &http.Client{}
	}
	// Copy so the caller's client is not mutated; the redirect policy is
	// part of the safety contract and must apply even to injected clients.
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("too many redirects")
		}
		if err := allowedURL(req.URL); err != nil {
			return fmt.Errorf("refusing redirect: %w", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jwt-cli")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetching %s: HTTP %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", u, err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("fetching %s: response larger than 1 MiB", u)
	}
	return body, nil
}

// allowedURL enforces https, or http only to loopback hosts.
func allowedURL(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%s: plain http is only allowed for localhost; use https", u)
	}
	return fmt.Errorf("%s: unsupported scheme %q; use https", u, u.Scheme)
}
