// Package token builds, signs, decodes, and verifies JSON Web Tokens and
// produces a check-by-check verification report.
package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// Decoded is a token split into its parts, decoded without verification.
type Decoded struct {
	Header    map[string]any `json:"header"`
	Payload   map[string]any `json:"payload"`
	Signature string         `json:"signature"`
	// Raw holds the three base64url segments as they appeared in the token.
	Raw [3]string `json:"-"`
}

// Clean trims whitespace and a leading "Bearer " prefix.
func Clean(s string) string {
	s = strings.TrimSpace(s)
	const prefix = "bearer "
	if len(s) > len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		s = strings.TrimSpace(s[len(prefix):])
	}
	return s
}

// Decode splits and base64url-decodes a token without checking anything
// about the signature. Two-segment tokens are accepted with an empty
// signature. Numbers are kept as json.Number to preserve precision.
func Decode(tok string) (*Decoded, error) {
	tok = Clean(tok)
	if tok == "" {
		return nil, fmt.Errorf("empty token")
	}
	parts := strings.Split(tok, ".")
	if len(parts) == 2 {
		parts = append(parts, "")
	}
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token: expected 3 dot-separated segments, got %d", len(parts))
	}
	hdr, err := decodeObject(parts[0], "header")
	if err != nil {
		return nil, err
	}
	pl, err := decodeObject(parts[1], "payload")
	if err != nil {
		return nil, err
	}
	return &Decoded{
		Header:    hdr,
		Payload:   pl,
		Signature: parts[2],
		Raw:       [3]string{parts[0], parts[1], parts[2]},
	}, nil
}

// Compact re-joins the raw segments, which is the exact input the signature
// covers.
func (d *Decoded) Compact() string {
	return d.Raw[0] + "." + d.Raw[1] + "." + d.Raw[2]
}

func decodeObject(seg, name string) (map[string]any, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %s is not base64url: %w", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("invalid token: %s is not a JSON object: %w", name, err)
	}
	if m == nil {
		return nil, fmt.Errorf("invalid token: %s is null", name)
	}
	return m, nil
}

// NumericDate converts a claim value to a time. present is false for nil.
// Accepted: json.Number, float64, int64, int.
func NumericDate(v any) (t time.Time, present bool, err error) {
	var secs float64
	switch x := v.(type) {
	case nil:
		return time.Time{}, false, nil
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return time.Unix(i, 0).UTC(), true, nil
		}
		f, err := x.Float64()
		if err != nil {
			return time.Time{}, true, fmt.Errorf("not a number: %q", x.String())
		}
		secs = f
	case float64:
		secs = x
	case int64:
		return time.Unix(x, 0).UTC(), true, nil
	case int:
		return time.Unix(int64(x), 0).UTC(), true, nil
	default:
		return time.Time{}, true, fmt.Errorf("not a number (%T)", v)
	}
	whole, frac := math.Modf(secs)
	return time.Unix(int64(whole), int64(frac*1e9)).UTC(), true, nil
}
