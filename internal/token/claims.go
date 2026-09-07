package token

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/lazhari/jwt/internal/timeparse"
)

// ClaimsInput gathers everything the sign command knows about the payload.
// Precedence, lowest to highest: Payload, Claims, the named standard claims.
type ClaimsInput struct {
	Payload  map[string]any
	Claims   map[string]any
	Issuer   string
	Subject  string
	Audience []string
	Exp      string // timeparse.At syntax
	Nbf      string
	Iat      string
	NoIat    bool
	JTI      string
	JTIAuto  bool
	Now      time.Time
}

// BuildClaims merges the inputs into a claims map ready to sign. Time claims
// are stored as int64 Unix seconds.
func BuildClaims(in ClaimsInput) (map[string]any, error) {
	if in.JTI != "" && in.JTIAuto {
		return nil, fmt.Errorf("use either --jti or --jti-auto, not both")
	}
	if in.NoIat && in.Iat != "" {
		return nil, fmt.Errorf("use either --iat or --no-iat, not both")
	}
	if in.Now.IsZero() {
		in.Now = time.Now()
	}

	out := make(map[string]any, len(in.Payload)+len(in.Claims)+7)
	maps.Copy(out, in.Payload)
	maps.Copy(out, in.Claims)

	if in.Issuer != "" {
		out["iss"] = in.Issuer
	}
	if in.Subject != "" {
		out["sub"] = in.Subject
	}
	switch len(in.Audience) {
	case 0:
	case 1:
		out["aud"] = in.Audience[0]
	default:
		out["aud"] = in.Audience
	}

	if !in.NoIat {
		t := in.Now
		if in.Iat != "" {
			var err error
			if t, err = timeparse.At(in.Iat, in.Now); err != nil {
				return nil, fmt.Errorf("--iat: %w", err)
			}
		}
		out["iat"] = t.Unix()
	}
	if in.Exp != "" {
		t, err := timeparse.At(in.Exp, in.Now)
		if err != nil {
			return nil, fmt.Errorf("--exp: %w", err)
		}
		out["exp"] = t.Unix()
	}
	if in.Nbf != "" {
		t, err := timeparse.At(in.Nbf, in.Now)
		if err != nil {
			return nil, fmt.Errorf("--nbf: %w", err)
		}
		out["nbf"] = t.Unix()
	}

	if in.JTIAuto {
		id, err := NewJTI()
		if err != nil {
			return nil, err
		}
		out["jti"] = id
	} else if in.JTI != "" {
		out["jti"] = in.JTI
	}
	return out, nil
}

// NewJTI returns a random UUID version 4 string.
func NewJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating jti: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ParseValue interprets a flag value. Valid JSON is decoded (numbers as
// json.Number); anything else is returned as a string.
func ParseValue(s string) any {
	if !json.Valid([]byte(s)) {
		return s
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return s
	}
	return v
}

// ParseKVs turns repeated "key=value" flags into a map using ParseValue.
func ParseKVs(items []string) (map[string]any, error) {
	out := make(map[string]any, len(items))
	for _, item := range items {
		k, v, ok := strings.Cut(item, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("expected key=value, got %q", item)
		}
		out[k] = ParseValue(v)
	}
	return out, nil
}
