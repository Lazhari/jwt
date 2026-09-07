package token

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lazhari/jwt/internal/keys"
	"github.com/lazhari/jwt/internal/timeparse"
)

// Clock supplies the current time so checks are testable.
type Clock func() time.Time

// VerifyOptions controls verification. Zero values mean "do not check"
// for Issuer, Subject, Audience, and Require.
type VerifyOptions struct {
	// Key may be nil only for alg none with AllowNone.
	Key *keys.Key
	// Algs is the allowlist. Empty means every algorithm the key kind serves.
	Algs      []string
	Issuer    string
	Subject   string
	Audience  string
	Leeway    time.Duration
	IgnoreExp bool
	IgnoreNbf bool
	AllowNone bool
	Require   []string
	Now       Clock
}

// Check is one line of the verification report.
type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Skipped bool   `json:"skipped"`
	Detail  string `json:"detail,omitempty"`
}

// Verification is the report. Valid is true when every non-skipped check
// passed.
type Verification struct {
	Valid     bool    `json:"valid"`
	Algorithm string  `json:"algorithm"`
	KeySource string  `json:"key_source,omitempty"`
	Checks    []Check `json:"checks"`
}

// Result is a decoded token plus, for verify, its report.
type Result struct {
	*Decoded
	Verification *Verification `json:"verification,omitempty"`
}

// Verify decodes the token, checks the signature, then runs every claim
// check independently. It returns an error only for input problems (a
// malformed token or a missing key); failed checks are reported in the
// result.
func Verify(tok string, opt VerifyOptions) (*Result, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	dec, err := Decode(tok)
	if err != nil {
		return nil, err
	}
	alg, _ := dec.Header["alg"].(string)
	v := &Verification{Algorithm: alg}

	material, algCheck, err := selectMaterial(alg, opt)
	if err != nil {
		return nil, err
	}
	switch {
	case alg == "none" && algCheck.Passed:
		v.KeySource = "none"
	case opt.Key != nil:
		v.KeySource = opt.Key.Source
	}
	v.Checks = append(v.Checks, algCheck)
	if c, present := critCheck(dec.Header); present {
		v.Checks = append(v.Checks, c)
	}
	if algCheck.Passed {
		v.Checks = append(v.Checks, signatureCheck(dec, alg, material, v.KeySource))
	} else {
		v.Checks = append(v.Checks, Check{Name: "signature", Skipped: true, Detail: "not checked"})
	}
	v.Checks = append(v.Checks, claimChecks(dec.Payload, opt)...)

	v.Valid = true
	for _, c := range v.Checks {
		if !c.Skipped && !c.Passed {
			v.Valid = false
			break
		}
	}
	return &Result{Decoded: dec, Verification: v}, nil
}

// selectMaterial decides whether alg is acceptable and which key material
// verifies it. A nil error with a failed Check means "report and continue".
func selectMaterial(alg string, opt VerifyOptions) (any, Check, error) {
	c := Check{Name: "alg"}
	switch {
	case alg == "":
		c.Detail = "header has no alg"
		return nil, c, nil
	case alg == "none":
		if !opt.AllowNone {
			c.Detail = "alg none is not allowed (pass --insecure-allow-none to accept unsigned tokens)"
			return nil, c, nil
		}
		if len(opt.Algs) > 0 && !slices.Contains(opt.Algs, "none") {
			c.Detail = fmt.Sprintf("none is not in the allowed list [%s]", strings.Join(opt.Algs, ", "))
			return nil, c, nil
		}
		c.Passed = true
		c.Detail = "none (unsigned, allowed by --insecure-allow-none)"
		return jwt.UnsafeAllowNoneSignatureType, c, nil
	case opt.Key == nil:
		return nil, c, fmt.Errorf("token uses %s but no key was provided", alg)
	}
	allowed := opt.Algs
	if len(allowed) == 0 {
		// A JWK that declares "alg" is for that algorithm only; otherwise
		// every algorithm the key kind serves is acceptable.
		if opt.Key.Alg != "" {
			allowed = []string{opt.Key.Alg}
		} else {
			allowed = keys.AlgsFor(opt.Key.Kind)
		}
	}
	if !slices.Contains(allowed, alg) {
		c.Detail = fmt.Sprintf("%s is not in the allowed list [%s]", alg, strings.Join(allowed, ", "))
		return nil, c, nil
	}
	if err := keys.Compatible(opt.Key, alg); err != nil {
		c.Detail = err.Error()
		return nil, c, nil
	}
	c.Passed = true
	c.Detail = alg
	return opt.Key.PublicMaterial(), c, nil
}

// critCheck reports on the "crit" header (RFC 7515 section 4.1.11). This
// tool implements no header extensions, so any entry is unrecognised and
// the token must be rejected. The second result is false when the header
// is absent, in which case no check line is emitted.
func critCheck(hdr map[string]any) (Check, bool) {
	raw, present := hdr["crit"]
	if !present {
		return Check{}, false
	}
	c := Check{Name: "crit"}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		c.Detail = "crit must be a non-empty array"
		return c, true
	}
	names := make([]string, len(list))
	for i, e := range list {
		names[i] = fmt.Sprintf("%v", e)
	}
	c.Detail = fmt.Sprintf("unsupported critical header extensions: [%s]", strings.Join(names, ", "))
	return c, true
}

// signatureCheck verifies the compact token. Padding is not allowed on the
// base64url segments: padded segments are rejected here the way RFC
// 7515-strict servers reject them, so a token that passes verify is one
// those servers will also accept.
func signatureCheck(dec *Decoded, alg string, material any, source string) Check {
	c := Check{Name: "signature"}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{alg}),
		jwt.WithoutClaimsValidation(),
		jwt.WithJSONNumber(),
	)
	_, err := parser.Parse(dec.Compact(), func(*jwt.Token) (any, error) { return material, nil })
	switch {
	case err == nil:
		c.Passed = true
		if alg == "none" {
			c.Detail = "unsigned token accepted"
		} else {
			c.Detail = "verified with " + source
		}
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		c.Detail = "signature does not match " + source
	default:
		c.Detail = err.Error()
	}
	return c
}

func claimChecks(payload map[string]any, opt VerifyOptions) []Check {
	now := opt.Now()
	var out []Check

	out = append(out, timeCheck("exp", payload["exp"], opt.IgnoreExp, "no exp claim (never expires)", func(t time.Time) (bool, string) {
		// The detail describes the token as it is; the pass/fail applies
		// leeway, so "expired 10s ago" can still pass with --leeway 30s.
		detail := "expires " + timeparse.Relative(t, now)
		if t.Before(now) {
			detail = "expired " + timeparse.Relative(t, now)
		}
		return !now.After(t.Add(opt.Leeway)), detail
	}))

	if _, present := payload["nbf"]; present || opt.IgnoreNbf {
		out = append(out, timeCheck("nbf", payload["nbf"], opt.IgnoreNbf, "no nbf claim", func(t time.Time) (bool, string) {
			if t.After(now) {
				return !t.After(now.Add(opt.Leeway)), "not valid for " + timeparse.Short(t.Sub(now))
			}
			return true, "valid since " + timeparse.Relative(t, now)
		}))
	}

	if _, present := payload["iat"]; present {
		out = append(out, timeCheck("iat", payload["iat"], false, "", func(t time.Time) (bool, string) {
			if t.After(now.Add(opt.Leeway)) {
				return false, "issued " + timeparse.Relative(t, now) + ", clock skew?"
			}
			return true, "issued " + timeparse.Relative(t, now)
		}))
	}

	if opt.Issuer != "" {
		out = append(out, stringCheck("iss", payload["iss"], opt.Issuer))
	}
	if opt.Subject != "" {
		out = append(out, stringCheck("sub", payload["sub"], opt.Subject))
	}
	if opt.Audience != "" {
		out = append(out, audienceCheck(payload["aud"], opt.Audience))
	}
	for _, name := range opt.Require {
		c := Check{Name: "require:" + name}
		if _, ok := payload[name]; ok {
			c.Passed, c.Detail = true, "present"
		} else {
			c.Detail = "claim " + name + " is missing"
		}
		out = append(out, c)
	}
	return out
}

// timeCheck evaluates a NumericDate claim. absent is the detail when the
// claim is missing, which counts as a pass (use --require to demand it).
func timeCheck(name string, v any, ignore bool, absent string, eval func(time.Time) (bool, string)) Check {
	c := Check{Name: name}
	if ignore {
		c.Skipped, c.Detail = true, "ignored"
		return c
	}
	t, present, err := NumericDate(v)
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	if !present {
		c.Passed, c.Detail = true, absent
		return c
	}
	c.Passed, c.Detail = eval(t)
	return c
}

func stringCheck(name string, v any, want string) Check {
	c := Check{Name: name}
	got, isString := v.(string)
	switch {
	case v == nil:
		c.Detail = fmt.Sprintf("no %s claim, expected %q", name, want)
	case !isString:
		c.Detail = fmt.Sprintf("%s is not a string (%T)", name, v)
	case got != want:
		c.Detail = fmt.Sprintf("%s is %q, expected %q", name, got, want)
	default:
		c.Passed, c.Detail = true, got
	}
	return c
}

func audienceCheck(v any, want string) Check {
	c := Check{Name: "aud"}
	var auds []string
	switch x := v.(type) {
	case nil:
		c.Detail = fmt.Sprintf("no aud claim, expected %q", want)
		return c
	case string:
		auds = []string{x}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				auds = append(auds, s)
			}
		}
	default:
		c.Detail = fmt.Sprintf("aud is not a string or array (%T)", v)
		return c
	}
	if slices.Contains(auds, want) {
		c.Passed, c.Detail = true, want
		return c
	}
	quoted := make([]string, len(auds))
	for i, a := range auds {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	c.Detail = fmt.Sprintf("aud is [%s], expected %q", strings.Join(quoted, ", "), want)
	return c
}
