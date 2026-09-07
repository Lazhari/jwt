package token

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lazhari/jwt/internal/keys"
)

// SignInput is everything needed to produce a token.
type SignInput struct {
	Payload map[string]any
	// Header holds extra header members such as kid or typ. "alg" is
	// rejected here; set Alg instead.
	Header map[string]any
	// Alg is the JWS algorithm. Empty means keys.DefaultAlg(Key).
	Alg string
	// Key may be nil only when Alg is "none".
	Key *keys.Key
}

// Sign produces a compact JWS.
func Sign(in SignInput) (string, error) {
	alg := in.Alg
	if alg == "" {
		if in.Key == nil {
			return "", fmt.Errorf("no key and no --alg given")
		}
		alg = keys.DefaultAlg(in.Key)
	}
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("unsupported algorithm %q (supported: %s, none)", alg, strings.Join(keys.AllAlgs(), ", "))
	}

	var material any
	if alg == "none" {
		material = jwt.UnsafeAllowNoneSignatureType
	} else {
		if in.Key == nil {
			return "", fmt.Errorf("algorithm %s needs a key", alg)
		}
		if err := keys.Compatible(in.Key, alg); err != nil {
			return "", err
		}
		if !in.Key.Private {
			return "", fmt.Errorf("signing with %s needs a private key, but %s is a public key", alg, in.Key.Source)
		}
		material = in.Key.Material
	}

	t := jwt.NewWithClaims(method, jwt.MapClaims(in.Payload))
	for k, v := range in.Header {
		if k == "alg" {
			return "", fmt.Errorf("set the algorithm with --alg, not --header alg")
		}
		t.Header[k] = v
	}
	s, err := t.SignedString(material)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return s, nil
}
