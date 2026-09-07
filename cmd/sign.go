package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lazhari/jwt/internal/keys"
	"github.com/lazhari/jwt/internal/output"
	"github.com/lazhari/jwt/internal/token"
)

type signFlags struct {
	keys    keyFlags
	payload string
	claims  []string
	iss     string
	sub     string
	aud     []string
	exp     string
	nbf     string
	iat     string
	noIat   bool
	jti     string
	jtiAuto bool
	alg     string
	kid     string
	typ     string
	headers []string
}

func newSignCmd(streams *ioStreams) *cobra.Command {
	var f signFlags
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Create and sign a token",
		Long: `Create and sign a token. Claims come from --payload (a JSON object),
repeatable --claim key=value flags, and the standard claim flags; later
sources win. Relative times such as +1h are relative to now.

The algorithm defaults to the key type: HS256 for secrets, RS256 for RSA,
ES256/ES384/ES512 for EC by curve, EdDSA for Ed25519.`,
		Example: `  jwt sign --secret "$JWT_SECRET" --claim sub=u1 --exp +1h
  jwt sign --key private.pem --alg PS256 --payload @claims.json --kid k1
  jwt sign --alg none --claim test=true`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSign(cmd, streams, &f)
		},
	}
	f.keys.bind(cmd, false)
	fs := cmd.Flags()
	fs.StringVar(&f.payload, "payload", "", "JSON object of claims: a string, @file, or - for stdin")
	fs.StringArrayVar(&f.claims, "claim", nil, "Claim as key=value; JSON values are parsed (repeatable)")
	fs.StringVar(&f.iss, "iss", "", "Issuer claim")
	fs.StringVar(&f.sub, "sub", "", "Subject claim")
	fs.StringArrayVar(&f.aud, "aud", nil, "Audience claim (repeatable; one value is a string, several are an array)")
	fs.StringVar(&f.exp, "exp", "", "Expiration: +1h, Unix seconds, or RFC 3339")
	fs.StringVar(&f.nbf, "nbf", "", "Not-before: +5m, Unix seconds, or RFC 3339")
	fs.StringVar(&f.iat, "iat", "", "Issued-at (default now): now, -1m, Unix seconds, or RFC 3339")
	fs.BoolVar(&f.noIat, "no-iat", false, "Omit the iat claim")
	fs.StringVar(&f.jti, "jti", "", "JWT ID claim")
	fs.BoolVar(&f.jtiAuto, "jti-auto", false, "Generate a random UUID for the jti claim")
	fs.StringVar(&f.alg, "alg", "", "Algorithm (default by key type), or none")
	fs.StringVar(&f.kid, "kid", "", "Key ID header")
	fs.StringVar(&f.typ, "typ", "JWT", "Type header")
	fs.StringArrayVar(&f.headers, "header", nil, "Extra header member as key=value (repeatable)")
	return cmd
}

func runSign(cmd *cobra.Command, streams *ioStreams, f *signFlags) error {
	payload := map[string]any{}
	if f.payload != "" {
		raw, err := readInput(f.payload, streams.in)
		if err != nil {
			return usageError(fmt.Errorf("--payload: %w", err))
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&payload); err != nil || payload == nil {
			return usageError(fmt.Errorf("--payload: not a JSON object"))
		}
	}
	extra, err := token.ParseKVs(f.claims)
	if err != nil {
		return usageError(fmt.Errorf("--claim: %w", err))
	}
	claims, err := token.BuildClaims(token.ClaimsInput{
		Payload:  payload,
		Claims:   extra,
		Issuer:   f.iss,
		Subject:  f.sub,
		Audience: f.aud,
		Exp:      f.exp,
		Nbf:      f.nbf,
		Iat:      f.iat,
		NoIat:    f.noIat,
		JTI:      f.jti,
		JTIAuto:  f.jtiAuto,
		Now:      streams.now(),
	})
	if err != nil {
		return usageError(err)
	}

	header, err := token.ParseKVs(f.headers)
	if err != nil {
		return usageError(fmt.Errorf("--header: %w", err))
	}
	if f.kid != "" {
		header["kid"] = f.kid
	}
	if f.typ != "" {
		header["typ"] = f.typ
	}

	var key *keys.Key
	if f.alg != "none" {
		// The header kid also selects the key: --key may name a JWKS with
		// several private keys, and --kid says which one to sign with.
		src := f.keys.source(streams)
		src.KID = f.kid
		key, err = keys.Load(src, header)
		if err != nil {
			return usageError(err)
		}
	}

	tok, err := token.Sign(token.SignInput{Payload: claims, Header: header, Alg: f.alg, Key: key})
	if err != nil {
		return usageError(err)
	}

	if jsonWanted(cmd) {
		d, err := token.Decode(tok)
		if err != nil {
			return err
		}
		return output.WriteJSON(streams.out, map[string]any{"token": tok, "header": d.Header, "payload": d.Payload})
	}
	_, err = fmt.Fprintln(streams.out, tok)
	return err
}

func init() { commandBuilders = append(commandBuilders, newSignCmd) }
