package cmd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lazhari/jwt/internal/jwk"
	"github.com/lazhari/jwt/internal/keys"
	"github.com/lazhari/jwt/internal/output"
)

func newJWKCmd(streams *ioStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwk",
		Short: "Convert keys between PEM and JWK, or fetch a JWKS",
	}
	cmd.AddCommand(newJWKConvertCmd(streams), newJWKFetchCmd(streams))
	return cmd
}

func newJWKConvertCmd(streams *ioStreams) *cobra.Command {
	var in, kid string
	var public bool
	cmd := &cobra.Command{
		Use:   "convert",
		Short: "Convert a PEM key to JWK, or a JWK to PEM",
		Long: `Convert a single key. PEM input produces a JWK; JWK input produces PEM
(PKCS#8 for private keys, PKIX for public keys). The input format is
detected from the content.`,
		Example: `  jwt jwk convert --in private.pem --kid 2025-01 > private.jwk
  jwt jwk convert --in private.pem --public > public.jwk
  jwt jwk convert --in key.jwk > key.pem`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runJWKConvert(cmd, streams, in, kid, public)
		},
	}
	cmd.Flags().StringVar(&in, "in", "", "Input file (PEM or JWK), or - for stdin")
	cmd.Flags().StringVar(&kid, "kid", "", "Key ID to set on JWK output")
	cmd.Flags().BoolVar(&public, "public", false, "Emit only the public half")
	return cmd
}

func runJWKConvert(cmd *cobra.Command, streams *ioStreams, in, kid string, public bool) error {
	if in == "" {
		return usageError(errors.New("--in is required"))
	}
	spec := in
	if in != "-" {
		spec = "@" + in
	}
	data, err := readInput(spec, streams.in)
	if err != nil {
		return usageError(fmt.Errorf("--in: %w", err))
	}
	trimmed := bytes.TrimSpace(keys.StripBOM(data))
	if bytes.HasPrefix(trimmed, []byte("{")) && jwk.IsSet(trimmed) {
		return usageError(errors.New("convert takes a single JWK, not a JWKS; use \"jwk fetch --kid\" or extract one key first"))
	}
	key, err := keys.ParseMaterial(data, in, "", nil)
	if err != nil {
		return usageError(err)
	}
	material := key.Material
	if public {
		material = publicOf(material)
	}

	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		j, err := jwk.FromKey(material, kid)
		if err != nil {
			return usageError(err)
		}
		return output.WriteJSON(streams.out, j)
	}

	// JWK to PEM. A kid has nowhere to go in PEM output, so setting it
	// here is a mistake rather than something to ignore.
	if cmd.Flags().Changed("kid") {
		return usageError(errors.New("--kid applies only when converting to JWK"))
	}
	if key.Kind == keys.HMAC {
		return usageError(errors.New("oct (HMAC) keys have no PEM form"))
	}
	var block *pem.Block
	if key.Private && !public {
		der, err := x509.MarshalPKCS8PrivateKey(material)
		if err != nil {
			return usageError(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	} else {
		der, err := x509.MarshalPKIXPublicKey(publicOf(material))
		if err != nil {
			return usageError(err)
		}
		block = &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	}
	_, err = streams.out.Write(pem.EncodeToMemory(block))
	return err
}

func newJWKFetchCmd(streams *ioStreams) *cobra.Command {
	var kid string
	cmd := &cobra.Command{
		Use:   "fetch URL",
		Short: "Download a JWKS and print it, or one key by kid",
		Long: `Fetch a JWKS over HTTPS (plain HTTP is allowed only for localhost).
The response must be at most 1 MiB and the request times out after ten
seconds.`,
		Example: `  jwt jwk fetch https://auth.example.com/.well-known/jwks.json
  jwt jwk fetch https://auth.example.com/.well-known/jwks.json --kid abc`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runJWKFetch(streams, args[0], kid)
		},
	}
	cmd.Flags().StringVar(&kid, "kid", "", "Print only the key with this ID")
	return cmd
}

func runJWKFetch(streams *ioStreams, url, kid string) error {
	body, err := keys.Fetch(context.Background(), streams.http, url)
	if err != nil {
		return usageError(err)
	}
	set, err := jwk.ParseSet(body)
	if err != nil {
		return usageError(err)
	}
	if kid == "" {
		return output.WriteJSON(streams.out, set)
	}
	k, err := set.Lookup(kid)
	if err != nil {
		return usageError(err)
	}
	return output.WriteJSON(streams.out, k)
}

func init() { commandBuilders = append(commandBuilders, newJWKCmd) }
