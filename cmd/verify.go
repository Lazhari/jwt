package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lazhari/jwt/internal/keys"
	"github.com/lazhari/jwt/internal/output"
	"github.com/lazhari/jwt/internal/timeparse"
	"github.com/lazhari/jwt/internal/token"
)

type verifyFlags struct {
	keys      keyFlags
	algs      []string
	iss       string
	sub       string
	aud       string
	leeway    string
	ignoreExp bool
	ignoreNbf bool
	allowNone bool
	require   []string
}

func newVerifyCmd(streams *ioStreams) *cobra.Command {
	var f verifyFlags
	cmd := &cobra.Command{
		Use:   "verify [token]",
		Short: "Verify the signature and claims, and print a report",
		Long: `Verify a token. The signature is checked with the given key, then each
claim check runs independently so the report shows everything that is wrong.
The header and payload are printed even when verification fails.

Exit code 0 means every check passed, 1 means the token is not valid, and
2 means the token or key could not be read.`,
		Example: `  jwt verify "$TOKEN" --secret "$JWT_SECRET"
  jwt verify "$TOKEN" --key public.pem --iss https://auth.example.com --aud api
  jwt verify "$TOKEN" --jwks-url https://auth.example.com/.well-known/jwks.json
  jwt verify "$TOKEN" --secret "$JWT_SECRET" --ignore-exp --json | jq .payload`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd, streams, args, &f)
		},
	}
	f.keys.bind(cmd, true)
	fs := cmd.Flags()
	fs.StringSliceVar(&f.algs, "alg", nil, "Allowed algorithms (repeatable or comma-separated; default: all for the key type)")
	fs.StringVar(&f.iss, "iss", "", "Expected issuer")
	fs.StringVar(&f.sub, "sub", "", "Expected subject")
	fs.StringVar(&f.aud, "aud", "", "Expected audience (any entry may match)")
	fs.StringVar(&f.leeway, "leeway", "0s", "Clock skew tolerance for exp, nbf, and iat")
	fs.BoolVar(&f.ignoreExp, "ignore-exp", false, "Do not fail on an expired token")
	fs.BoolVar(&f.ignoreNbf, "ignore-nbf", false, "Do not fail on a token that is not valid yet")
	fs.StringSliceVar(&f.require, "require", nil, "Claims that must be present (comma-separated)")
	fs.BoolVar(&f.allowNone, "insecure-allow-none", false, "Accept unsigned tokens (alg none)")
	return cmd
}

func runVerify(cmd *cobra.Command, streams *ioStreams, args []string, f *verifyFlags) error {
	tok, err := tokenArg(args, streams.in)
	if err != nil {
		return err
	}
	d, err := token.Decode(tok)
	if err != nil {
		return usageError(err)
	}
	leeway, err := timeparse.Duration(f.leeway)
	if err != nil {
		return usageError(fmt.Errorf("--leeway: %w", err))
	}
	// --kid only selects a key out of a set, so it is meaningless for a
	// secret. --key is included because it accepts a JWKS document.
	if cmd.Flags().Changed("kid") && f.keys.jwksFile == "" && f.keys.jwksURL == "" && f.keys.key == "" {
		return usageError(errors.New("--kid applies only to JWKS sources"))
	}

	algs := nonEmpty(f.algs)
	require := nonEmpty(f.require)

	alg, _ := d.Header["alg"].(string)
	key, err := keys.Load(f.keys.source(streams), d.Header)
	if err != nil {
		// An unsigned token needs no key; every other load error is fatal.
		if alg != "none" || !errors.Is(err, keys.ErrNoKey) {
			return usageError(err)
		}
		key = nil
	}
	if key != nil {
		for _, a := range algs {
			if err := keys.Compatible(key, a); err != nil {
				return usageError(fmt.Errorf("--alg: %w", err))
			}
		}
	}

	res, err := token.Verify(tok, token.VerifyOptions{
		Key:       key,
		Algs:      algs,
		Issuer:    f.iss,
		Subject:   f.sub,
		Audience:  f.aud,
		Leeway:    leeway,
		IgnoreExp: f.ignoreExp,
		IgnoreNbf: f.ignoreNbf,
		AllowNone: f.allowNone,
		Require:   require,
		Now:       streams.now,
	})
	if err != nil {
		return usageError(err)
	}

	if jsonWanted(cmd) {
		err = output.JSON(streams.out, res)
	} else {
		err = output.Table(streams.out, res, renderOptions(cmd, streams))
	}
	if err != nil {
		return err
	}
	if !res.Verification.Valid {
		return failedVerification()
	}
	return nil
}

// nonEmpty trims whitespace from each item and drops blank entries, so a
// trailing comma in a repeatable flag ("--require sub," or "--alg HS256,")
// does not leave an empty string in the list.
func nonEmpty(items []string) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func init() { commandBuilders = append(commandBuilders, newVerifyCmd) }
