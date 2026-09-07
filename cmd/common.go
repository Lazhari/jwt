package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/lazhari/jwt/internal/keys"
	"github.com/lazhari/jwt/internal/output"
	"github.com/lazhari/jwt/internal/token"
)

const defaultWidth = 100

// readInput resolves a value spec: "-" reads stdin, "@path" reads a file,
// anything else is the literal value.
func readInput(spec string, stdin io.Reader) ([]byte, error) {
	switch {
	case spec == "-":
		return io.ReadAll(stdin)
	case strings.HasPrefix(spec, "@"):
		return os.ReadFile(spec[1:])
	}
	return []byte(spec), nil
}

// tokenArg returns the token from the single positional argument (literal,
// "-", or "@path") or, with no argument, from piped stdin.
func tokenArg(args []string, stdin io.Reader) (string, error) {
	var raw []byte
	switch len(args) {
	case 1:
		b, err := readInput(args[0], stdin)
		if err != nil {
			return "", usageError(fmt.Errorf("reading token: %w", err))
		}
		raw = b
	case 0:
		if isTerminal(stdin) {
			return "", usageError(errors.New("no token given: pass it as an argument or pipe it on stdin"))
		}
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", usageError(fmt.Errorf("reading token from stdin: %w", err))
		}
		raw = b
	default:
		return "", usageError(errors.New("expected one token argument"))
	}
	tok := token.Clean(string(raw))
	if tok == "" {
		return "", usageError(errors.New("token is empty"))
	}
	return tok, nil
}

// isTerminal reports whether v is backed by a terminal. It accepts anything
// with an Fd method, not just *os.File, so wrapped streams still work.
func isTerminal(v any) bool {
	f, ok := v.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(f.Fd())
}

// keyFlags binds the shared key-source flags.
type keyFlags struct {
	secret, secretB64, secretFile, key, jwksFile, jwksURL, kid string
}

func (f *keyFlags) bind(cmd *cobra.Command, verify bool) {
	fs := cmd.Flags()
	fs.StringVar(&f.secret, "secret", "", "HMAC secret as text (or set JWT_SECRET)")
	fs.StringVar(&f.secretB64, "secret-b64", "", "HMAC secret, base64 or base64url encoded")
	fs.StringVar(&f.secretFile, "secret-file", "", "Read the HMAC secret from a file")
	fs.StringVar(&f.key, "key", "", "PEM or JWK key file, or - for stdin (or set JWT_KEY)")
	if verify {
		fs.StringVar(&f.jwksFile, "jwks-file", "", "JWKS file; the key is chosen by kid")
		fs.StringVar(&f.jwksURL, "jwks-url", "", "JWKS URL (https); the key is chosen by kid")
		fs.StringVar(&f.kid, "kid", "", "Key ID to select from the JWKS (overrides the token header)")
	}
}

func (f *keyFlags) source(streams *ioStreams) keys.Source {
	return keys.Source{
		Secret:     f.secret,
		SecretB64:  f.secretB64,
		SecretFile: f.secretFile,
		KeyPath:    f.key,
		JWKSFile:   f.jwksFile,
		JWKSURL:    f.jwksURL,
		KID:        f.kid,
		Env:        streams.env,
		Stdin:      streams.in,
		HTTP:       streams.http,
		Warn:       streams.err,
	}
}

func jsonWanted(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("json")
	return v
}

// renderOptions decides colour and width from flags, environment, and
// whether stdout is a terminal.
func renderOptions(cmd *cobra.Command, streams *ioStreams) output.Options {
	noColor, _ := cmd.Flags().GetBool("no-color")
	color := !noColor && streams.env("NO_COLOR") == "" && isTerminal(streams.out)

	width := defaultWidth
	if f, ok := streams.out.(*os.File); ok {
		if w, _, err := term.GetSize(f.Fd()); err == nil && w > 0 {
			width = w
		}
	}
	if cols := streams.env("COLUMNS"); cols != "" {
		if n, err := strconv.Atoi(cols); err == nil && n > 0 {
			width = n
		}
	}
	return output.Options{Color: color, Width: width, Now: streams.now()}
}
