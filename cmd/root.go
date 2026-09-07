// Package cmd implements the jwt command-line interface. Each command is a
// thin layer over the internal packages: flags in, one call, render out.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// Version information, set by main from ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// SetVersion records build information for the version command.
func SetVersion(v, c, d string) { version, commit, date = v, c, d }

// ioStreams carries every process-level dependency so commands are testable.
type ioStreams struct {
	in   io.Reader
	out  io.Writer
	err  io.Writer
	env  func(string) string
	now  func() time.Time
	http *http.Client // nil means the keys package default
}

// commandBuilders is filled by init functions in the command files.
var commandBuilders []func(*ioStreams) *cobra.Command

// exitError carries an exit code. A nil err prints nothing.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// usageError marks an input, key, or I/O problem: exit code 2.
func usageError(err error) error { return &exitError{code: 2, err: err} }

// failedVerification marks a token that did not verify: exit code 1. The
// report already explains why, so no message is printed.
func failedVerification() error { return &exitError{code: 1} }

func newRootCmd(streams *ioStreams) *cobra.Command {
	root := &cobra.Command{
		Use:   "jwt",
		Short: "Sign, decode, verify, and inspect JSON Web Tokens",
		Long: `jwt is a command-line tool for working with JSON Web Tokens.

Algorithms: HS256 HS384 HS512, RS256 RS384 RS512, PS256 PS384 PS512,
ES256 ES384 ES512, EdDSA, and none (sign only, or verify with
--insecure-allow-none).

Keys come from --secret, --secret-b64, --secret-file, --key (PEM or JWK),
--jwks-file, --jwks-url, or the JWT_SECRET and JWT_KEY environment variables.

Exit codes: 0 success or valid token, 1 token failed verification,
2 usage, input, key, or I/O error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().Bool("json", false, "Output a single JSON document")
	root.PersistentFlags().Bool("no-color", false, "Disable colored output (also NO_COLOR env)")
	root.SetIn(streams.in)
	root.SetOut(streams.out)
	root.SetErr(streams.err)
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return usageError(fmt.Errorf("%w\nRun '%s --help' for usage", err, c.CommandPath()))
	})
	for _, build := range commandBuilders {
		root.AddCommand(build(streams))
	}
	return root
}

// run executes the CLI and returns the exit code.
func run(args []string, streams *ioStreams) int {
	root := newRootCmd(streams)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			_, _ = fmt.Fprintf(streams.err, "jwt: %v\n", ee.err)
		}
		return ee.code
	}
	_, _ = fmt.Fprintf(streams.err, "jwt: %v\n", err)
	return 2
}

// Run executes the CLI with the given streams and returns the exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return run(args, &ioStreams{in: stdin, out: stdout, err: stderr, env: os.Getenv, now: time.Now})
}

// Execute runs the CLI on os.Args and exits the process.
func Execute() {
	os.Exit(Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
