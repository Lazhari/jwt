package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lazhari/jwt/internal/output"
	"github.com/lazhari/jwt/internal/token"
)

func newDecodeCmd(streams *ioStreams) *cobra.Command {
	var part string
	cmd := &cobra.Command{
		Use:   "decode [token]",
		Short: "Show header, payload, and signature without verifying",
		Long: `Decode a token without checking its signature or claims. The token is
the first argument, - for stdin, or @file; with no argument it is read from
piped stdin. A leading "Bearer " prefix is stripped.`,
		Example: `  jwt decode eyJhbGciOi...
  curl -s ... | jq -r .access_token | jwt decode
  jwt decode "$TOKEN" --part payload | jq .sub`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecode(cmd, streams, args, part)
		},
	}
	cmd.Flags().StringVar(&part, "part", "", "Print only one part as raw JSON: header, payload, or signature")
	return cmd
}

// newInspectCmd keeps the v1 name working as a hidden alias.
func newInspectCmd(streams *ioStreams) *cobra.Command {
	cmd := newDecodeCmd(streams)
	cmd.Use = "inspect [token]"
	cmd.Short = "Alias of decode"
	cmd.Hidden = true
	return cmd
}

func runDecode(cmd *cobra.Command, streams *ioStreams, args []string, part string) error {
	tok, err := tokenArg(args, streams.in)
	if err != nil {
		return err
	}
	d, err := token.Decode(tok)
	if err != nil {
		return usageError(err)
	}
	switch part {
	case "":
	case "header":
		return output.WriteJSON(streams.out, d.Header)
	case "payload":
		return output.WriteJSON(streams.out, d.Payload)
	case "signature":
		_, err := fmt.Fprintln(streams.out, d.Signature)
		return err
	default:
		return usageError(fmt.Errorf("--part must be header, payload, or signature, got %q", part))
	}
	res := &token.Result{Decoded: d}
	if jsonWanted(cmd) {
		return output.JSON(streams.out, res)
	}
	return output.Table(streams.out, res, renderOptions(cmd, streams))
}

func init() {
	commandBuilders = append(commandBuilders, newDecodeCmd, newInspectCmd)
}
