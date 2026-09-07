package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lazhari/jwt/internal/output"
)

func newVersionCmd(streams *ioStreams) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if jsonWanted(cmd) {
				return output.WriteJSON(streams.out, map[string]string{"version": version, "commit": commit, "date": date})
			}
			_, err := fmt.Fprintf(streams.out, "jwt %s (%s, %s)\n", version, commit, date)
			return err
		},
	}
}

func init() { commandBuilders = append(commandBuilders, newVersionCmd) }
