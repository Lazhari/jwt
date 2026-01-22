// Package cmd provides the command-line interface implementation for the JWT CLI tool.
// It includes commands for signing, decoding, and inspecting JWT tokens.
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "jwt",
	Short: "JWT CLI tool for signing and decoding tokens",
	Long:  `A CLI tool to sign and decode JWT tokens using various algorithms.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
