// Command jwt signs, decodes, verifies, and inspects JSON Web Tokens.
package main

import "github.com/lazhari/jwt/cmd"

// Set by GoReleaser through -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersion(version, commit, date)
	cmd.Execute()
}
