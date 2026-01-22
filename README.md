# JWT CLI

[![Go Version](https://img.shields.io/github/go-mod/go-version/lazhari/jwt)](https://go.dev/)
[![CI](https://github.com/lazhari/jwt/workflows/CI/badge.svg)](https://github.com/lazhari/jwt/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/lazhari/jwt)](https://goreportcard.com/report/github.com/lazhari/jwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A fast, simple, and powerful command-line tool for creating, decoding, and inspecting JWT (JSON Web Tokens). Built with Go and Cobra.

## Features

- **Sign JWT tokens** with HMAC algorithms (HS256, HS384, HS512)
- **Decode and verify** JWT tokens with signature validation
- **Inspect tokens** without verification (like jwt.io)
- **Human-friendly time parsing** - Use `1d`, `5min`, `+30m`, `+7d` for expiration times
- **Beautiful table output** - Clean, styled output using lipgloss
- **JSON output option** - Machine-readable output for automation
- **Standard JWT claims** - Support for iss, sub, aud, exp, nbf, iat, jti
- **Auto-generate JTI** - UUID-style JWT ID generation
- **Cross-platform** - Works on Linux, macOS, and Windows

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Sign Command](#sign-command)
  - [Decode Command](#decode-command)
  - [Inspect Command](#inspect-command)
- [Examples](#examples)
- [Time Formats](#time-formats)
- [Algorithms](#algorithms)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Installation

### Using Go

```bash
go install github.com/lazhari/jwt@latest
```

### Using Homebrew (macOS/Linux)

```bash
brew install lazhari/tap/jwt
```

### Download Binary

Download the latest release for your platform from the [releases page](https://github.com/lazhari/jwt/releases).

### Build from Source

```bash
git clone https://github.com/lazhari/jwt.git
cd jwt
make build
# Binary will be in bin/jwt
```

## Quick Start

```bash
# Sign a JWT token
jwt sign --payload '{"user_id":123,"role":"admin"}' --secret "your-secret-key" --exp "+1h"

# Decode and verify a JWT
jwt decode YOUR_TOKEN_HERE --secret "your-secret-key"

# Inspect a JWT without verification
jwt inspect YOUR_TOKEN_HERE
```

## Usage

### Sign Command

Create and sign a new JWT token.

#### Basic Usage

```bash
jwt sign --payload '{"user_id":123}' --secret "my-secret-key"
```

#### With Standard Claims

```bash
jwt sign \
  --payload '{"user_id":123}' \
  --secret "my-secret-key" \
  --iss "https://example.com" \
  --sub "user123" \
  --aud "https://api.example.com" \
  --exp "+1h" \
  --jti-auto
```

#### Available Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--payload` | JSON payload (required) | `'{"user_id":123}'` |
| `--secret` | Secret key for signing (required) | `"my-secret-key"` |
| `--alg` | Algorithm (default: HS256) | `HS256`, `HS384`, `HS512` |
| `--iss` | Issuer claim | `"https://example.com"` |
| `--sub` | Subject claim | `"user123"` |
| `--aud` | Audience claim (repeatable) | `"https://api.example.com"` |
| `--exp` | Expiration time | `"+1h"`, `"1609459200"`, `"2024-01-01T00:00:00Z"` |
| `--nbf` | Not Before time | `"+5m"`, `"1609459200"` |
| `--iat` | Issued At time (default: now) | `"now"`, `"1609459200"` |
| `--no-iat` | Omit Issued At claim | (boolean flag) |
| `--jti` | JWT ID | `"unique-id-123"` |
| `--jti-auto` | Auto-generate JWT ID | (boolean flag) |

### Decode Command

Decode and verify a JWT token.

#### Basic Usage

```bash
jwt decode YOUR_TOKEN --secret "my-secret-key"
```

#### JSON Output

```bash
jwt decode YOUR_TOKEN --secret "my-secret-key" --json
```

#### Available Flags

| Flag | Description |
|------|-------------|
| `--secret` | Secret key for verification (required) |
| `--json` | Output in JSON format |

### Inspect Command

Inspect a JWT token without verification (no secret required).

#### Basic Usage

```bash
jwt inspect YOUR_TOKEN
```

#### JSON Output

```bash
jwt inspect YOUR_TOKEN --json
```

#### Available Flags

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |

## Examples

### Create a token that expires in 1 hour

```bash
jwt sign \
  --payload '{"user_id":123,"email":"user@example.com"}' \
  --secret "super-secret-key" \
  --exp "+1h"
```

### Create a token with multiple claims

```bash
jwt sign \
  --payload '{"data":"important"}' \
  --secret "my-secret" \
  --iss "auth-service" \
  --sub "user-456" \
  --aud "api-service" \
  --aud "web-app" \
  --exp "+7d" \
  --jti-auto
```

### Decode and verify a token

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjN9.abc123"
jwt decode $TOKEN --secret "my-secret"
```

### Inspect token without verification

```bash
# Useful for debugging or examining tokens when you don't have the secret
jwt inspect $TOKEN
```

### Use environment variables for secrets

```bash
# More secure than passing secrets on command line
export JWT_SECRET="my-secret-key"
jwt sign --payload '{"user_id":123}' --secret "$JWT_SECRET"
```

### Generate a token for testing APIs

```bash
# Create a token for API testing
TOKEN=$(jwt sign --payload '{"user_id":999,"role":"admin"}' --secret "test-key" --exp "+1d")
echo "Authorization: Bearer $TOKEN"

# Use with curl
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/protected
```

## Time Formats

The `--exp`, `--nbf`, and `--iat` flags support multiple time formats:

### Relative Time (from now)

```bash
--exp "+1h"      # 1 hour from now
--exp "+30m"     # 30 minutes from now
--exp "+7d"      # 7 days from now
--exp "+60s"     # 60 seconds from now
--nbf "+5min"    # 5 minutes from now (alternative syntax)
```

Supported units: `d` (days), `h` (hours), `m`/`min` (minutes), `s`/`sec` (seconds)

### Unix Timestamp

```bash
--exp "1609459200"
```

### ISO 8601 / RFC 3339

```bash
--exp "2024-12-31T23:59:59Z"
--exp "2024-06-15T10:30:00+02:00"
```

## Algorithms

Currently supported HMAC algorithms:

| Algorithm | Description | Key Size |
|-----------|-------------|----------|
| HS256 | HMAC-SHA256 (default) | 256 bits (32 bytes) |
| HS384 | HMAC-SHA384 | 384 bits (48 bytes) |
| HS512 | HMAC-SHA512 | 512 bits (64 bytes) |

### Generating Strong Secrets

```bash
# Generate a strong secret (32 bytes for HS256)
openssl rand -base64 32

# Or use /dev/urandom
head -c 32 /dev/urandom | base64
```

## Building from Source

### Prerequisites

- Go 1.21 or later
- Make (optional, for using Makefile)

### Build

```bash
# Clone the repository
git clone https://github.com/lazhari/jwt.git
cd jwt

# Using Make
make build

# Or using Go directly
go build -o jwt .
```

### Run Tests

```bash
# Using Make
make test

# With coverage
make test-coverage

# Or using Go directly
go test ./...
```

### Available Make Targets

```bash
make help           # Show all available targets
make build          # Build the binary
make install        # Install to GOPATH/bin
make test           # Run tests
make test-coverage  # Run tests with coverage
make lint           # Run golangci-lint
make fmt            # Format code
make clean          # Remove build artifacts
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:

- Setting up your development environment
- Code style guidelines
- Submitting pull requests
- Reporting bugs
- Requesting features

Quick contribution steps:

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run tests: `make test`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## Security Best Practices

**Protect your secrets:**
- Use environment variables instead of command-line arguments
  ```bash
  export JWT_SECRET="my-secret-key"
  jwt sign --payload '{"user_id":123}' --secret "$JWT_SECRET"
  ```
- Generate strong secrets: `openssl rand -base64 32`
- Never commit secrets to version control

**Token validation:**
- Always verify tokens with `decode` command using the correct secret
- Use `inspect` only for debugging (it doesn't verify signatures)
- Set appropriate expiration times with `--exp`

For security issues, please open a GitHub issue.

## Roadmap

Planned features for future releases:

- [ ] RSA algorithm support (RS256, RS384, RS512)
- [ ] ECDSA algorithm support (ES256, ES384, ES512)
- [ ] Read secrets from files (`--secret-file`)
- [ ] Interactive secret input
- [ ] Config file support
- [ ] Shell completion (bash, zsh, fish)
- [ ] Token validation with custom claims
- [ ] Batch token operations
- [ ] Key generation utility

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) - CLI framework
- JWT implementation by [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
- Beautiful terminal output by [Charm](https://github.com/charmbracelet) - Lipgloss

## Support

- **Issues**: [GitHub Issues](https://github.com/lazhari/jwt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lazhari/jwt/discussions)
- **Documentation**: [GitHub Wiki](https://github.com/lazhari/jwt/wiki)

---

Made with ❤️ by [Lazhari](https://github.com/lazhari)
