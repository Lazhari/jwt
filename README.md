# jwt

[![Go Version](https://img.shields.io/github/go-mod/go-version/lazhari/jwt)](https://go.dev/)
[![CI](https://github.com/lazhari/jwt/workflows/CI/badge.svg)](https://github.com/lazhari/jwt/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/lazhari/jwt)](https://goreportcard.com/report/github.com/lazhari/jwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A command-line tool for creating, decoding, verifying, and debugging JSON
Web Tokens. Every JWS algorithm, keys from PEM, JWK, JWKS files or URLs, a
check-by-check verification report, key generation, and scriptable JSON
output with real exit codes.

## Install

### Quick install (Linux and macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/lazhari/jwt/main/install.sh | sh
```

The script picks the release archive for your OS and CPU, verifies its
SHA-256 against the release's `checksums.txt`, and installs `jwt` into
`/usr/local/bin` when that is writable or `~/.local/bin` otherwise. It never
runs `sudo`; use `curl -fsSL ... | sudo sh` for a system-wide install. Set
`JWT_VERSION=2.0.1` to pin a release or `JWT_INSTALL_DIR=/some/dir` to choose
the location. Piping a script into a shell is convenient, not mandatory: you
can download [install.sh](install.sh), read it, and run it with `sh`.

### Homebrew (macOS and Linux)

```bash
brew install lazhari/tap/jwt
```

### Go

```bash
go install github.com/lazhari/jwt@latest
```

### Debian and Ubuntu

```bash
VERSION=2.0.0 ARCH=amd64   # ARCH: amd64, arm64, or armv7
curl -LO "https://github.com/lazhari/jwt/releases/download/v${VERSION}/jwt-cli_${VERSION}_linux_${ARCH}.deb"
sudo apt install "./jwt-cli_${VERSION}_linux_${ARCH}.deb"
```

### Fedora, RHEL, and openSUSE

```bash
VERSION=2.0.0 ARCH=amd64
sudo dnf install "https://github.com/lazhari/jwt/releases/download/v${VERSION}/jwt_${VERSION}_linux_${ARCH}.rpm"
```

### Alpine

```bash
VERSION=2.0.0 ARCH=amd64
wget "https://github.com/lazhari/jwt/releases/download/v${VERSION}/jwt_${VERSION}_linux_${ARCH}.apk"
sudo apk add --allow-untrusted "./jwt_${VERSION}_linux_${ARCH}.apk"
```

### Package repositories (apt, dnf, apk)

Releases are also pushed to a Gemfury repository, so you can add it once and
get updates with your package manager.

```bash
# Debian and Ubuntu
echo "deb [trusted=yes] https://apt.fury.io/lazhari/ /" | sudo tee /etc/apt/sources.list.d/lazhari.list
sudo apt update && sudo apt install jwt-cli

# Fedora, RHEL, and openSUSE
printf '[lazhari]\nname=lazhari\nbaseurl=https://yum.fury.io/lazhari/\nenabled=1\ngpgcheck=0\n' | sudo tee /etc/yum.repos.d/lazhari.repo
sudo dnf install jwt

# Alpine
echo "https://alpine.fury.io/lazhari/" | sudo tee -a /etc/apk/repositories
sudo apk add --allow-untrusted jwt
```

The packages are not GPG-signed yet, which is why the apt line uses
`trusted=yes`, the yum repo sets `gpgcheck=0`, and Alpine needs
`--allow-untrusted`. Signed packages are planned.

Package names differ by family on purpose: `jwt-cli` on Debian and Ubuntu,
because those distributions already ship an unrelated package called `jwt`,
and `jwt` on Fedora and Alpine. The installed command is `jwt` everywhere.

### Prebuilt binaries

Archives for Linux (x86_64, arm64, armv7), macOS (x86_64, arm64), and Windows
(x86_64) are attached to every release on the
[releases page](https://github.com/lazhari/jwt/releases), together with a
`checksums.txt` file.

```bash
VERSION=2.0.0
curl -LO "https://github.com/lazhari/jwt/releases/download/v${VERSION}/jwt_${VERSION}_Linux_x86_64.tar.gz"
curl -LO "https://github.com/lazhari/jwt/releases/download/v${VERSION}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt
tar -xzf "jwt_${VERSION}_Linux_x86_64.tar.gz" jwt && sudo install -m 0755 jwt /usr/local/bin/jwt
```

On macOS use `shasum -a 256 --ignore-missing -c checksums.txt` and the
`Darwin_arm64` or `Darwin_x86_64` archive.

## Quick start

```bash
# Create a secret and sign a token
export JWT_SECRET=$(jwt keygen --alg HS256)
TOKEN=$(jwt sign --claim sub=user-1 --claim role=admin --exp +1h)

# Look inside without verifying
jwt decode "$TOKEN"

# Verify signature and claims
jwt verify "$TOKEN" --aud api --iss https://auth.example.com

# Script it
jwt verify "$TOKEN" --json | jq .verification.valid
jwt decode "$TOKEN" --part payload | jq -r .sub
```

## Commands

| Command | Purpose |
|---------|---------|
| `jwt sign` | Create and sign a token |
| `jwt decode` | Show header, payload, and signature without verifying |
| `jwt verify` | Verify signature and claims, print a report |
| `jwt keygen` | Generate an HMAC secret or an RSA, EC, or Ed25519 key pair |
| `jwt jwk convert` | Convert a key between PEM and JWK |
| `jwt jwk fetch` | Download a JWKS, or one key by kid |
| `jwt version` | Print version information |
| `jwt completion` | Shell completion for bash, zsh, fish, PowerShell |

Global flags: `--json` prints one JSON document; `--no-color` disables
styling (so does the `NO_COLOR` environment variable or a non-terminal
stdout).

### Token input

`decode` and `verify` take the token as the first argument, `-` for stdin,
or `@file`. With no argument the token is read from piped stdin. A leading
`Bearer ` prefix and surrounding whitespace are stripped.

```bash
curl -s https://auth.example.com/token | jq -r .access_token | jwt decode
jwt verify @token.txt --key public.pem
```

### Keys

`sign` and `verify` accept exactly one key source:

| Flag | Meaning |
|------|---------|
| `--secret` | HMAC secret as text |
| `--secret-b64` | HMAC secret, base64 or base64url encoded |
| `--secret-file` | HMAC secret read from a file |
| `--key` | PEM or JWK file, or `-` for stdin. Format is detected |
| `--jwks-file` | JWKS file, key chosen by `kid` (verify only) |
| `--jwks-url` | JWKS fetched over HTTPS, key chosen by `kid` (verify only) |
| `--kid` | Override the `kid` used for JWKS lookup (verify only) |

Environment fallbacks: `JWT_SECRET` for `--secret`, `JWT_KEY` for `--key`.

The tool warns when an HMAC secret is below 32 bytes; use 32 bytes for
HS256, 48 bytes for HS384, and 64 bytes for HS512. `jwt keygen` produces a
secret of the right size for the algorithm you name.

PEM inputs may be PKCS#1, PKCS#8, SEC1, PKIX, or an X.509 certificate.
A private key given to `verify` is accepted and its public half is used.
JWKS URLs must use HTTPS, except plain HTTP to localhost.

### Algorithms

| Family | Algorithms | Key |
|--------|-----------|-----|
| HMAC | HS256, HS384, HS512 | secret |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 | RSA key |
| RSA PSS | PS256, PS384, PS512 | RSA key |
| ECDSA | ES256, ES384, ES512 | EC P-256, P-384, P-521 |
| EdDSA | EdDSA | Ed25519 |
| Unsigned | none | sign only, or verify with `--insecure-allow-none` |

When `--alg` is omitted in `sign`, it is inferred from the key: HS256,
RS256, ES256/ES384/ES512 by curve, or EdDSA. In `verify`, the allowed
algorithms default to every algorithm the key type supports; pass `--alg`
to narrow the list. A key that does not match the allowed algorithms is
rejected before the token is checked.

## sign

```bash
jwt sign --secret "$JWT_SECRET" --payload '{"user_id":123}' --exp +1h
jwt sign --key private.pem --alg PS256 --payload @claims.json --kid 2025-01
jwt sign --secret "$JWT_SECRET" --claim role=admin --claim id=7 --aud api --aud web --jti-auto
jwt sign --alg none --claim test=true        # unsigned fixture
```

Claims are merged in this order, later winning: `--payload`, then
`--claim` flags, then the standard claim flags (`--iss`, `--sub`, `--aud`,
`--exp`, `--nbf`, `--iat`, `--jti`). A `--claim` value that is valid JSON
is parsed, so `id=7` is a number and `flag=true` a boolean; anything else
is a string. Use `id='"7"'` for a string that looks like JSON.

Header flags: `--kid`, `--typ` (default `JWT`), and repeatable
`--header key=value`.

Time flags accept `now`, a relative offset such as `+1h` or `-30m`
(units: `d`, `h`, `m`/`min`, `s`/`sec`, or Go durations like `1h30m`), a
Unix timestamp, or RFC 3339. Relative offsets are always relative to now.
`iat` defaults to now; `--no-iat` omits it.

## decode

```bash
jwt decode "$TOKEN"
jwt decode "$TOKEN" --json
jwt decode "$TOKEN" --part payload | jq .
```

Timestamps are shown as the raw value, UTC time, and a relative note such
as `expires in 2h13m` or `expired 3d ago`. Nested values are shown as
compact JSON. Keys are sorted.

`decode` tolerates base64 padding on the segments so a malformed token can
still be inspected. `verify` does not: padded segments are rejected there,
the way RFC 7515-strict servers reject them.

## verify

```bash
jwt verify "$TOKEN" --secret "$JWT_SECRET"
jwt verify "$TOKEN" --key public.pem --iss https://auth.example.com --aud api --sub user-1
jwt verify "$TOKEN" --jwks-url https://auth.example.com/.well-known/jwks.json
jwt verify "$TOKEN" --secret "$JWT_SECRET" --leeway 30s --require exp,jti
jwt verify "$TOKEN" --secret "$JWT_SECRET" --ignore-exp      # debug an old token
```

The report lists each check: `alg`, `crit` when the header carries one,
`signature`, `exp`, `nbf` and `iat` when present, `iss`/`aud`/`sub` when
expected values are given, and one `require:<claim>` line per `--require`
entry. The header and payload are printed even when verification fails.

A JWK that declares `alg` narrows the default allowlist to that one
algorithm, and a key marked `use: enc` is refused outright. A token whose
header carries `crit` is rejected, since this tool implements no header
extensions; `typ` is not checked.

Exit codes: `0` valid, `1` the token failed a check, `2` the token or key
could not be read.

## keygen

```bash
jwt keygen --alg HS256                                # base64url secret on stdout
jwt keygen --alg ES256 --out ec.pem --pub ec.pub      # PKCS#8 + PKIX PEM, mode 0600
jwt keygen --alg RS256 --bits 4096 --format jwk --kid 2025-01
```

Files are never overwritten.

## jwk

```bash
jwt jwk convert --in private.pem --kid 2025-01 > private.jwk
jwt jwk convert --in private.pem --public > public.jwk
jwt jwk convert --in key.jwk > key.pem
jwt jwk fetch https://auth.example.com/.well-known/jwks.json --kid abc
```

## JSON output

With `--json`, `decode` and `verify` print one document:

```json
{
  "header": { "alg": "RS256", "kid": "abc", "typ": "JWT" },
  "payload": { "exp": 1735740780, "sub": "user-1" },
  "signature": "…",
  "verification": {
    "valid": true,
    "algorithm": "RS256",
    "key_source": "jwks:abc",
    "checks": [
      { "name": "alg", "passed": true, "skipped": false, "detail": "RS256" },
      { "name": "signature", "passed": true, "skipped": false, "detail": "verified with jwks:abc" },
      { "name": "exp", "passed": true, "skipped": false, "detail": "expires in 2h13m" }
    ]
  }
}
```

`decode` omits `verification`. `sign --json` prints `token`, `header`, and
`payload`.

## Migrating from v1

| v1 | v2 |
|----|----|
| `jwt decode TOKEN --secret S` | `jwt verify TOKEN --secret S` |
| `jwt inspect TOKEN` | `jwt decode TOKEN` (`inspect` still works) |
| `--json` printed labelled fragments | one JSON document |
| errors on stdout, exit 0 | errors on stderr, exit 1 or 2 |
| `--exp +1h` relative to `iat` | relative to now |

## Building

```bash
git clone https://github.com/lazhari/jwt.git && cd jwt
make build          # bin/jwt
make test           # go test -race ./...
make test-coverage  # coverage report
make lint           # golangci-lint
```

Requires Go 1.25 or later.

## Security

See [SECURITY.md](SECURITY.md). Short version: keep secrets out of the
command line, use `verify` not `decode` before trusting a token, never
pass `--insecure-allow-none` outside of tests, and give HMAC secrets at
least 32 bytes (48 for HS384, 64 for HS512).

## License

MIT. See [LICENSE](LICENSE).
