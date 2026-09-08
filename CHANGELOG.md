# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-09-08

### Changed
- The Debian package is now named `jwt-cli`, because Debian and Ubuntu ship an
  unrelated package called `jwt` that would always win on version. It declares
  a conflict with `jwt`. The rpm and apk packages keep the name `jwt` and
  declare a conflict with Alpine's unrelated `jwt-cli`. The installed command
  is `jwt` on every platform.

### Added
- Release workflow publishes the GitHub release, the Homebrew cask, and the
  deb, rpm, and apk packages on Gemfury (`apt.fury.io/lazhari`,
  `yum.fury.io/lazhari`, `alpine.fury.io/lazhari`).
- README install sections for Homebrew, Go, apt, dnf, apk, and prebuilt
  archives with checksum verification.

### Fixed
- Release runs are idempotent and serialized per tag.
- CI test step runs under bash on every OS; lint findings fixed; actions
  bumped to Node 24 majors.

## [2.0.0] - 2026-09-04

### Added
- Algorithms RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, and none.
- `verify` command with a check-by-check report, `--iss`, `--aud`, `--sub`,
  `--leeway`, `--ignore-exp`, `--ignore-nbf`, `--require`, and an
  algorithm allowlist via `--alg`.
- Keys from PEM (PKCS#1, PKCS#8, SEC1, PKIX, certificates), JWK, JWKS
  files, and JWKS URLs with `kid` lookup.
- `--secret-b64`, `--secret-file`, `--key`, and the `JWT_SECRET` and
  `JWT_KEY` environment variables.
- `keygen` for HMAC secrets and RSA, EC, Ed25519 key pairs in PEM or JWK.
- `jwk convert` and `jwk fetch`.
- `sign --claim key=value`, `--header key=value`, `--kid`, `--typ`,
  `--payload @file` and `-` for stdin.
- Token input from stdin or `@file`; `Bearer ` prefix stripped.
- `decode --part header|payload|signature` for piping into jq.
- `version` command and shell completion.
- `--no-color` and `NO_COLOR` support.

### Changed
- `decode` no longer verifies; use `verify`. `inspect` is a hidden alias of
  `decode`.
- `--json` prints one JSON document with sorted keys.
- Errors go to stderr; exit codes are 0 (ok), 1 (invalid token), 2 (usage
  or input error).
- Table output sorts keys, annotates timestamps with relative times, wraps
  long values instead of truncating, and renders nested values as JSON.
- Relative times such as `--exp +1h` are relative to now, not to `iat`.
- Requires Go 1.25. The key code uses `ecdsa.ParseUncompressedPublicKey`,
  `ecdsa.ParseRawPrivateKey`, and `(*ecdsa.PrivateKey).Bytes`, which were
  added in that release.

### Removed
- `decode --secret`. Pass the key to `verify` instead.

### Migration
- See the "Migrating from v1" table in the
  [README](README.md#migrating-from-v1) for the command-by-command
  mapping from 1.x.

## [1.0.0] - 2021-XX-XX

### Added
- Initial release
- `sign` command for creating JWT tokens
  - Support for HS256, HS384, HS512 algorithms
  - Custom JSON payload support
  - Standard JWT claims: iss, sub, aud, exp, nbf, iat, jti
  - Auto-generate JTI with `--jti-auto` flag
  - Flexible time formats (Unix timestamp, ISO 8601, relative time)
  - Optional iat with `--no-iat` flag
- `decode` command for verifying JWT tokens
  - Signature verification with secret key
  - Display header and payload
  - Show validity status
  - JSON output format option
  - Pretty table output with lipgloss
- `inspect` command for examining tokens without verification
  - Decode header and payload without secret
  - Display signature (without verification)
  - JSON output format option
  - Pretty table output
- Human-friendly time parsing (e.g., "1d", "5min", "+30m")
- Clean table output using charmbracelet/lipgloss
- MIT License

[2.0.1]: https://github.com/lazhari/jwt/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/lazhari/jwt/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/lazhari/jwt/releases/tag/v1.0.0
