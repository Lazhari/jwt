# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive unit tests for all commands
- GitHub Actions CI/CD workflow
- CONTRIBUTING.md with contribution guidelines
- SECURITY.md with security policy and best practices
- This CHANGELOG.md file
- Makefile for build automation
- GoReleaser configuration for releases
- GoDoc comments for exported functions

### Changed
- Improved README.md with badges and better documentation
- Updated .gitignore to exclude build artifacts

### Removed
- Compiled binary from version control

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

[Unreleased]: https://github.com/lazhari/jwt/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/lazhari/jwt/releases/tag/v1.0.0
