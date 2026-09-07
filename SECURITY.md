# Security Policy

## Reporting a vulnerability

Open a GitHub issue marked "security" or email the maintainer address on
the GitHub profile. Include the command, flags, and inputs that reproduce
the problem. Expect an acknowledgement within a week.

## Scope

This tool handles secrets and private keys. The following are treated as
security bugs:

- A token verifying with the wrong key or algorithm (algorithm confusion,
  `none` accepted without `--insecure-allow-none`).
- Key material written to stdout or stderr unintentionally.
- Files created with permissions wider than 0600. This is best-effort on
  Windows, which has no POSIX permission bits: the file inherits the
  directory ACL and Go reports mode 0666 for it.
- JWKS fetches over plain HTTP to non-loopback hosts, or following
  redirects to them.

## Handling secrets

- Prefer `--secret-file`, `--key`, or the `JWT_SECRET` and `JWT_KEY`
  environment variables over `--secret` on the command line, which lands
  in shell history and process listings.
- HMAC secrets should be at least as long as the hash output. The tool
  warns below 32 bytes; use 32 bytes for HS256, 48 bytes for HS384, and
  64 bytes for HS512. `jwt keygen --alg HS384` produces a secret of the
  right size for its algorithm.
- `decode` never verifies. Use `verify` before trusting any claim.
