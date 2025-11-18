# JWT CLI

A command-line tool for signing and decoding JWT tokens, built with Cobra and Go.

## Installation

Install the CLI using Go:

```bash
go install github.com/lazhari/jwt@latest
```

## Usage

### Sign a JWT

Sign a JWT with custom payload, key, and algorithm:

```bash
jwt sign --payload '{"user_id":123,"role":"admin"}' --key 'mysecretkey' --alg HS256 --exp "1d"
```

### Decode a JWT

Decode and verify a JWT:

```bash
jwt decode 'your.jwt.token' --key 'mysecretkey'
```

### Inspect a JWT

Inspect a JWT without verification (like jwt.io):

```bash
jwt inspect 'your.jwt.token'
```

### Options

- `--json`: Output in JSON format instead of tables (for decode and inspect)

## Features

- Sign JWTs with HS256, HS384, HS512 algorithms
- Human-friendly expiration times (e.g., 1d, 5min)
- Decode and verify JWTs
- Inspect JWTs without secrets
- Clean table output with lipgloss
- JSON output option

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

MIT License - see LICENSE file for details
