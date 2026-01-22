# Contributing to JWT CLI

Thank you for your interest in contributing to JWT CLI! We welcome contributions from the community.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your changes
4. Make your changes
5. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git

### Clone and Build

```bash
# Clone your fork
git clone https://github.com/lazhari/jwt.git
cd jwt

# Download dependencies
go mod download

# Build the project
go build -o jwt .

# Run tests
go test ./...
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-rsa-support` - for new features
- `fix/token-parsing-bug` - for bug fixes
- `docs/update-readme` - for documentation changes
- `refactor/simplify-decode` - for refactoring

### Commit Messages

Write clear, concise commit messages:
- Use present tense ("Add feature" not "Added feature")
- First line should be 50 characters or less
- Reference issues and pull requests when applicable

Example:
```
Add RSA algorithm support

- Implement RS256, RS384, RS512 signing methods
- Add key file reading functionality
- Update documentation

Fixes #123
```

## Testing

All code changes should include tests:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -race -coverprofile=coverage.txt -covermode=atomic ./...

# Run tests verbosely
go test -v ./...
```

### Writing Tests

- Place test files next to the code they test (e.g., `sign.go` → `sign_test.go`)
- Use table-driven tests for multiple test cases
- Test both success and failure scenarios
- Aim for >70% code coverage

## Code Style

### Go Style Guidelines

- Follow standard Go formatting (use `gofmt` or `goimports`)
- Follow [Effective Go](https://golang.org/doc/effective_go)
- Write GoDoc comments for all exported functions
- Keep functions focused and small
- Use meaningful variable names

### Running Linters

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run
```

### Code Organization

- Put command implementations in the `cmd/` directory
- Keep helper functions close to where they're used
- Separate concerns (parsing, validation, output formatting)

## Submitting Changes

### Pull Request Process

1. **Update documentation** - Update README.md if adding features
2. **Add tests** - Ensure your changes are tested
3. **Run tests** - Make sure all tests pass
4. **Run linters** - Ensure code quality
5. **Update CHANGELOG.md** - Add entry for your changes
6. **Create PR** - Submit pull request with clear description

### Pull Request Description

Include in your PR description:
- What changes you made and why
- How to test the changes
- Screenshots (if UI changes)
- Related issues

Example:
```markdown
## Summary
Adds support for RSA algorithms (RS256, RS384, RS512)

## Changes
- Added RSA signing method implementations
- Added key file reading from filesystem
- Updated sign command to accept --key-file flag
- Added tests for RSA signing and verification

## Testing
go test ./...

## Related Issues
Closes #123
```

### Code Review

- Be open to feedback
- Respond to comments promptly
- Make requested changes in new commits
- Don't force-push after review has started

## Reporting Bugs

### Before Submitting

- Check if the bug has already been reported
- Try to reproduce with the latest version
- Gather relevant information (OS, Go version, etc.)

### Bug Report Template

```markdown
**Description**
Clear description of the bug

**Steps to Reproduce**
1. Run command: `jwt sign --payload '{"test":"data"}' --secret mysecret`
2. Observe error...

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: macOS 14.0
- Go version: 1.23
- JWT CLI version: 1.0.0

**Additional Context**
Any other relevant information
```

## Requesting Features

### Feature Request Template

```markdown
**Feature Description**
Clear description of the proposed feature

**Use Case**
Why this feature would be useful

**Proposed Implementation**
(Optional) How you think it could work

**Alternatives Considered**
(Optional) Other solutions you've thought about
```

## Questions?

If you have questions about contributing:
- Open a GitHub Discussion
- Check existing issues and PRs
- Review the README.md

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
