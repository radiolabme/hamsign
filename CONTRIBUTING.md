# Contributing to hamsign

Thank you for your interest in contributing to hamsign! We welcome contributions from the community.

## Reporting Issues

Bugs and feature requests can be submitted via [GitHub Issues](https://github.com/radiolabme/hamsign/issues).

For general questions and discussions, please use [GitHub Discussions](https://github.com/radiolabme/hamsign/discussions).

## Contributing Code

### Developer Certificate of Origin

Every commit must be signed off with the `Signed-off-by: REAL NAME <email@example.com>` line.

Use the `git commit -s` command to add the Signed-off-by line.

See the [Developer Certificate of Origin](https://developercertificate.org/) for more information.

### Licensing

hamsign is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE) for details.

By contributing to this project, you agree that your contributions will be licensed under the same BSD 3-Clause License.

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/hamsign.git
   cd hamsign
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/my-new-feature
   ```
4. **Make your changes** and write tests
5. **Run tests** to ensure everything works:
   ```bash
   go test ./...
   ```
6. **Format your code**:
   ```bash
   go fmt ./...
   ```
7. **Commit your changes** with sign-off:
   ```bash
   git commit -s -m "Add my new feature"
   ```
8. **Push to your fork**:
   ```bash
   git push origin feature/my-new-feature
   ```
9. **Open a Pull Request** on GitHub

### Pull Request Guidelines

- **Write clear commit messages** that explain what changed and why
- **Add tests** for any new functionality or bug fixes
- **Ensure all tests pass** (`go test ./...`)
- **Follow Go conventions** and use `gofmt` for formatting
- **Keep PRs focused** - one feature or fix per PR when possible
- **Update documentation** if your changes affect usage
- **Sign off all commits** with `git commit -s`

### Code Style

- Follow standard Go formatting (`gofmt`)
- Write clear, idiomatic Go code
- Add comments for exported functions and types
- Keep functions focused and reasonably sized
- Use meaningful variable and function names

### Testing

We strive for comprehensive test coverage:

- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test with real certificate files (requires `-tags=integration`)
- **Test data**: Use synthetic test data in `testdata/synthetic/`

Run tests:
```bash
# Unit tests only
go test ./...

# Include integration tests
go test -tags=integration ./...

# With coverage
go test -cover ./...

# Verbose output
go test -v ./...
```

### What to Contribute

Good areas for contribution:

- **Bug fixes**: Check [open issues](https://github.com/radiolabme/hamsign/issues)
- **Documentation**: Improve README, examples, or code comments
- **Tests**: Add test coverage for existing code
- **GABBI support**: Implement the wire format encoding/decoding
- **Examples**: Add real-world usage examples
- **Performance**: Profile and optimize hot paths
- **Platform support**: Test and document behavior on different platforms

Look for issues labeled [`good first issue`](https://github.com/radiolabme/hamsign/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) if you're new to the project.

### Questions?

If you have questions about contributing, feel free to:

- Open a [Discussion](https://github.com/radiolabme/hamsign/discussions)
- Ask in an existing issue
- Reach out to the maintainers

We appreciate your contributions and look forward to working with you!

## Release Process

Releases are managed by maintainers using semantic versioning:

1. Changes are merged to `main`
2. A version tag is created (e.g., `v0.1.0`)
3. GitHub Actions builds binaries for all platforms
4. The [radiolabme/homebrew-tap](https://github.com/radiolabme/homebrew-tap) is automatically updated with the new formula

Homebrew users receive updates via `brew upgrade hamsign`.
