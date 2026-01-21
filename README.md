# hamsign

[![Go Reference](https://pkg.go.dev/badge/github.com/radiolabme/hamsign.svg)](https://pkg.go.dev/github.com/radiolabme/hamsign)
[![CI](https://github.com/radiolabme/hamsign/actions/workflows/ci.yml/badge.svg)](https://github.com/radiolabme/hamsign/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/radiolabme/hamsign)](https://goreportcard.com/report/github.com/radiolabme/hamsign)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://radiolabme.github.io/hamsign/)

A Go library for digital signing and certificate management in amateur radio operations.

## Overview

Amateur radio operators have long sought verifiable methods to confirm the authenticity of contact records (QSOs). The ARRL's Logbook of The World (LoTW) pioneered the use of X.509 certificates with amateur radio-specific extensions to create cryptographically signed QSO records. This approach enables operators to prove they held a particular callsign at a specific time and location, establishing trust in contest adjudication, award verification, and general record-keeping.

**hamsign** provides a clean, well-tested Go implementation of the core Trusted QSL (TQSL) certificate operations and signing primitives. It handles the specialized X.509 extensions defined for amateur radio use, manages certificate chains with flexible expiry policies, and provides tools for generating certificate requests with embedded station information.

## Motivation

The original TQSL software, while functional, presents challenges for modern development:

- **Aging codebase**: The reference implementation has accumulated decades of technical debt
- **Limited portability**: C++ dependencies and platform-specific code complicate deployment
- **Integration barriers**: Difficult to embed in web services, mobile applications, or cloud infrastructure
- **Testing limitations**: Legacy architecture makes comprehensive automated testing challenging

This project addresses these issues by providing:

- **Clean Go implementation**: Idiomatic code with comprehensive test coverage
- **Minimal dependencies**: Only requires standard library and well-maintained crypto packages
- **Modern APIs**: Structured types and clear error handling for integration
- **Format compatibility**: Reads and writes standard TQSL file formats (TQ5/TQ6/TQ8)
- **Flexible verification**: Configurable certificate expiry policies for various deployment scenarios

## Features

### Certificate Operations
- Load certificates and keys from PKCS#12 (`.p12`) and PEM formats
- Parse TQ6 (certificate) and TQ8 (certificate request) files with transparent gzip handling
- Generate certificate requests (TQ5) with encrypted private keys
- Support for certificate renewal with cryptographic proof of identity
- Export to PKCS#12 format for compatibility with existing tools

### Digital Signing
- RSA-SHA1 signing for compatibility with existing TQSL infrastructure
- Certificate chain verification with embedded or custom CA certificates
- Multiple expiry policies: strict, ignore CA expiry, or ignore all expiry
- QSO date range validation against certificate restrictions

### Amateur Radio Extensions
- Extract callsign, operator name, and email from certificates
- Parse DXCC entity codes and QSO date restrictions
- Handle address information from certificate requests
- Support for all TQSL custom OIDs (1.3.6.1.4.1.12348.1.*)

## Related Work

This library builds on decades of work in amateur radio digital signing:

- **[ARRL Logbook of The World](http://www.arrl.org/logbook-of-the-world)**: The pioneering amateur radio QSO confirmation system
- **[Trusted QSL specifications](https://sourceforge.net/projects/trustedqsl/)**: Original format and protocol documentation from the ARRL and Darryl Wagoner WA1GON
- **[TQSL source code](https://sourceforge.net/p/trustedqsl/tqsl/ci/master/tree/)**: Reference C++ implementation maintained by the ARRL
- **[Amateur Radio Digital Certificates (RFC)](https://www.itu.int/dms_pubrec/itu-r/rec/m/R-REC-M.1371-5-201402-I!!PDF-E.pdf)**: ITU recommendations for amateur radio station identification

The custom X.509 extensions used by this library follow the private enterprise number (PEN) allocation to the ARRL (12348) and the OID structure defined in the Trusted QSL specifications.

## Installation

### As a Library

```bash
go get github.com/radiolabme/hamsign
```

### CLI Tools (Homebrew)

```bash
brew tap radiolabme/tap
brew install hamsign
```

See [radiolabme/homebrew-tap](https://github.com/radiolabme/homebrew-tap) for more installation options.

## Usage

### Loading and Signing

```go
package main

import (
    "log"
    "os"
    "github.com/radiolabme/hamsign"
)

func main() {
    // Load certificate and key from PKCS#12 file
    p12Data, _ := os.ReadFile("certificate.p12")
    cert, key, err := hamsign.LoadPKCS12(p12Data, "password")
    if err != nil {
        log.Fatal(err)
    }

    // Create signer with default embedded CA certificates
    signer, err := hamsign.NewSigner(cert, key, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Extract station information
    info, err := hamsign.ParseStationInfo(cert)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Callsign: %s", info.Callsign)
    log.Printf("Operator: %s", info.OperatorName)

    // Sign data
    data := []byte("QSO record data")
    signature, err := signer.Sign(data)
    if err != nil {
        log.Fatal(err)
    }

    // Verify signature
    err = signer.Verify(data, signature)
    if err != nil {
        log.Fatal(err)
    }
}
```

### Certificate Request Generation

```go
req := &hamsign.CertificateRequest{
    Callsign:     "N0CALL",
    Name:         "Jane Smith",
    Email:        "jane@example.com",
    Address1:     "123 Main St",
    City:         "Anytown",
    State:        "NY",
    PostalCode:   "12345",
    Country:      "US",
    DXCC:         291,
    QSONotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
    QSONotAfter:  time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
}

tq5, encryptedKey, err := hamsign.GenerateRequest(req, "password")
if err != nil {
    log.Fatal(err)
}

// Write TQ5 and encrypted key to files
os.WriteFile("request.tq5", tq5, 0644)
os.WriteFile("request.key", encryptedKey, 0600)
```

## Project Structure

```
hamsign/
├── hamsign.go          # Core signing and certificate operations
├── request.go          # Certificate request generation
├── hamcert/            # X.509 extension parsing (standalone package)
│   └── hamcert.go
├── gabbi/              # GABBI wire format (placeholder)
│   └── gabbi.go
├── example/            # Example programs demonstrating usage
│   ├── loadcert/       # Load and inspect TQ6 certificates
│   ├── signdata/       # Sign data with PKCS#12 files
│   └── verifycert/     # Certificate chain verification
└── testdata/           # Test fixtures and synthetic data
```

## Examples

The [example/](example/) directory contains runnable programs demonstrating common use cases:

- **loadcert**: Load a TQ6 file and display station information
- **signdata**: Sign data using a PKCS#12 certificate
- **verifycert**: Verify certificate chains with different expiry policies

```bash
# Run an example
go run ./example/loadcert /path/to/certificate.tq6
```

See [example/README.md](example/README.md) for detailed instructions.

## Documentation

API documentation is available at:

- **[radiolabme.github.io/hamsign](https://radiolabme.github.io/hamsign/)** — Full API reference (GitHub Pages)
- **[pkg.go.dev/github.com/radiolabme/hamsign](https://pkg.go.dev/github.com/radiolabme/hamsign)** — Go package index

To serve documentation locally:

```bash
make docs
# Opens at http://localhost:8080/github.com/radiolabme/hamsign
```

## Development

### Prerequisites

- Go 1.21 or later
- Docker (optional, for containerized builds)
- [golangci-lint](https://golangci-lint.run/) (for linting)

### Makefile Targets

```bash
make test           # Run unit tests
make test-coverage  # Run tests with coverage report
make test-integration # Run integration tests (requires local testdata)
make lint           # Run golangci-lint
make vet            # Run go vet
make fmt            # Format code with gofmt
make build          # Build for current platform
make build-all      # Cross-compile for all platforms
make ci             # Run full CI pipeline locally
make install-hooks  # Install git hooks
```

### Docker Development

```bash
make docker-build   # Build Docker images
make docker-test    # Run tests in Docker
make docker-ci      # Run CI pipeline in Docker
```

### Git Hooks

Pre-commit and pre-push hooks ensure code quality:

```bash
make install-hooks
```

Pre-commit checks formatting, runs `go vet`, and executes short tests. Pre-push runs the full CI pipeline.

### Testing

```bash
# Run unit tests
go test ./...

# Run integration tests with real certificates (requires local testdata)
go test -tags=integration ./...

# View test coverage
go test -cover ./...
```

### CI/CD

GitHub Actions runs on every push and pull request:
- Matrix testing across Go 1.21/1.22 and Linux/macOS/Windows
- golangci-lint static analysis
- Cross-compilation for 6 platform targets

Releases are automated via GoReleaser when tags are pushed.

## License

This project is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE) for details.

The project incorporates work based on the Trusted QSL specifications, which are licensed under a BSD-style license by the ARRL and Darryl Wagoner WA1GON. The original specifications required specific attribution, which is preserved in accordance with the terms of that license.

## Dependencies

- [software.sslmate.com/src/go-pkcs12](https://github.com/SSLMate/go-pkcs12) - BSD 3-Clause License
- [golang.org/x/crypto](https://github.com/golang/crypto) - BSD 3-Clause License

## Contributing

Contributions are welcome! Please ensure:

- All tests pass (`go test ./...`)
- Code follows `gofmt` style
- New features include tests and documentation
- Commit messages clearly describe changes

## Acknowledgments

- **ARRL** and **Darryl Wagoner WA1GON** for the original Trusted QSL specifications and reference implementation
- **Rick Murphy** and the Trusted QSL Group for early documentation and protocol design
- The amateur radio community for decades of experimentation with digital authentication

## Security Considerations

This library implements RSA-SHA1 signatures for compatibility with existing TQSL infrastructure. SHA-1 is cryptographically weak and should not be used for new protocol designs. However, in the context of amateur radio QSO verification, where the threat model involves primarily preventing accidental or casual misrepresentation rather than defending against determined attackers, this remains acceptable for backward compatibility.

For new applications not requiring TQSL compatibility, consider using modern signature algorithms like Ed25519 or RSA-PSS with SHA-256 or stronger.

## Contact

For questions or issues, please open a GitHub issue or contact the maintainers.