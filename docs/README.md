# API Documentation

This project uses [pkgsite](https://pkg.go.dev/golang.org/x/pkgsite) to generate API documentation in the same style as pkg.go.dev.

## Viewing Documentation

### Online

Documentation is published automatically on every push to `main`:

- **GitHub Pages**: https://radiolabme.github.io/hamsign/
- **pkg.go.dev**: https://pkg.go.dev/github.com/radiolabme/hamsign

Sub-packages:
- https://pkg.go.dev/github.com/radiolabme/hamsign/hamcert

### Locally

```bash
# Serve documentation at http://localhost:8080
make docs

# Or manually:
go install golang.org/x/pkgsite/cmd/pkgsite@latest
pkgsite -http=localhost:8080 .
```

Then visit: http://localhost:8080/github.com/radiolabme/hamsign

## Writing Documentation

Documentation is generated from Go source comments using [godoc conventions](https://go.dev/blog/godoc):

```go
// Package hamsign provides digital signing for amateur radio certificates.
//
// This paragraph describes the package in more detail.
// Multiple lines are joined.
//
// A blank line starts a new paragraph.
package hamsign

// LoadPKCS12 loads a certificate and private key from PKCS#12 data.
// If the PKCS#12 file contains CA certificates, they are ignored.
//
// Example:
//
//	cert, key, err := hamsign.LoadPKCS12(data, "password")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadPKCS12(data []byte, password string) (*x509.Certificate, crypto.PrivateKey, error) {
```

### Key conventions

- First sentence becomes the synopsis (keep it short)
- Package comment goes in the file with `package name`
- Use `//` comments, not `/* */`
- Indent code examples with a tab
- Reference other symbols with `[SymbolName]` (Go 1.19+)

## Static Site Generation

The documentation is automatically published to GitHub Pages on every push to `main` via the `.github/workflows/docs.yml` workflow.

To generate locally:

```bash
make docs-build
# Output in docs/site/
```

Note: Static generation requires `wget` and works best on Linux/macOS.
