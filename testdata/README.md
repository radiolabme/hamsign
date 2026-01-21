# Test Data

This directory contains test data for the hamsign library.

## Directory Structure

```
testdata/
├── synthetic/      # Generated test files (committed to git)
│   ├── generate.go # Generator program (build ignored)
│   ├── README.md   # Documentation for synthetic files
│   └── *.pem, *.p12, *.tq6, *.tq8  # Generated test files
├── 2025/           # Personal test data (gitignored)
├── 2026/           # Personal test data (gitignored)
└── README.md       # This file
```

## Synthetic Test Data

The `synthetic/` directory contains programmatically generated test certificates
and files. These files:

- Do NOT contain any real personal information
- Use fake callsigns (N0CALL, W1TEST, etc.)
- Use sample addresses (123 Main St, Anytown, NY 12345)
- Use example.com email addresses
- Are committed to version control

To regenerate synthetic files:

```bash
cd testdata/synthetic
go run generate.go
```

## Personal Test Data (Integration Tests)

The `2025/` and `2026/` directories are gitignored and should contain real TQSL
certificate exports for integration testing. These are used by tests in
`integration_test.go` which require the `integration` build tag:

```bash
go test -tags=integration ./...
```

Integration tests will skip gracefully if personal testdata is not present.

## Test File Organization

| Test File | Package | Data Source | Purpose |
|-----------|---------|-------------|---------|
| `hamsign_test.go` | hamsign | In-memory generated | Unit tests for core signing |
| `synthetic_test.go` | hamsign | In-memory generated | Unit tests with ham extensions |
| `testdata_test.go` | hamsign | `testdata/synthetic/` | Tests using file-based synthetic data |
| `integration_test.go` | hamsign | `testdata/2025/, 2026/` | Integration tests with real certs |
| `hamcert/hamcert_test.go` | hamcert | In-memory generated | Unit tests for certificate parsing |

## Build Tags

- **No tag**: Runs unit tests with synthetic/in-memory data
- **`integration`**: Also runs integration tests requiring personal testdata

```bash
# Run only unit tests (CI-safe)
go test ./...

# Run all tests including integration
go test -tags=integration ./...
```
