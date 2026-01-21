# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-21

### Added

- Core signing functionality with `NewSigner`, `Sign`, and `Verify`
- PKCS#12 and PEM certificate/key loading via `LoadPKCS12` and `LoadPEM`
- TQ6 certificate file parsing with gzip and XML support via `LoadTQ6`
- TQ8 certificate request parsing via `LoadTQ8`
- Certificate request generation via `GenerateRequest`
- PKCS#12 export via `ExportPKCS12`
- Certificate chain verification with configurable expiry policies:
  - `ExpiryPolicyStrict` - all certificates must be valid
  - `ExpiryPolicyIgnoreCA` - ignore CA expiry (default, for TQSL compatibility)
  - `ExpiryPolicyIgnoreAll` - ignore all expiry (for historical records)
- Embedded root and intermediate CA certificates with `DefaultRoots` and `DefaultIntermediates`
- QSO date range validation via `QSODateRangeValid`
- `hamcert` sub-package for standalone certificate parsing:
  - `ParseStationInfo` - extract callsign, operator, DXCC, QSO date range
  - `ParseRequestAddress` - extract address information
- Example CLI tools:
  - `loadcert` - load and inspect TQ6 certificate files
  - `signdata` - sign data using PKCS#12 certificates
  - `verifycert` - verify certificate chains
- Cross-platform builds for Linux, macOS, Windows (amd64, arm64)
- Raspberry Pi support (ARMv6, ARMv7)
- GitHub Actions CI with matrix testing
- API documentation via pkgsite (GitHub Pages)

### Notes

- Uses RSA-SHA1 for compatibility with existing TQSL infrastructure
- Pure Go implementation with no CGO dependencies
- Distribution-agnostic Linux binaries (works on Alpine, Debian, etc.)

[Unreleased]: https://github.com/radiolabme/hamsign/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/radiolabme/hamsign/releases/tag/v0.1.0
