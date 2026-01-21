# Synthetic Test Data

This directory contains synthetic test certificates and files for testing the hamsign library. These files are generated programmatically and do not contain any real personal information.

## TQSL File Formats

| Extension | Name | Description | Covered |
|-----------|------|-------------|---------|
| `.pem` | PEM Certificate | Standard X.509 certificate in PEM format | ✓ |
| `.p12` | PKCS#12 | Certificate + private key bundle | ✓ |
| `.tq6` | User Certificate | TQSL user certificate file (PEM, XML, or gzip) | ✓ |
| `.tq5` | Station Location | Station location data for GABBI (not certificate-related) | N/A |
| `.tq8` | Certificate Request | PKCS#10 CSR for certificate signing (via `LoadTQ8`) | ✓ |

## Regenerating Files

To regenerate all test files:

```bash
go run generate.go
```

## File Descriptions

### Valid Certificates

| File | Description | Expected Outcome |
|------|-------------|------------------|
| `valid_cert.pem` | Valid certificate with callsign W1TEST, DXCC 291, QSO dates 2020-2030 | Should load successfully, parse station info |
| `valid_key.pem` | Matching private key for valid_cert.pem | Should load and work for signing |
| `full_ham_cert.pem` | Certificate with all ham radio extensions (callsign, DXCC, QSO dates, email, address) | Should parse all StationInfo and RequestAddress fields |
| `full_ham_key.pem` | Matching private key for full_ham_cert.pem | Should load and work for signing |

### Expired Certificates

| File | Description | Expected Outcome |
|------|-------------|------------------|
| `expired_cert.pem` | Certificate that expired 1 year ago (callsign W1EXPIRED) | `IsExpired()` returns true, `VerifyChain()` fails with ExpiryPolicyStrict |
| `expired_key.pem` | Matching private key for expired_cert.pem | Should still work for signing (expiry doesn't affect signing) |

### PKCS#12 Files

| File | Password | Description | Expected Outcome |
|------|----------|-------------|------------------|
| `with_password.p12` | `testpassword` | PKCS#12 with password protection | `LoadPKCS12` succeeds with correct password, fails with wrong password |
| `no_password.p12` | (empty string) | PKCS#12 without password | `LoadPKCS12` succeeds with empty string password |

### TQ6 Files

| File | Format | Description | Expected Outcome |
|------|--------|-------------|------------------|
| `raw_pem.tq6` | Raw PEM | Plain concatenated PEM certificate | `LoadTQ6` extracts 1 certificate |
| `xml_embedded.tq6` | XML + PEM | PEM certificate embedded in XML tags | `LoadTQ6` extracts 1 certificate |
| `gzip_compressed.tq6` | Gzip + PEM | Gzip-compressed PEM certificate | `LoadTQ6` decompresses and extracts 1 certificate |
| `gzip_xml.tq6` | Gzip + XML + PEM | Gzip-compressed XML with embedded PEM | `LoadTQ6` decompresses, parses XML, extracts 1 certificate |

### Multi-Certificate Files

| File | Description | Expected Outcome |
|------|-------------|------------------|
| `multi_cert.pem` | Three certificates (W1AA, W2BB, K3CC) concatenated | Should parse all 3 certificates, each with different callsign |

### TQ8 Certificate Request Files

| File | Format | Description | Expected Outcome |
|------|--------|-------------|------------------|
| `cert_request.tq8` | Raw PEM | PKCS#10 Certificate Signing Request | `LoadTQ8` extracts CSR |
| `cert_request_xml.tq8` | XML + PEM | CSR embedded in XML tags | `LoadTQ8` extracts CSR from XML |
| `cert_request_gzip.tq8` | Gzip + PEM | Gzip-compressed CSR | `LoadTQ8` decompresses and extracts CSR |
| `cert_request_key.pem` | PEM | Private key for the CSR | Use with CSR for testing |

### Invalid/Error Test Files

| File | Description | Expected Outcome |
|------|-------------|------------------|
| `invalid_not_pem.pem` | Plain text, not PEM format | `LoadPEM` returns error "failed to decode certificate PEM" |
| `invalid_corrupted_cert.pem` | PEM format but corrupted certificate data | `LoadPEM` returns error "failed to parse certificate" |
| `invalid_corrupted_key.pem` | PEM format but corrupted key data | `LoadPEM` returns error "failed to parse private key" |
| `no_certs.tq6` | XML with no PEM certificates | `LoadTQ6` returns error "no certificates found" |
| `corrupted_gzip.tq6` | Gzip magic bytes but corrupted data | `LoadTQ6` returns gzip decompression error |
| `empty.pem` | Empty file (0 bytes) | `LoadPEM` returns error "failed to decode certificate PEM" |

## Certificate Details

### Station Information (StationInfo)

All valid certificates contain:
- **Callsign**: Stored in extension OID 1.3.6.1.4.1.12348.1.1
- **Operator Name**: Stored in Subject CN
- **DXCC Entity**: Stored in extension OID 1.3.6.1.4.1.12348.1.4 (291 = USA)
- **QSO Not Before**: Stored in extension OID 1.3.6.1.4.1.12348.1.2
- **QSO Not After**: Stored in extension OID 1.3.6.1.4.1.12348.1.3

### Request Address (full_ham_cert.pem only)

Uses generic USPS-style sample address data (not real):

- **Callsign**: N0CALL
- **Operator Name**: JANE Q HAMOPERATOR
- **Address1**: OID 1.3.6.1.4.1.12348.1.9 = "123 Main St"
- **City**: OID 1.3.6.1.4.1.12348.1.11 = "Anytown"
- **State**: OID 1.3.6.1.4.1.12348.1.12 = "NY"
- **PostalCode**: OID 1.3.6.1.4.1.12348.1.13 = "12345"
- **Country**: OID 1.3.6.1.4.1.12348.1.14 = "USA"
- **Email**: OID 1.3.6.1.4.1.12348.1.8 = "ham@example.com"

## Usage in Tests

```go
// Load a valid certificate
certData, _ := os.ReadFile("testdata/synthetic/valid_cert.pem")
keyData, _ := os.ReadFile("testdata/synthetic/valid_key.pem")
cert, key, err := hamsign.LoadPEM(certData, keyData)

// Test error handling
invalidData, _ := os.ReadFile("testdata/synthetic/invalid_not_pem.pem")
_, _, err := hamsign.LoadPEM(invalidData, keyData)
// err should be non-nil

// Test PKCS12 with password
p12Data, _ := os.ReadFile("testdata/synthetic/with_password.p12")
cert, key, err := hamsign.LoadPKCS12(p12Data, "testpassword")

// Test TQ6 loading
tq6Data, _ := os.ReadFile("testdata/synthetic/gzip_compressed.tq6")
certs, err := hamsign.LoadTQ6(tq6Data)
```
