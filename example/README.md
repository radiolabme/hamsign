# hamsign Examples

This directory contains example programs demonstrating how to use the hamsign library.

## Prerequisites

Before running these examples, you'll need:

1. **Go 1.21 or later** installed
2. **TQSL certificate files** exported from the [TrustedQSL](https://lotw.arrl.org/lotw-help/installation/) application

### Exporting Certificates from TQSL

To export your certificates for use with these examples:

**TQ6 file (certificate without private key):**
1. Open TQSL
2. Go to "Callsign Certificates"
3. Right-click your certificate
4. Select "Save Callsign Certificate File..."
5. Save with `.tq6` extension

**P12 file (certificate with private key):**
1. Open TQSL
2. Go to "Callsign Certificates"
3. Right-click your certificate
4. Select "Save Key File..."
5. Enter a password when prompted
6. Save with `.p12` extension

⚠️ **Security Note:** P12 files contain your private key. Keep them secure and never share them.

## Examples

### loadcert - Certificate Inspection

Loads a TQ6 certificate file and displays information including callsign, DXCC entity, and QSO date ranges.

```bash
cd loadcert
go run main.go /path/to/your/certificate.tq6
```

Example output:
```
Found 1 certificate(s) in certificate.tq6

=== Certificate 1 ===
Subject:      John Smith
Serial:       12345
Issuer:       ARRL Intermediate CA
Valid From:   2020-01-15T00:00:00Z
Valid Until:  2025-01-15T23:59:59Z
Status:       Valid

Amateur Radio Information:
  Callsign:     W1ABC
  Operator:     John Smith
  DXCC Entity:  291

QSO Date Range:
  Not Before:   2020-01-15
  Not After:    2025-01-15
  Current QSOs: Can be signed
```

### signdata - Digital Signing

Demonstrates loading a PKCS#12 file and signing data with your amateur radio certificate.

```bash
cd signdata
go run main.go /path/to/your/certificate.p12 "your-password"
```

⚠️ **Note:** Passing passwords on the command line is insecure. This is for demonstration only.

Example output:
```
Loaded certificate for: John Smith
Callsign: W1ABC

Verifying certificate chain...
Chain verification: OK

Signing data: "W1AW de K1ABC 14.070 MHz FT8 -10dB 2024-01-15 14:30:00"
Signature (base64): MEUCIQD...

Verifying signature...
Signature verification: OK

Verifying against tampered data: "W1AW de K1ABC 14.070 MHz FT8 -05dB 2024-01-15 14:30:00"
Signature verification: FAILED (as expected)
```

### verifycert - Chain Verification

Demonstrates different certificate chain verification strategies.

```bash
cd verifycert
go run main.go /path/to/your/certificate.tq6
```

This example shows three verification modes:
- **Strict:** All certificates must be currently valid
- **Ignore CA expiry:** Allows expired CA certificates (TQSL compatibility)
- **Ignore all expiry:** For historical verification

## Running from Module Root

You can also run examples directly from the repository root:

```bash
go run ./example/loadcert /path/to/cert.tq6
go run ./example/signdata /path/to/cert.p12 password
go run ./example/verifycert /path/to/cert.tq6
```

## Building Examples

To build standalone binaries:

```bash
# Build all examples
go build -o bin/loadcert ./example/loadcert
go build -o bin/signdata ./example/signdata  
go build -o bin/verifycert ./example/verifycert

# Or use the Makefile
make build
```

## Using in Your Own Code

These examples demonstrate common patterns for using hamsign. For library usage:

```go
import (
    "github.com/radiolabme/hamsign"
    "github.com/radiolabme/hamsign/hamcert"
)

// Load certificates
certs, _ := hamsign.LoadTQ6(data)

// Parse amateur radio info
info, _ := hamcert.ParseStationInfo(certs[0])
fmt.Println(info.Callsign)

// Create signer from PKCS#12
cert, key, _ := hamsign.LoadPKCS12(p12Data, password)
signer, _ := hamsign.NewSigner(cert, key, nil)

// Sign data
signature, _ := signer.Sign([]byte("data"))
```

## License

See the repository [LICENSE](../LICENSE) file.
