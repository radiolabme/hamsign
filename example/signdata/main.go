// Example: signdata demonstrates digital signing with amateur radio certificates.
//
// This example shows how to:
//   - Load a PKCS#12 certificate file (.p12)
//   - Create a signer with certificate chain validation
//   - Sign arbitrary data
//   - Verify signatures
//
// PKCS#12 files can be exported from TQSL and contain both the certificate
// and private key needed for signing.
//
// Usage:
//
//	go run main.go <path-to-p12-file> <password>
//
// WARNING: This example accepts a password on the command line for simplicity.
// In production, use secure password input methods.
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/radiolabme/hamsign"
)

func main() {
	// Verify command line arguments.
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <p12-file> <password>\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "\nLoads a PKCS#12 file and demonstrates signing operations.")
		fmt.Fprintln(os.Stderr, "\nTo export a P12 file from TQSL:")
		fmt.Fprintln(os.Stderr, "  Callsign Certificates → Right-click → Save Key File")
		os.Exit(1)
	}

	filename := os.Args[1]
	password := os.Args[2]

	// Read the PKCS#12 file.
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Load the certificate and private key from PKCS#12 format.
	// The password protects the private key within the file.
	cert, key, err := hamsign.LoadPKCS12(data, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading PKCS#12: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded certificate for: %s\n", cert.Subject.CommonName)

	// Extract callsign from the certificate.
	info, err := hamsign.ParseStationInfo(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not parse station info: %v\n", err)
	} else {
		fmt.Printf("Callsign: %s\n", info.Callsign)
	}

	// Create a signer with the loaded certificate and key.
	// Passing nil for options uses the embedded CA certificates
	// and default expiry policy (ExpiryPolicyIgnoreCA).
	signer, err := hamsign.NewSigner(cert, key, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating signer: %v\n", err)
		os.Exit(1)
	}

	// Verify the certificate chain.
	// This ensures the certificate chains to a trusted root CA.
	fmt.Println("\nVerifying certificate chain...")
	if err := signer.VerifyChain(); err != nil {
		fmt.Printf("Chain verification: FAILED - %v\n", err)
		// Note: We continue anyway for demonstration purposes.
		// In production, you might want to exit here.
	} else {
		fmt.Println("Chain verification: OK")
	}

	// Sign some example data.
	// In a real application, this would be a QSO record.
	exampleData := []byte("W1AW de K1ABC 14.070 MHz FT8 -10dB 2024-01-15 14:30:00")
	fmt.Printf("\nSigning data: %q\n", string(exampleData))

	signature, err := signer.Sign(exampleData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
		os.Exit(1)
	}

	// Display the signature in base64 format.
	// Signatures are typically encoded for transmission.
	sigBase64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("Signature (base64): %s\n", sigBase64)

	// Verify the signature.
	// This demonstrates the verification process using the same signer.
	fmt.Println("\nVerifying signature...")
	if err := signer.Verify(exampleData, signature); err != nil {
		fmt.Printf("Signature verification: FAILED - %v\n", err)
	} else {
		fmt.Println("Signature verification: OK")
	}

	// Demonstrate that tampering is detected.
	tamperedData := []byte("W1AW de K1ABC 14.070 MHz FT8 -05dB 2024-01-15 14:30:00")
	fmt.Printf("\nVerifying against tampered data: %q\n", string(tamperedData))
	if err := signer.Verify(tamperedData, signature); err != nil {
		fmt.Println("Signature verification: FAILED (as expected)")
	} else {
		fmt.Println("Signature verification: OK (unexpected!)")
	}
}
