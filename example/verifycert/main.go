// Example: verifycert demonstrates certificate chain verification.
//
// This example shows how to:
//   - Verify a certificate against the embedded CA certificates
//   - Use custom CA certificates for verification
//   - Handle different expiry policies
//
// Certificate chain verification ensures that a user certificate was issued
// by a trusted Certificate Authority (CA) and has not been tampered with.
//
// Usage:
//
//	go run main.go <path-to-tq6-file>
package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/radiolabme/hamsign"
)

// Build-time variables set via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <tq6-file>\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "\nVerifies certificate chains from a TQ6 file.")
}

func main() {
	// Handle version flags
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("verifycert %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Handle help flags
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		printUsage()
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	filename := os.Args[1]

	// Load the TQ6 file.
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	certs, err := hamsign.LoadTQ6(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing TQ6: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d certificate(s)\n\n", len(certs))

	// Get the default root and intermediate CA pools.
	// These are embedded in the hamsign package.
	roots := hamsign.DefaultRoots()
	intermediates := hamsign.DefaultIntermediates()

	// Verify each certificate.
	for i, cert := range certs {
		fmt.Printf("=== Certificate %d: %s ===\n", i+1, cert.Subject.CommonName)

		// Try to extract amateur radio info to identify the cert type.
		info, _ := hamsign.ParseStationInfo(cert)
		if info != nil {
			fmt.Printf("Callsign: %s\n", info.Callsign)
		}

		// Check basic validity period.
		fmt.Printf("Valid: %s to %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))

		if hamsign.IsExpired(cert) {
			fmt.Println("Status: EXPIRED")
		} else {
			daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
			fmt.Printf("Status: Valid (%d days remaining)\n", daysRemaining)
		}

		// Demonstrate different verification strategies.
		fmt.Println("\nVerification Results:")

		// 1. Strict verification (all certificates must be valid).
		fmt.Print("  Strict mode:          ")
		verifyStrict(cert, roots, intermediates)

		// 2. Ignore CA expiry (default for TQSL compatibility).
		fmt.Print("  Ignore CA expiry:     ")
		verifyIgnoreCAExpiry(cert, roots, intermediates)

		// 3. Ignore all expiry.
		fmt.Print("  Ignore all expiry:    ")
		verifyIgnoreAllExpiry(cert, roots, intermediates)

		fmt.Println()
	}
}

// verifyStrict performs strict chain verification.
// All certificates in the chain must be currently valid.
func verifyStrict(cert *x509.Certificate, roots, intermediates *x509.CertPool) {
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// No CurrentTime override - uses system time
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		fmt.Printf("FAILED - %v\n", err)
		return
	}

	fmt.Printf("OK (chain length: %d)\n", len(chains[0]))
}

// verifyIgnoreCAExpiry ignores expiration on CA certificates.
// This is useful when CA certificates have expired but user certificates are valid.
func verifyIgnoreCAExpiry(cert *x509.Certificate, roots, intermediates *x509.CertPool) {
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// Set time to certificate validity period to bypass CA expiry checks
		CurrentTime: cert.NotBefore.Add(time.Hour),
	}

	_, err := cert.Verify(opts)
	if err != nil {
		fmt.Printf("FAILED - %v\n", err)
		return
	}

	// Still check if the user certificate itself is expired.
	if hamsign.IsExpired(cert) {
		fmt.Println("OK (chain valid, but user cert expired)")
		return
	}

	fmt.Println("OK")
}

// verifyIgnoreAllExpiry ignores expiration on all certificates.
// This is useful for historical verification or archive purposes.
func verifyIgnoreAllExpiry(cert *x509.Certificate, roots, intermediates *x509.CertPool) {
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// Set time to certificate validity period
		CurrentTime: cert.NotBefore.Add(time.Hour),
	}

	_, err := cert.Verify(opts)
	if err != nil {
		fmt.Printf("FAILED - %v\n", err)
		return
	}

	fmt.Println("OK")
}
