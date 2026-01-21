// Example: loadcert demonstrates loading and inspecting amateur radio certificates.
//
// This example shows how to:
//   - Load certificates from TQ6 files (TQSL certificate export format)
//   - Extract amateur radio-specific information using hamcert
//   - Display certificate validity and QSO date ranges
//
// TQ6 files are the standard export format from TQSL (TrustedQSL) and contain
// X.509 certificates with custom extensions for amateur radio operations.
//
// Usage:
//
//	go run main.go <path-to-tq6-file>
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/radiolabme/hamsign"
	"github.com/radiolabme/hamsign/hamcert"
)

// Build-time variables set via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <tq6-file>\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "\nLoads a TQ6 certificate file and displays station information.")
	fmt.Fprintln(os.Stderr, "\nTQ6 files can be exported from TQSL via:")
	fmt.Fprintln(os.Stderr, "  Callsign Certificates → Right-click → Save Callsign Certificate File")
}

func main() {
	// Handle version flags
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("loadcert %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Handle help flags
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		printUsage()
		os.Exit(0)
	}

	// Verify command line arguments
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	filename := os.Args[1]

	// Read the TQ6 file from disk.
	// TQ6 files may be gzip-compressed or plain text.
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Parse the TQ6 file.
	// hamsign.LoadTQ6 handles both compressed and uncompressed formats,
	// as well as XML-embedded certificates and raw PEM certificates.
	certs, err := hamsign.LoadTQ6(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing TQ6: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d certificate(s) in %s\n\n", len(certs), filename)

	// Process each certificate found in the file.
	// TQ6 files may contain multiple certificates (e.g., user cert + CA certs).
	for i, cert := range certs {
		fmt.Printf("=== Certificate %d ===\n", i+1)

		// Display basic X.509 certificate information.
		fmt.Printf("Subject:      %s\n", cert.Subject.CommonName)
		fmt.Printf("Serial:       %s\n", cert.SerialNumber.String())
		fmt.Printf("Issuer:       %s\n", cert.Issuer.CommonName)
		fmt.Printf("Valid From:   %s\n", cert.NotBefore.Format(time.RFC3339))
		fmt.Printf("Valid Until:  %s\n", cert.NotAfter.Format(time.RFC3339))

		// Check if the certificate is currently valid.
		if hamsign.IsExpired(cert) {
			fmt.Println("Status:       EXPIRED")
		} else {
			fmt.Println("Status:       Valid")
		}

		// Extract amateur radio-specific extensions using hamcert.
		// These extensions contain callsign, DXCC entity, and QSO date ranges.
		info, err := hamcert.ParseStationInfo(cert)
		if err != nil {
			// Not all certificates in a TQ6 have amateur radio extensions.
			// CA certificates, for example, will not have a callsign.
			fmt.Printf("Note:         No amateur radio extensions (may be a CA cert)\n")
			fmt.Println()
			continue
		}

		// Display amateur radio-specific information.
		fmt.Println("\nAmateur Radio Information:")
		fmt.Printf("  Callsign:     %s\n", info.Callsign)
		if info.OperatorName != "" {
			fmt.Printf("  Operator:     %s\n", info.OperatorName)
		}
		if info.Email != "" {
			fmt.Printf("  Email:        %s\n", info.Email)
		}
		if info.DXCC > 0 {
			fmt.Printf("  DXCC Entity:  %d\n", info.DXCC)
		}

		// Display QSO date range if specified.
		// QSO date ranges limit when contacts can be signed with this certificate.
		if !info.QSONotBefore.IsZero() || !info.QSONotAfter.IsZero() {
			fmt.Println("\nQSO Date Range:")
			if !info.QSONotBefore.IsZero() {
				fmt.Printf("  Not Before:   %s\n", info.QSONotBefore.Format("2006-01-02"))
			}
			if !info.QSONotAfter.IsZero() {
				fmt.Printf("  Not After:    %s\n", info.QSONotAfter.Format("2006-01-02"))
			}

			// Check if today's date falls within the QSO date range.
			if hamsign.QSODateRangeValid(cert, time.Now()) {
				fmt.Println("  Current QSOs: Can be signed")
			} else {
				fmt.Println("  Current QSOs: OUTSIDE valid range")
			}
		}

		// Attempt to extract request address information.
		// This is typically only present in user certificates.
		addr, err := hamcert.ParseRequestAddress(cert)
		if err == nil && addr.City != "" {
			fmt.Println("\nRegistered Address:")
			if addr.Address1 != "" {
				fmt.Printf("  Address:      %s\n", addr.Address1)
			}
			if addr.Address2 != "" {
				fmt.Printf("                %s\n", addr.Address2)
			}
			if addr.City != "" || addr.State != "" || addr.PostalCode != "" {
				fmt.Printf("  Location:     %s, %s %s\n", addr.City, addr.State, addr.PostalCode)
			}
			if addr.Country != "" {
				fmt.Printf("  Country:      %s\n", addr.Country)
			}
		}

		fmt.Println()
	}
}
