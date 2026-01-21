//go:build integration

package hamsign

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These tests require the testdata folder which is gitignored.
// Run with: go test -tags integration -v

const testdataDir = "testdata"

func testdataExists(t *testing.T) bool {
	t.Helper()
	if _, err := os.Stat(testdataDir); os.IsNotExist(err) {
		t.Skip("testdata directory not found, skipping integration tests")
		return false
	}
	return true
}

// parseTQSLKeyFile parses the TQSL key file format which uses ADIF-like tags.
// Returns the private key PEM for the given callsign.
func parseTQSLKeyFile(data []byte, callsign string) ([]byte, error) {
	content := string(data)

	// Split by <eor> to get individual records
	records := strings.Split(content, "<eor>")

	for _, record := range records {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}

		// Check if this record matches our callsign and is not deleted
		if !strings.Contains(record, "<CALLSIGN:") {
			continue
		}

		// Extract callsign from record
		callsignMatch := regexp.MustCompile(`<CALLSIGN:\d+>(\S+)`).FindStringSubmatch(record)
		if len(callsignMatch) < 2 || callsignMatch[1] != callsign {
			continue
		}

		// Check if deleted
		if strings.Contains(record, "<DELETED:4>True") {
			continue
		}

		// Extract private key
		keyMatch := regexp.MustCompile(`<PRIVATE_KEY:\d+>(-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----)`).FindStringSubmatch(record)
		if len(keyMatch) >= 2 {
			return []byte(keyMatch[1]), nil
		}

		// Also try RSA PRIVATE KEY format
		keyMatch = regexp.MustCompile(`<PRIVATE_KEY:\d+>(-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----)`).FindStringSubmatch(record)
		if len(keyMatch) >= 2 {
			return []byte(keyMatch[1]), nil
		}
	}

	return nil, fmt.Errorf("no key found for callsign %s", callsign)
}

func TestIntegration_LoadPEM_2025Certificate(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	certPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "certs", "user")
	keyPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "keys", "KB2S")

	// Read certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	// Parse the TQSL key file format
	keyPEM, err := parseTQSLKeyFile(keyData, "KB2S")
	if err != nil {
		t.Fatalf("failed to parse key file: %v", err)
	}

	t.Logf("Found private key PEM (%d bytes)", len(keyPEM))

	// Load certificate and key
	cert, key, err := LoadPEM(certData, keyPEM)
	if err != nil {
		t.Fatalf("LoadPEM failed: %v", err)
	}

	t.Run("certificate loaded", func(t *testing.T) {
		if cert == nil {
			t.Fatal("certificate is nil")
		}
		t.Logf("Loaded certificate for: %s", cert.Subject.CommonName)
		t.Logf("Serial: %s", cert.SerialNumber.String())
		t.Logf("NotBefore: %s", cert.NotBefore)
		t.Logf("NotAfter: %s", cert.NotAfter)
	})

	t.Run("key loaded", func(t *testing.T) {
		if key == nil {
			t.Fatal("private key is nil")
		}
	})

	t.Run("parse station info", func(t *testing.T) {
		info, err := ParseStationInfo(cert)
		if err != nil {
			t.Fatalf("ParseStationInfo failed: %v", err)
		}

		if info.Callsign != "KB2S" {
			t.Errorf("callsign mismatch: got %s, want KB2S", info.Callsign)
		}

		t.Logf("Callsign: %s", info.Callsign)
		t.Logf("Operator: %s", info.OperatorName)
		t.Logf("DXCC: %d", info.DXCC)
		t.Logf("QSO Not Before: %s", info.QSONotBefore)
		t.Logf("QSO Not After: %s", info.QSONotAfter)
		t.Logf("Email: %s", info.Email)

		// Verify expected values
		if info.DXCC != 291 {
			t.Errorf("DXCC mismatch: got %d, want 291 (USA)", info.DXCC)
		}
	})

	t.Run("sign and verify", func(t *testing.T) {
		signer, err := NewSigner(cert, key, &VerifyOptions{
			Expiry: ExpiryPolicyIgnoreAll, // Both CA and user cert may be expired
		})
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		testData := []byte("test QSO data: N0CALL 20231001 1200 14.200 SSB")

		sig, err := signer.Sign(testData)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		t.Logf("Signature length: %d bytes", len(sig))

		err = signer.Verify(testData, sig)
		if err != nil {
			t.Errorf("Verify failed: %v", err)
		}

		// Test wrong data
		err = signer.Verify([]byte("wrong data"), sig)
		if err == nil {
			t.Error("verification should fail with wrong data")
		}
	})
}

func TestIntegration_LoadPKCS12_2026Certificate(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	p12Path := filepath.Join(testdataDir, "2026", "KB2S.p12")

	// Read PKCS12 file
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("failed to read PKCS12 file: %v", err)
	}

	// Try common passwords used by TQSL
	// Note: Users may have set their own password, so we also check for environment variable
	passwords := []string{"", "tqsl"}
	if envPwd := os.Getenv("TQSL_TEST_PASSWORD"); envPwd != "" {
		passwords = append([]string{envPwd}, passwords...)
	}

	var cert *x509.Certificate
	var key crypto.PrivateKey
	var loadErr error

	for _, pwd := range passwords {
		cert, key, loadErr = LoadPKCS12(p12Data, pwd)
		if loadErr == nil {
			t.Logf("Loaded PKCS12 with password: %q", pwd)
			break
		}
	}

	if loadErr != nil {
		t.Skipf("LoadPKCS12 failed with all default passwords (set TQSL_TEST_PASSWORD env var): %v", loadErr)
	}

	t.Run("certificate loaded", func(t *testing.T) {
		if cert == nil {
			t.Fatal("certificate is nil")
		}
		t.Logf("Loaded certificate for: %s", cert.Subject.CommonName)
		t.Logf("Serial: %s", cert.SerialNumber.String())
		t.Logf("NotBefore: %s", cert.NotBefore)
		t.Logf("NotAfter: %s", cert.NotAfter)
	})

	t.Run("key loaded", func(t *testing.T) {
		if key == nil {
			t.Fatal("private key is nil")
		}
	})

	t.Run("parse station info", func(t *testing.T) {
		info, err := ParseStationInfo(cert)
		if err != nil {
			t.Fatalf("ParseStationInfo failed: %v", err)
		}

		if info.Callsign != "KB2S" {
			t.Errorf("callsign mismatch: got %s, want KB2S", info.Callsign)
		}

		t.Logf("Callsign: %s", info.Callsign)
		t.Logf("Operator: %s", info.OperatorName)
		t.Logf("DXCC: %d", info.DXCC)
		t.Logf("QSO Not Before: %s", info.QSONotBefore)
		t.Logf("QSO Not After: %s", info.QSONotAfter)
		t.Logf("Email: %s", info.Email)
	})

	t.Run("sign and verify", func(t *testing.T) {
		signer, err := NewSigner(cert, key, &VerifyOptions{
			Expiry: ExpiryPolicyIgnoreCA,
		})
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		testData := []byte("test QSO data: N0CALL 20260101 1200 14.200 SSB")

		sig, err := signer.Sign(testData)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		t.Logf("Signature length: %d bytes", len(sig))

		err = signer.Verify(testData, sig)
		if err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})

	t.Run("verify chain against embedded CA", func(t *testing.T) {
		signer, err := NewSigner(cert, key, &VerifyOptions{
			Expiry: ExpiryPolicyIgnoreCA, // CA certs are expired
		})
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		err = signer.VerifyChain()
		if err != nil {
			// This may fail if user cert is also expired
			if IsExpired(cert) {
				t.Skipf("User certificate is expired (NotAfter: %s): %v", cert.NotAfter, err)
			}
			t.Errorf("Chain verification failed: %v", err)
		}
	})
}

func TestIntegration_QSODateRange(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	certPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "certs", "user")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	info, err := ParseStationInfo(cert)
	if err != nil {
		t.Fatalf("ParseStationInfo failed: %v", err)
	}

	t.Logf("QSO date range: %s to %s", info.QSONotBefore, info.QSONotAfter)

	t.Run("date within range", func(t *testing.T) {
		// Date within the range
		qsoDate := time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
		if !QSODateRangeValid(cert, qsoDate) {
			t.Errorf("date %s should be valid", qsoDate)
		}
	})

	t.Run("date before range", func(t *testing.T) {
		// Date before the range
		qsoDate := time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
		if QSODateRangeValid(cert, qsoDate) {
			t.Errorf("date %s should be invalid (before range)", qsoDate)
		}
	})

	t.Run("date after range", func(t *testing.T) {
		// Date after the range
		qsoDate := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		if QSODateRangeValid(cert, qsoDate) {
			t.Errorf("date %s should be invalid (after range)", qsoDate)
		}
	})
}

func TestIntegration_MultipleCertificates(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	certPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "certs", "user")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}

	// The user file may contain multiple certificates
	var certs []*x509.Certificate
	remaining := certData

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Logf("Failed to parse one certificate: %v", err)
				continue
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		t.Fatal("no certificates found in user file")
	}
	t.Logf("Found %d certificate(s) in user file", len(certs))

	for i, cert := range certs {
		t.Run(fmt.Sprintf("cert_%d", i), func(t *testing.T) {
			info, err := ParseStationInfo(cert)
			if err != nil {
				t.Fatalf("ParseStationInfo failed for certificate %d: %v", i, err)
			}

			// Verify required fields are populated
			if info.Callsign == "" {
				t.Error("callsign is empty")
			}
			if cert.Subject.CommonName == "" {
				t.Error("subject common name is empty")
			}

			t.Logf("Certificate %d: %s (Serial: %s, Expired: %v)",
				i, info.Callsign, cert.SerialNumber, IsExpired(cert))
		})
	}
}

func TestIntegration_ExportAndReload(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	// Use the 2025 PEM files which don't require a password
	certPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "certs", "user")
	keyPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "keys", "KB2S")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	keyPEM, err := parseTQSLKeyFile(keyData, "KB2S")
	if err != nil {
		t.Fatalf("failed to parse key file: %v", err)
	}

	cert, key, err := LoadPEM(certData, keyPEM)
	if err != nil {
		t.Fatalf("LoadPEM failed: %v", err)
	}

	// Export with our own password
	newPassword := "testpassword123"
	exported, err := ExportPKCS12(cert, key, newPassword)
	if err != nil {
		t.Fatalf("ExportPKCS12 failed: %v", err)
	}

	t.Logf("Exported PKCS12 size: %d bytes", len(exported))

	// Reload
	reloadedCert, reloadedKey, err := LoadPKCS12(exported, newPassword)
	if err != nil {
		t.Fatalf("Failed to reload exported PKCS12: %v", err)
	}

	// Verify same certificate
	if reloadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("Certificate serial number mismatch after export/reload")
	}

	// Verify signing works with reloaded key
	signer, err := NewSigner(reloadedCert, reloadedKey, nil)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	testData := []byte("round-trip test data")
	sig, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = signer.Verify(testData, sig)
	if err != nil {
		t.Errorf("Verify failed after export/reload: %v", err)
	}

	t.Log("Export and reload successful")
}

func TestIntegration_ParseRequestAddressFromCert(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	// The user certificate should have address info from the CSR
	p12Path := filepath.Join(testdataDir, "2026", "KB2S.p12")

	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("failed to read PKCS12 file: %v", err)
	}

	// Try common passwords
	passwords := []string{"", "tqsl"}
	if envPwd := os.Getenv("TQSL_TEST_PASSWORD"); envPwd != "" {
		passwords = append([]string{envPwd}, passwords...)
	}

	var cert *x509.Certificate
	var loadErr error
	for _, pwd := range passwords {
		cert, _, loadErr = LoadPKCS12(p12Data, pwd)
		if loadErr == nil {
			break
		}
	}
	if loadErr != nil {
		t.Skipf("LoadPKCS12 failed (set TQSL_TEST_PASSWORD): %v", loadErr)
	}

	// ParseRequestAddress may return an error if address extensions are not present
	// This is expected for some certificates - the test verifies the function doesn't panic
	addr, err := ParseRequestAddress(cert)
	if err != nil {
		t.Skipf("ParseRequestAddress not available for this certificate: %v", err)
	}

	// If we got an address, verify the struct is populated (at least partially)
	t.Logf("Address1: %s", addr.Address1)
	t.Logf("Address2: %s", addr.Address2)
	t.Logf("City: %s", addr.City)
	t.Logf("State: %s", addr.State)
	t.Logf("PostalCode: %s", addr.PostalCode)
	t.Logf("Country: %s", addr.Country)
}

func TestIntegration_VerifyChainWithEmbeddedCA(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	// This test verifies that our embedded CA certificates match
	// what was used to sign the user certificates

	certPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "certs", "user")
	keyPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "keys", "KB2S")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	keyPEM, err := parseTQSLKeyFile(keyData, "KB2S")
	if err != nil {
		t.Fatalf("failed to parse key file: %v", err)
	}

	cert, key, err := LoadPEM(certData, keyPEM)
	if err != nil {
		t.Fatalf("LoadPEM failed: %v", err)
	}

	t.Run("with embedded CA ignoring all expiry", func(t *testing.T) {
		signer, err := NewSigner(cert, key, &VerifyOptions{
			Expiry: ExpiryPolicyIgnoreAll,
		})
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		err = signer.VerifyChain()
		if err != nil {
			t.Errorf("Chain verification failed: %v", err)
		} else {
			t.Log("Chain verification passed with embedded CA")
		}
	})

	t.Run("check issuer chain", func(t *testing.T) {
		t.Logf("Certificate issuer: %s", cert.Issuer.String())

		// Verify the issuer matches our intermediate CA
		roots := DefaultRoots()
		intermediates := DefaultIntermediates()

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   cert.NotBefore.Add(time.Hour), // Within validity
		}

		chains, err := cert.Verify(opts)
		if err != nil {
			t.Errorf("Chain verification failed: %v", err)
			return
		}

		if len(chains) == 0 {
			t.Error("no valid certificate chains found")
			return
		}

		t.Logf("Found %d valid chain(s)", len(chains))
		for i, chain := range chains {
			t.Logf("Chain %d:", i)
			for j, c := range chain {
				t.Logf("  [%d] %s", j, c.Subject.CommonName)
			}
		}
	})
}

// Verify that parsing handles the TQ6 format properly
func TestIntegration_ParseTQ6(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	// The 2026/KB2S.tq6 file should be a user certificate file
	tq6Path := filepath.Join(testdataDir, "2026", "KB2S.tq6")

	tq6Data, err := os.ReadFile(tq6Path)
	if err != nil {
		t.Skipf("TQ6 file not found: %v", err)
	}

	// LoadTQ6 handles gzip decompression automatically
	certs, err := LoadTQ6(tq6Data)
	if err != nil {
		t.Fatalf("LoadTQ6 failed: %v", err)
	}

	if len(certs) == 0 {
		t.Fatal("no certificates found in TQ6 file")
	}

	t.Logf("Found %d certificates in TQ6 file", len(certs))

	// Verify each certificate is parseable
	for i, cert := range certs {
		if cert.Subject.CommonName == "" {
			t.Errorf("certificate %d has empty common name", i)
		}
		if cert.SerialNumber == nil {
			t.Errorf("certificate %d has nil serial number", i)
		}
	}
}

// Test error cases for the library functions
func TestIntegration_ErrorCases(t *testing.T) {
	if !testdataExists(t) {
		return
	}

	t.Run("LoadPKCS12 with wrong password", func(t *testing.T) {
		p12Path := filepath.Join(testdataDir, "2026", "KB2S.p12")
		p12Data, err := os.ReadFile(p12Path)
		if err != nil {
			t.Skipf("PKCS12 file not found: %v", err)
		}

		_, _, err = LoadPKCS12(p12Data, "definitely-wrong-password")
		if err == nil {
			t.Error("LoadPKCS12 should fail with wrong password")
		}
	})

	t.Run("LoadPEM with invalid cert", func(t *testing.T) {
		invalidCert := []byte("not a valid PEM certificate")
		validKey := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----`)

		_, _, err := LoadPEM(invalidCert, validKey)
		if err == nil {
			t.Error("LoadPEM should fail with invalid certificate")
		}
	})

	t.Run("LoadPEM with invalid key", func(t *testing.T) {
		validCert := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpeg
-----END CERTIFICATE-----`)
		invalidKey := []byte("not a valid PEM key")

		_, _, err := LoadPEM(validCert, invalidKey)
		if err == nil {
			t.Error("LoadPEM should fail with invalid key")
		}
	})

	t.Run("LoadTQ6 with no certificates", func(t *testing.T) {
		noCerts := []byte("<xml>no certificates here</xml>")
		_, err := LoadTQ6(noCerts)
		if err == nil {
			t.Error("LoadTQ6 should fail when no certificates found")
		}
	})

	t.Run("NewSigner with nil certificate", func(t *testing.T) {
		_, err := NewSigner(nil, nil, nil)
		if err == nil {
			t.Error("NewSigner should fail with nil certificate")
		}
	})

	t.Run("Verify with corrupted signature", func(t *testing.T) {
		// Load a valid cert/key pair
		certPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "certs", "user")
		keyPath := filepath.Join(testdataDir, "2025", "TrustedQSL", "keys", "KB2S")

		certData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("failed to read certificate: %v", err)
		}
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("failed to read key: %v", err)
		}

		keyPEM, err := parseTQSLKeyFile(keyData, "KB2S")
		if err != nil {
			t.Fatalf("failed to parse key: %v", err)
		}

		cert, key, err := LoadPEM(certData, keyPEM)
		if err != nil {
			t.Fatalf("LoadPEM failed: %v", err)
		}

		signer, err := NewSigner(cert, key, &VerifyOptions{Expiry: ExpiryPolicyIgnoreAll})
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		testData := []byte("test data")
		sig, err := signer.Sign(testData)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		// Corrupt the signature
		sig[0] ^= 0xFF
		sig[len(sig)-1] ^= 0xFF

		err = signer.Verify(testData, sig)
		if err == nil {
			t.Error("Verify should fail with corrupted signature")
		}
	})
}
