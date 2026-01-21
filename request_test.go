package hamsign

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateRequest(t *testing.T) {
	// Using sample data (not real callsign or address)
	req := &CertificateRequest{
		Callsign:     "N0CALL",
		Name:         "Test Operator",
		Email:        "test@example.com",
		DXCC:         291,
		QSONotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		QSONotAfter:  time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		Address1:     "123 Main St",
		City:         "Anytown",
		State:        "NY",
		PostalCode:   "12345",
		Country:      "USA",
	}

	t.Run("valid request", func(t *testing.T) {
		tq5, encKey, err := GenerateRequest(req, "testpassword")
		if err != nil {
			t.Fatalf("GenerateRequest failed: %v", err)
		}

		// Verify TQ5 is valid PEM
		block, _ := pem.Decode(tq5)
		if block == nil {
			t.Fatal("TQ5 is not valid PEM")
		}
		if block.Type != "CERTIFICATE REQUEST" {
			t.Errorf("unexpected PEM type: %s", block.Type)
		}

		// Verify CSR can be parsed
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse CSR: %v", err)
		}
		if csr.Subject.CommonName != req.Name {
			t.Errorf("subject CN mismatch: got %s, want %s", csr.Subject.CommonName, req.Name)
		}

		// Verify encrypted key is valid PEM
		block, _ = pem.Decode(encKey)
		if block == nil {
			t.Fatal("encrypted key is not valid PEM")
		}
		if block.Type != "RSA PRIVATE KEY" {
			t.Errorf("unexpected key PEM type: %s", block.Type)
		}
		//nolint:staticcheck // SA1019: x509.IsEncryptedPEMBlock used to verify TQSL-compatible encryption
		if !x509.IsEncryptedPEMBlock(block) {
			t.Error("key is not encrypted")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		_, _, err := GenerateRequest(nil, "password")
		if err == nil {
			t.Error("expected error for nil request")
		}
	})

	t.Run("missing callsign", func(t *testing.T) {
		badReq := &CertificateRequest{Name: "Test"}
		_, _, err := GenerateRequest(badReq, "password")
		if err == nil {
			t.Error("expected error for missing callsign")
		}
	})
}

func TestRenewRequest(t *testing.T) {
	// Generate a certificate to sign the renewal with
	cert, key := generateTestCert(t)

	// Using sample data (not real callsign)
	req := &CertificateRequest{
		Callsign:     "N0CALL",
		Name:         "Test Operator",
		Email:        "test@example.com",
		DXCC:         291,
		QSONotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		QSONotAfter:  time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
	}

	t.Run("valid renewal", func(t *testing.T) {
		tq5, encKey, err := RenewRequest(req, cert, key, "testpassword")
		if err != nil {
			t.Fatalf("RenewRequest failed: %v", err)
		}

		// Verify TQ5 is valid PEM
		block, _ := pem.Decode(tq5)
		if block == nil {
			t.Fatal("TQ5 is not valid PEM")
		}
		if block.Type != "CERTIFICATE REQUEST" {
			t.Errorf("unexpected PEM type: %s", block.Type)
		}

		// Verify renewal headers are present
		if block.Headers["X-Renewal-Signature"] == "" {
			t.Error("missing renewal signature header")
		}
		if block.Headers["X-Renewal-Serial"] == "" {
			t.Error("missing renewal serial header")
		}

		// Verify encrypted key
		block, _ = pem.Decode(encKey)
		if block == nil {
			t.Fatal("encrypted key is not valid PEM")
		}
	})

	t.Run("nil signing cert", func(t *testing.T) {
		_, _, err := RenewRequest(req, nil, key, "password")
		if err == nil {
			t.Error("expected error for nil signing cert")
		}
	})

	t.Run("nil signing key", func(t *testing.T) {
		_, _, err := RenewRequest(req, cert, nil, "password")
		if err == nil {
			t.Error("expected error for nil signing key")
		}
	})
}
