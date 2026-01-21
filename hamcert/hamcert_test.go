package hamcert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// generateTestCertWithExtensions creates a certificate with custom extensions for testing.
func generateTestCertWithExtensions(t *testing.T, extensions []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Operator",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       extensions,
		EmailAddresses:        []string{"test@example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func makeStringExt(oid asn1.ObjectIdentifier, value string) pkix.Extension {
	val, _ := asn1.Marshal(value)
	return pkix.Extension{Id: oid, Value: val}
}

func makeIntExt(oid asn1.ObjectIdentifier, value int) pkix.Extension {
	val, _ := asn1.Marshal(value)
	return pkix.Extension{Id: oid, Value: val}
}

func TestParseStationInfo(t *testing.T) {
	// Using sample data (not real callsign or email)
	extensions := []pkix.Extension{
		makeStringExt(oidCallsign, "N0CALL"),
		makeIntExt(oidDXCCEntity, 291),
		makeStringExt(oidQSONotBefore, "20200101"),
		makeStringExt(oidQSONotAfter, "20301231"),
		makeStringExt(oidCRQEmail, "ham@example.com"),
	}

	cert := generateTestCertWithExtensions(t, extensions)

	t.Run("parse all fields", func(t *testing.T) {
		info, err := ParseStationInfo(cert)
		if err != nil {
			t.Fatalf("ParseStationInfo failed: %v", err)
		}

		if info.Callsign != "N0CALL" {
			t.Errorf("callsign: got %s, want N0CALL", info.Callsign)
		}
		if info.DXCC != 291 {
			t.Errorf("DXCC: got %d, want 291", info.DXCC)
		}
		if info.OperatorName != "Test Operator" {
			t.Errorf("operator name: got %s, want Test Operator", info.OperatorName)
		}
		if info.Email != "ham@example.com" {
			t.Errorf("email: got %s, want ham@example.com", info.Email)
		}

		expectedNotBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		if !info.QSONotBefore.Equal(expectedNotBefore) {
			t.Errorf("QSONotBefore: got %v, want %v", info.QSONotBefore, expectedNotBefore)
		}

		expectedNotAfter := time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)
		if !info.QSONotAfter.Equal(expectedNotAfter) {
			t.Errorf("QSONotAfter: got %v, want %v", info.QSONotAfter, expectedNotAfter)
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		_, err := ParseStationInfo(nil)
		if err == nil {
			t.Error("expected error for nil certificate")
		}
	})

	t.Run("missing callsign", func(t *testing.T) {
		certNoCallsign := generateTestCertWithExtensions(t, nil)
		_, err := ParseStationInfo(certNoCallsign)
		if err == nil {
			t.Error("expected error for missing callsign")
		}
	})
}

func TestParseRequestAddress(t *testing.T) {
	// Using USPS-style sample address data (not real)
	extensions := []pkix.Extension{
		makeStringExt(oidCallsign, "N0CALL"),
		makeStringExt(oidCRQAddress1, "123 Main St"),
		makeStringExt(oidCRQAddress2, "Apt 1"),
		makeStringExt(oidCRQCity, "Anytown"),
		makeStringExt(oidCRQState, "NY"),
		makeStringExt(oidCRQPostal, "12345"),
		makeStringExt(oidCRQCountry, "USA"),
	}

	cert := generateTestCertWithExtensions(t, extensions)

	t.Run("parse all fields", func(t *testing.T) {
		addr, err := ParseRequestAddress(cert)
		if err != nil {
			t.Fatalf("ParseRequestAddress failed: %v", err)
		}

		if addr.Address1 != "123 Main St" {
			t.Errorf("Address1: got %s, want 123 Main St", addr.Address1)
		}
		if addr.Address2 != "Apt 1" {
			t.Errorf("Address2: got %s, want Apt 1", addr.Address2)
		}
		if addr.City != "Anytown" {
			t.Errorf("City: got %s, want Anytown", addr.City)
		}
		if addr.State != "NY" {
			t.Errorf("State: got %s, want NY", addr.State)
		}
		if addr.PostalCode != "12345" {
			t.Errorf("PostalCode: got %s, want 12345", addr.PostalCode)
		}
		if addr.Country != "USA" {
			t.Errorf("Country: got %s, want USA", addr.Country)
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		_, err := ParseRequestAddress(nil)
		if err == nil {
			t.Error("expected error for nil certificate")
		}
	})

	t.Run("empty address", func(t *testing.T) {
		certNoAddr := generateTestCertWithExtensions(t, []pkix.Extension{
			makeStringExt(oidCallsign, "N0CALL"),
		})
		addr, err := ParseRequestAddress(certNoAddr)
		if err != nil {
			t.Fatalf("ParseRequestAddress failed: %v", err)
		}
		// Should return empty struct, not error
		if addr.Address1 != "" || addr.City != "" {
			t.Error("expected empty address fields")
		}
	})
}
