package hamsign

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// OIDs for amateur radio certificate extensions (from hamcert package)
var (
	testOIDCallsign     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 1}
	testOIDQSONotBefore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 2}
	testOIDQSONotAfter  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 3}
	testOIDDXCCEntity   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 4}
	testOIDCRQEmail     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 8}
	testOIDCRQAddress1  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 9}
	testOIDCRQCity      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 11}
	testOIDCRQState     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 12}
	testOIDCRQPostal    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 13}
	testOIDCRQCountry   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 14}
)

// testCertConfig holds configuration for generating test certificates
type testCertConfig struct {
	callsign      string
	operatorName  string
	email         string
	dxcc          int
	qsoNotBefore  time.Time
	qsoNotAfter   time.Time
	certNotBefore time.Time
	certNotAfter  time.Time
	address1      string
	city          string
	state         string
	postalCode    string
	country       string
	useRawASCII   bool // Use raw ASCII instead of ASN.1 encoding for extensions
	serialNumber  int64
}

// generateHamCert creates a certificate with amateur radio extensions for testing
func generateHamCert(t *testing.T, cfg testCertConfig) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial := cfg.serialNumber
	if serial == 0 {
		serial = 123456
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: cfg.operatorName,
		},
		NotBefore:             cfg.certNotBefore,
		NotAfter:              cfg.certNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{},
	}

	// Add callsign as extension
	template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDCallsign, cfg.callsign, cfg.useRawASCII))

	// Add DXCC entity
	if cfg.dxcc != 0 {
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDDXCCEntity, cfg.dxcc, cfg.useRawASCII))
	}

	// Add QSO date range
	if !cfg.qsoNotBefore.IsZero() {
		dateStr := cfg.qsoNotBefore.Format("2006-01-02")
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDQSONotBefore, dateStr, cfg.useRawASCII))
	}
	if !cfg.qsoNotAfter.IsZero() {
		dateStr := cfg.qsoNotAfter.Format("2006-01-02")
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDQSONotAfter, dateStr, cfg.useRawASCII))
	}

	// Add email
	if cfg.email != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDCRQEmail, cfg.email, cfg.useRawASCII))
	}

	// Add address fields
	if cfg.address1 != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDCRQAddress1, cfg.address1, cfg.useRawASCII))
	}
	if cfg.city != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDCRQCity, cfg.city, cfg.useRawASCII))
	}
	if cfg.state != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDCRQState, cfg.state, cfg.useRawASCII))
	}
	if cfg.postalCode != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDCRQPostal, cfg.postalCode, cfg.useRawASCII))
	}
	if cfg.country != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeExtension(t, testOIDCRQCountry, cfg.country, cfg.useRawASCII))
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

// makeExtension creates an X.509 extension with optional raw ASCII encoding
func makeExtension(t *testing.T, oid asn1.ObjectIdentifier, value interface{}, useRawASCII bool) pkix.Extension {
	t.Helper()

	var data []byte
	var err error

	if useRawASCII {
		// Store as raw ASCII bytes (TQSL style)
		switch v := value.(type) {
		case string:
			data = []byte(v)
		case int:
			data = []byte(string(rune('0' + v%10))) // Simple for small ints
			if v >= 10 {
				data = []byte(intToString(v))
			}
		}
	} else {
		// Standard ASN.1 encoding
		data, err = asn1.Marshal(value)
		if err != nil {
			t.Fatalf("failed to marshal extension value: %v", err)
		}
	}

	return pkix.Extension{
		Id:    oid,
		Value: data,
	}
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestSynthetic_ParseStationInfo tests parsing of amateur radio certificate extensions
func TestSynthetic_ParseStationInfo(t *testing.T) {
	now := time.Now()

	t.Run("full certificate with ASN1 encoding", func(t *testing.T) {
		// Using sample data (not real callsign, email, or address)
		cfg := testCertConfig{
			callsign:      "N0CALL",
			operatorName:  "JANE Q HAMOPERATOR",
			email:         "ham@example.com",
			dxcc:          291,
			qsoNotBefore:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			qsoNotAfter:   time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
			certNotBefore: now.Add(-24 * time.Hour),
			certNotAfter:  now.Add(365 * 24 * time.Hour),
			address1:      "123 Main St",
			city:          "Anytown",
			state:         "NY",
			postalCode:    "12345",
			country:       "USA",
			serialNumber:  100001,
		}

		cert, _ := generateHamCert(t, cfg)

		info, err := ParseStationInfo(cert)
		if err != nil {
			t.Fatalf("ParseStationInfo failed: %v", err)
		}

		if info.Callsign != "N0CALL" {
			t.Errorf("callsign: got %q, want %q", info.Callsign, "N0CALL")
		}
		if info.OperatorName != "JANE Q HAMOPERATOR" {
			t.Errorf("operator: got %q, want %q", info.OperatorName, "JANE Q HAMOPERATOR")
		}
		if info.DXCC != 291 {
			t.Errorf("DXCC: got %d, want %d", info.DXCC, 291)
		}
		if info.Email != "ham@example.com" {
			t.Errorf("email: got %q, want %q", info.Email, "ham@example.com")
		}

		// Verify QSO date range
		if info.QSONotBefore.Year() != 2020 {
			t.Errorf("QSONotBefore year: got %d, want %d", info.QSONotBefore.Year(), 2020)
		}
		if info.QSONotAfter.Year() != 2030 {
			t.Errorf("QSONotAfter year: got %d, want %d", info.QSONotAfter.Year(), 2030)
		}
	})

	// Note: "callsign in Subject DN" test is skipped because Go's x509.CreateCertificate
	// doesn't preserve custom OIDs in Subject.Names. Real TQSL certificates use custom
	// ASN.1 encoding for the Subject DN. The hamcert.getSubjectAttribute function works
	// correctly with real TQSL certificates as verified by integration tests.

	t.Run("raw ASCII encoding (TQSL style)", func(t *testing.T) {
		cfg := testCertConfig{
			callsign:      "N0CALL",
			operatorName:  "TEST OPERATOR",
			dxcc:          291,
			qsoNotBefore:  time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			certNotBefore: now.Add(-24 * time.Hour),
			certNotAfter:  now.Add(365 * 24 * time.Hour),
			useRawASCII:   true,
		}

		cert, _ := generateHamCert(t, cfg)

		info, err := ParseStationInfo(cert)
		if err != nil {
			t.Fatalf("ParseStationInfo failed: %v", err)
		}

		if info.Callsign != "N0CALL" {
			t.Errorf("callsign: got %q, want %q", info.Callsign, "N0CALL")
		}
	})

	t.Run("missing callsign fails", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test"},
			NotBefore:    now,
			NotAfter:     now.Add(time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		_, err := ParseStationInfo(cert)
		if err == nil {
			t.Error("ParseStationInfo should fail without callsign")
		}
	})

	t.Run("nil certificate fails", func(t *testing.T) {
		_, err := ParseStationInfo(nil)
		if err == nil {
			t.Error("ParseStationInfo should fail with nil certificate")
		}
	})
}

// TestSynthetic_ParseRequestAddress tests address parsing
func TestSynthetic_ParseRequestAddress(t *testing.T) {
	now := time.Now()

	// Using sample address data (not real)
	cfg := testCertConfig{
		callsign:      "N0CALL",
		operatorName:  "JANE Q HAMOPERATOR",
		certNotBefore: now.Add(-24 * time.Hour),
		certNotAfter:  now.Add(365 * 24 * time.Hour),
		address1:      "123 Main St",
		city:          "Anytown",
		state:         "NY",
		postalCode:    "12345",
		country:       "USA",
	}

	cert, _ := generateHamCert(t, cfg)

	addr, err := ParseRequestAddress(cert)
	if err != nil {
		t.Fatalf("ParseRequestAddress failed: %v", err)
	}

	if addr.Address1 != "123 Main St" {
		t.Errorf("Address1: got %q, want %q", addr.Address1, "123 Main St")
	}
	if addr.City != "Anytown" {
		t.Errorf("City: got %q, want %q", addr.City, "Anytown")
	}
	if addr.State != "NY" {
		t.Errorf("State: got %q, want %q", addr.State, "NY")
	}
	if addr.PostalCode != "12345" {
		t.Errorf("PostalCode: got %q, want %q", addr.PostalCode, "12345")
	}
	if addr.Country != "USA" {
		t.Errorf("Country: got %q, want %q", addr.Country, "USA")
	}
}

// TestSynthetic_QSODateRange tests QSO date range validation
func TestSynthetic_QSODateRange(t *testing.T) {
	now := time.Now()

	cfg := testCertConfig{
		callsign:      "N0CALL",
		operatorName:  "TEST OPERATOR",
		qsoNotBefore:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		qsoNotAfter:   time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		certNotBefore: now.Add(-24 * time.Hour),
		certNotAfter:  now.Add(365 * 24 * time.Hour),
	}

	cert, _ := generateHamCert(t, cfg)

	t.Run("date within range", func(t *testing.T) {
		qsoDate := time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC)
		if !QSODateRangeValid(cert, qsoDate) {
			t.Error("date should be valid")
		}
	})

	t.Run("date before range", func(t *testing.T) {
		qsoDate := time.Date(2019, 12, 31, 0, 0, 0, 0, time.UTC)
		if QSODateRangeValid(cert, qsoDate) {
			t.Error("date should be invalid (before range)")
		}
	})

	t.Run("date after range", func(t *testing.T) {
		qsoDate := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		if QSODateRangeValid(cert, qsoDate) {
			t.Error("date should be invalid (after range)")
		}
	})

	t.Run("date on boundary", func(t *testing.T) {
		// Exactly on the start boundary
		qsoDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		if !QSODateRangeValid(cert, qsoDate) {
			t.Error("date on start boundary should be valid")
		}

		// Exactly on the end boundary
		qsoDate = time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
		if !QSODateRangeValid(cert, qsoDate) {
			t.Error("date on end boundary should be valid")
		}
	})
}

// TestSynthetic_SignAndVerify tests signing and verification with ham radio certificates
func TestSynthetic_SignAndVerify(t *testing.T) {
	now := time.Now()

	cfg := testCertConfig{
		callsign:      "N0CALL",
		operatorName:  "TEST OPERATOR",
		dxcc:          291,
		certNotBefore: now.Add(-24 * time.Hour),
		certNotAfter:  now.Add(365 * 24 * time.Hour),
	}

	cert, key := generateHamCert(t, cfg)

	signer, err := NewSigner(cert, key, nil)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	t.Run("sign and verify QSO data", func(t *testing.T) {
		// Sample QSO data format (not real callsigns)
		qsoData := []byte("N0CALL K0TEST 20231015 1200 14.200 SSB 59 59")

		sig, err := signer.Sign(qsoData)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(sig) == 0 {
			t.Fatal("signature is empty")
		}

		err = signer.Verify(qsoData, sig)
		if err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})

	t.Run("verify fails with wrong data", func(t *testing.T) {
		qsoData := []byte("original QSO data")
		sig, _ := signer.Sign(qsoData)

		err := signer.Verify([]byte("tampered QSO data"), sig)
		if err == nil {
			t.Error("verification should fail with tampered data")
		}
	})

	t.Run("verify fails with corrupted signature", func(t *testing.T) {
		qsoData := []byte("test QSO data")
		sig, _ := signer.Sign(qsoData)

		// Corrupt signature
		sig[0] ^= 0xFF
		sig[len(sig)/2] ^= 0xFF
		sig[len(sig)-1] ^= 0xFF

		err := signer.Verify(qsoData, sig)
		if err == nil {
			t.Error("verification should fail with corrupted signature")
		}
	})
}

// TestSynthetic_PKCS12RoundTrip tests export and import of ham radio certificates
func TestSynthetic_PKCS12RoundTrip(t *testing.T) {
	now := time.Now()

	cfg := testCertConfig{
		callsign:      "K1ABC",
		operatorName:  "JOHN DOE",
		email:         "k1abc@example.com",
		dxcc:          291,
		qsoNotBefore:  time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		qsoNotAfter:   time.Date(2028, 12, 31, 0, 0, 0, 0, time.UTC),
		certNotBefore: now.Add(-24 * time.Hour),
		certNotAfter:  now.Add(365 * 24 * time.Hour),
		serialNumber:  789012,
	}

	cert, key := generateHamCert(t, cfg)

	t.Run("export and reload", func(t *testing.T) {
		password := "test-password-123"

		exported, err := ExportPKCS12(cert, key, password)
		if err != nil {
			t.Fatalf("ExportPKCS12 failed: %v", err)
		}

		if len(exported) == 0 {
			t.Fatal("exported PKCS12 is empty")
		}

		reloadedCert, reloadedKey, err := LoadPKCS12(exported, password)
		if err != nil {
			t.Fatalf("LoadPKCS12 failed: %v", err)
		}

		// Verify certificate matches
		if reloadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Error("serial number mismatch after reload")
		}

		// Verify ham radio extensions survived round-trip
		info, err := ParseStationInfo(reloadedCert)
		if err != nil {
			t.Fatalf("ParseStationInfo failed after reload: %v", err)
		}

		if info.Callsign != "K1ABC" {
			t.Errorf("callsign mismatch after reload: got %q, want %q", info.Callsign, "K1ABC")
		}
		if info.DXCC != 291 {
			t.Errorf("DXCC mismatch after reload: got %d, want %d", info.DXCC, 291)
		}

		// Verify key works for signing
		signer, err := NewSigner(reloadedCert, reloadedKey, nil)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		data := []byte("test data")
		sig, err := signer.Sign(data)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if err := signer.Verify(data, sig); err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})

	t.Run("wrong password fails", func(t *testing.T) {
		exported, _ := ExportPKCS12(cert, key, "correct-password")

		_, _, err := LoadPKCS12(exported, "wrong-password")
		if err == nil {
			t.Error("LoadPKCS12 should fail with wrong password")
		}
	})

	t.Run("empty password", func(t *testing.T) {
		exported, err := ExportPKCS12(cert, key, "")
		if err != nil {
			t.Fatalf("ExportPKCS12 with empty password failed: %v", err)
		}

		reloadedCert, _, err := LoadPKCS12(exported, "")
		if err != nil {
			t.Fatalf("LoadPKCS12 with empty password failed: %v", err)
		}

		if reloadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Error("serial number mismatch")
		}
	})
}

// TestSynthetic_LoadPEM tests PEM loading
func TestSynthetic_LoadPEM(t *testing.T) {
	now := time.Now()

	cfg := testCertConfig{
		callsign:      "W2XYZ",
		operatorName:  "JANE SMITH",
		dxcc:          291,
		certNotBefore: now.Add(-24 * time.Hour),
		certNotAfter:  now.Add(365 * 24 * time.Hour),
	}

	cert, key := generateHamCert(t, cfg)

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	t.Run("load valid PEM", func(t *testing.T) {
		loadedCert, loadedKey, err := LoadPEM(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("LoadPEM failed: %v", err)
		}

		if loadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Error("certificate mismatch")
		}

		// Verify key works
		signer, _ := NewSigner(loadedCert, loadedKey, nil)
		data := []byte("test")
		sig, _ := signer.Sign(data)
		if err := signer.Verify(data, sig); err != nil {
			t.Errorf("signature verification failed: %v", err)
		}
	})

	t.Run("invalid cert PEM", func(t *testing.T) {
		_, _, err := LoadPEM([]byte("not a PEM"), keyPEM)
		if err == nil {
			t.Error("LoadPEM should fail with invalid cert")
		}
	})

	t.Run("invalid key PEM", func(t *testing.T) {
		_, _, err := LoadPEM(certPEM, []byte("not a PEM"))
		if err == nil {
			t.Error("LoadPEM should fail with invalid key")
		}
	})

	t.Run("corrupted cert data", func(t *testing.T) {
		badCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("corrupted data"),
		})
		_, _, err := LoadPEM(badCertPEM, keyPEM)
		if err == nil {
			t.Error("LoadPEM should fail with corrupted cert data")
		}
	})
}

// TestSynthetic_LoadTQ6 tests TQ6 format loading
func TestSynthetic_LoadTQ6(t *testing.T) {
	now := time.Now()

	// Generate test certificates with sample callsigns
	cfg1 := testCertConfig{
		callsign:      "N0CALL",
		operatorName:  "FIRST OPERATOR",
		certNotBefore: now.Add(-24 * time.Hour),
		certNotAfter:  now.Add(365 * 24 * time.Hour),
		serialNumber:  1001,
	}
	cert1, _ := generateHamCert(t, cfg1)

	cfg2 := testCertConfig{
		callsign:      "K1ABC",
		operatorName:  "SECOND OPERATOR",
		certNotBefore: now.Add(-24 * time.Hour),
		certNotAfter:  now.Add(365 * 24 * time.Hour),
		serialNumber:  1002,
	}
	cert2, _ := generateHamCert(t, cfg2)

	t.Run("load raw PEM", func(t *testing.T) {
		// Create TQ6 data as concatenated PEM
		var buf bytes.Buffer
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})

		certs, err := LoadTQ6(buf.Bytes())
		if err != nil {
			t.Fatalf("LoadTQ6 failed: %v", err)
		}

		if len(certs) != 2 {
			t.Errorf("expected 2 certificates, got %d", len(certs))
		}
	})

	t.Run("load XML-embedded PEM", func(t *testing.T) {
		// Create TQ6 data as XML with embedded PEM
		var buf bytes.Buffer
		buf.WriteString(`<?xml version="1.0"?>
<tQSL_Certificates>
  <Certificates>
`)
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})
		buf.WriteString(`
  </Certificates>
</tQSL_Certificates>
`)

		certs, err := LoadTQ6(buf.Bytes())
		if err != nil {
			t.Fatalf("LoadTQ6 failed: %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("expected 1 certificate, got %d", len(certs))
		}
	})

	t.Run("load gzip-compressed", func(t *testing.T) {
		// Create TQ6 data and compress it
		var pemBuf bytes.Buffer
		_ = pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})

		var gzBuf bytes.Buffer
		gz := gzip.NewWriter(&gzBuf)
		_, _ = gz.Write(pemBuf.Bytes())
		_ = gz.Close()

		certs, err := LoadTQ6(gzBuf.Bytes())
		if err != nil {
			t.Fatalf("LoadTQ6 failed with gzip: %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("expected 1 certificate, got %d", len(certs))
		}
	})

	t.Run("no certificates fails", func(t *testing.T) {
		_, err := LoadTQ6([]byte("<xml>no certs here</xml>"))
		if err == nil {
			t.Error("LoadTQ6 should fail when no certificates found")
		}
	})

	t.Run("corrupted gzip fails", func(t *testing.T) {
		// Gzip magic bytes but corrupted data
		_, err := LoadTQ6([]byte{0x1f, 0x8b, 0x00, 0x00, 0x00})
		if err == nil {
			t.Error("LoadTQ6 should fail with corrupted gzip")
		}
	})
}

// TestSynthetic_ExpiryPolicies tests different expiration handling policies
func TestSynthetic_ExpiryPolicies(t *testing.T) {
	now := time.Now()

	t.Run("expired certificate with strict policy", func(t *testing.T) {
		cfg := testCertConfig{
			callsign:      "W1TEST",
			operatorName:  "TEST",
			certNotBefore: now.Add(-48 * time.Hour),
			certNotAfter:  now.Add(-24 * time.Hour), // Expired
		}

		cert, key := generateHamCert(t, cfg)

		signer, err := NewSigner(cert, key, &VerifyOptions{
			Expiry: ExpiryPolicyStrict,
		})
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		err = signer.VerifyChain()
		if err == nil {
			t.Error("VerifyChain should fail for expired cert with strict policy")
		}
	})

	t.Run("expired certificate with ignore-all policy", func(t *testing.T) {
		cfg := testCertConfig{
			callsign:      "W1TEST",
			operatorName:  "TEST",
			certNotBefore: now.Add(-48 * time.Hour),
			certNotAfter:  now.Add(-24 * time.Hour), // Expired
		}

		cert, key := generateHamCert(t, cfg)

		signer, err := NewSigner(cert, key, &VerifyOptions{
			Expiry: ExpiryPolicyIgnoreAll,
		})
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		// Self-signed cert won't verify against embedded CA, but signing should work
		data := []byte("test")
		sig, err := signer.Sign(data)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if err := signer.Verify(data, sig); err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})
}

// TestSynthetic_MultipleCertificates tests handling of multiple certificates
func TestSynthetic_MultipleCertificates(t *testing.T) {
	now := time.Now()

	// Create multiple certificates for different callsigns
	callsigns := []string{"W1AA", "W2BB", "W3CC", "K4DD", "N5EE"}
	var certs []*x509.Certificate

	for i, call := range callsigns {
		cfg := testCertConfig{
			callsign:      call,
			operatorName:  "OPERATOR " + call,
			dxcc:          291,
			certNotBefore: now.Add(-24 * time.Hour),
			certNotAfter:  now.Add(365 * 24 * time.Hour),
			serialNumber:  int64(2000 + i),
		}
		cert, _ := generateHamCert(t, cfg)
		certs = append(certs, cert)
	}

	// Create concatenated PEM
	var buf bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}

	// Load as TQ6
	loadedCerts, err := LoadTQ6(buf.Bytes())
	if err != nil {
		t.Fatalf("LoadTQ6 failed: %v", err)
	}

	if len(loadedCerts) != len(callsigns) {
		t.Errorf("expected %d certificates, got %d", len(callsigns), len(loadedCerts))
	}

	// Verify each certificate can be parsed
	for i, cert := range loadedCerts {
		info, err := ParseStationInfo(cert)
		if err != nil {
			t.Errorf("ParseStationInfo failed for cert %d: %v", i, err)
			continue
		}

		if info.Callsign != callsigns[i] {
			t.Errorf("cert %d: callsign mismatch: got %q, want %q", i, info.Callsign, callsigns[i])
		}
	}
}

// TestSynthetic_DXCCEntities tests various DXCC entity codes
func TestSynthetic_DXCCEntities(t *testing.T) {
	now := time.Now()

	dxccCases := []struct {
		dxcc int
		name string
	}{
		{291, "USA"},
		{1, "Canada"},
		{110, "Hawaii"},
		{6, "Alaska"},
		{227, "France"},
		{281, "England"},
	}

	for _, tc := range dxccCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testCertConfig{
				callsign:      "TEST",
				operatorName:  tc.name + " OPERATOR",
				dxcc:          tc.dxcc,
				certNotBefore: now.Add(-24 * time.Hour),
				certNotAfter:  now.Add(365 * 24 * time.Hour),
			}

			cert, _ := generateHamCert(t, cfg)

			info, err := ParseStationInfo(cert)
			if err != nil {
				t.Fatalf("ParseStationInfo failed: %v", err)
			}

			if info.DXCC != tc.dxcc {
				t.Errorf("DXCC: got %d, want %d", info.DXCC, tc.dxcc)
			}
		})
	}
}
