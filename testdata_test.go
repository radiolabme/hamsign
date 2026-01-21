package hamsign

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const syntheticDir = "testdata/synthetic"

func syntheticDataExists(t *testing.T) bool {
	t.Helper()
	if _, err := os.Stat(syntheticDir); os.IsNotExist(err) {
		t.Skip("synthetic testdata directory not found, run 'go run testdata/synthetic/generate.go'")
		return false
	}
	return true
}

func TestTestdata_ValidCertificate(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	certData, err := os.ReadFile(filepath.Join(syntheticDir, "valid_cert.pem"))
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	keyData, err := os.ReadFile(filepath.Join(syntheticDir, "valid_key.pem"))
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}

	cert, key, err := LoadPEM(certData, keyData)
	if err != nil {
		t.Fatalf("LoadPEM failed: %v", err)
	}

	// Verify station info
	info, err := ParseStationInfo(cert)
	if err != nil {
		t.Fatalf("ParseStationInfo failed: %v", err)
	}

	if info.Callsign != "W1TEST" {
		t.Errorf("callsign: got %q, want %q", info.Callsign, "W1TEST")
	}
	if info.DXCC != 291 {
		t.Errorf("DXCC: got %d, want %d", info.DXCC, 291)
	}

	// Verify signing works
	signer, err := NewSigner(cert, key, nil)
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
}

func TestTestdata_FullHamCertificate(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	certData, err := os.ReadFile(filepath.Join(syntheticDir, "full_ham_cert.pem"))
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	keyData, err := os.ReadFile(filepath.Join(syntheticDir, "full_ham_key.pem"))
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}

	cert, _, err := LoadPEM(certData, keyData)
	if err != nil {
		t.Fatalf("LoadPEM failed: %v", err)
	}

	// Verify station info
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
	if info.Email != "ham@example.com" {
		t.Errorf("email: got %q, want %q", info.Email, "ham@example.com")
	}
	if info.DXCC != 291 {
		t.Errorf("DXCC: got %d, want %d", info.DXCC, 291)
	}

	// Verify address (using USPS sample data)
	addr, err := ParseRequestAddress(cert)
	if err != nil {
		t.Fatalf("ParseRequestAddress failed: %v", err)
	}

	if addr.Address1 != "123 Main St" {
		t.Errorf("address1: got %q, want %q", addr.Address1, "123 Main St")
	}
	if addr.City != "Anytown" {
		t.Errorf("city: got %q, want %q", addr.City, "Anytown")
	}
	if addr.State != "NY" {
		t.Errorf("state: got %q, want %q", addr.State, "NY")
	}
	if addr.PostalCode != "12345" {
		t.Errorf("postal: got %q, want %q", addr.PostalCode, "12345")
	}
	if addr.Country != "USA" {
		t.Errorf("country: got %q, want %q", addr.Country, "USA")
	}
}

func TestTestdata_ExpiredCertificate(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	certData, err := os.ReadFile(filepath.Join(syntheticDir, "expired_cert.pem"))
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	keyData, err := os.ReadFile(filepath.Join(syntheticDir, "expired_key.pem"))
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}

	cert, key, err := LoadPEM(certData, keyData)
	if err != nil {
		t.Fatalf("LoadPEM failed: %v", err)
	}

	// Verify it's expired
	if !IsExpired(cert) {
		t.Error("certificate should be expired")
	}

	// Verify signing still works (expiry doesn't affect signing)
	signer, err := NewSigner(cert, key, &VerifyOptions{Expiry: ExpiryPolicyIgnoreAll})
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

	// Verify chain should fail with strict policy
	strictSigner, _ := NewSigner(cert, key, &VerifyOptions{Expiry: ExpiryPolicyStrict})
	err = strictSigner.VerifyChain()
	if err == nil {
		t.Error("VerifyChain should fail for expired cert with strict policy")
	}
}

func TestTestdata_PKCS12WithPassword(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	// Expected values from generate.go for PKCS12 files
	expectedCallsign := "K1P12"
	expectedOperator := "PKCS12 TEST"
	expectedDXCC := 291

	p12Data, err := os.ReadFile(filepath.Join(syntheticDir, "with_password.p12"))
	if err != nil {
		t.Fatalf("failed to read p12: %v", err)
	}

	// Should fail with wrong password
	_, _, err = LoadPKCS12(p12Data, "wrongpassword")
	if err == nil {
		t.Error("LoadPKCS12 should fail with wrong password")
	}

	// Should succeed with correct password
	cert, key, err := LoadPKCS12(p12Data, "testpassword")
	if err != nil {
		t.Fatalf("LoadPKCS12 failed with correct password: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("cert or key is nil")
	}

	// Verify certificate extension values
	if cert.Subject.CommonName != expectedOperator {
		t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, expectedOperator)
	}

	info, err := ParseStationInfo(cert)
	if err != nil {
		t.Fatalf("ParseStationInfo failed: %v", err)
	}

	if info.Callsign != expectedCallsign {
		t.Errorf("Callsign: got %q, want %q", info.Callsign, expectedCallsign)
	}
	if info.DXCC != expectedDXCC {
		t.Errorf("DXCC: got %d, want %d", info.DXCC, expectedDXCC)
	}
}

func TestTestdata_PKCS12NoPassword(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	// Expected values from generate.go for PKCS12 files (same cert used for both)
	expectedCallsign := "K1P12"
	expectedOperator := "PKCS12 TEST"
	expectedDXCC := 291

	p12Data, err := os.ReadFile(filepath.Join(syntheticDir, "no_password.p12"))
	if err != nil {
		t.Fatalf("failed to read p12: %v", err)
	}

	cert, key, err := LoadPKCS12(p12Data, "")
	if err != nil {
		t.Fatalf("LoadPKCS12 failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("cert or key is nil")
	}

	// Verify certificate extension values
	if cert.Subject.CommonName != expectedOperator {
		t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, expectedOperator)
	}

	info, err := ParseStationInfo(cert)
	if err != nil {
		t.Fatalf("ParseStationInfo failed: %v", err)
	}

	if info.Callsign != expectedCallsign {
		t.Errorf("Callsign: got %q, want %q", info.Callsign, expectedCallsign)
	}
	if info.DXCC != expectedDXCC {
		t.Errorf("DXCC: got %d, want %d", info.DXCC, expectedDXCC)
	}
}

func TestTestdata_TQ6Formats(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	// Expected values from generate.go for TQ6 files
	expectedCallsign := "W1TQ6"
	expectedOperator := "TQ6 TEST OPERATOR"
	expectedDXCC := 291

	testCases := []struct {
		file     string
		numCerts int
	}{
		{"raw_pem.tq6", 1},
		{"xml_embedded.tq6", 1},
		{"gzip_compressed.tq6", 1},
		{"gzip_xml.tq6", 1},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(syntheticDir, tc.file))
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			certs, err := LoadTQ6(data)
			if err != nil {
				t.Fatalf("LoadTQ6 failed: %v", err)
			}

			if len(certs) != tc.numCerts {
				t.Errorf("expected %d certs, got %d", tc.numCerts, len(certs))
			}

			// Verify the certificate extension values
			for i, cert := range certs {
				if cert.Subject.CommonName != expectedOperator {
					t.Errorf("cert %d CN: got %q, want %q", i, cert.Subject.CommonName, expectedOperator)
				}

				// Parse station info and verify values
				info, err := ParseStationInfo(cert)
				if err != nil {
					t.Errorf("cert %d ParseStationInfo failed: %v", i, err)
					continue
				}

				if info.Callsign != expectedCallsign {
					t.Errorf("cert %d Callsign: got %q, want %q", i, info.Callsign, expectedCallsign)
				}
				if info.DXCC != expectedDXCC {
					t.Errorf("cert %d DXCC: got %d, want %d", i, info.DXCC, expectedDXCC)
				}
				if info.OperatorName != expectedOperator {
					t.Errorf("cert %d OperatorName: got %q, want %q", i, info.OperatorName, expectedOperator)
				}
			}
		})
	}
}

func TestTestdata_MultiCert(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	data, err := os.ReadFile(filepath.Join(syntheticDir, "multi_cert.pem"))
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	certs, err := LoadTQ6(data)
	if err != nil {
		t.Fatalf("LoadTQ6 failed: %v", err)
	}

	if len(certs) != 3 {
		t.Errorf("expected 3 certs, got %d", len(certs))
	}

	expectedCallsigns := []string{"W1AA", "W2BB", "K3CC"}
	for i, cert := range certs {
		info, err := ParseStationInfo(cert)
		if err != nil {
			t.Errorf("ParseStationInfo failed for cert %d: %v", i, err)
			continue
		}
		if info.Callsign != expectedCallsigns[i] {
			t.Errorf("cert %d: callsign got %q, want %q", i, info.Callsign, expectedCallsigns[i])
		}
	}
}

func TestTestdata_TQ8Formats(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	// Helper functions to decode extension values
	getCSRExtString := func(exts []pkix.Extension, oid string) string {
		for _, ext := range exts {
			if ext.Id.String() == oid {
				var str string
				if _, err := asn1.Unmarshal(ext.Value, &str); err == nil {
					return str
				}
			}
		}
		return ""
	}
	getCSRExtInt := func(exts []pkix.Extension, oid string) int {
		for _, ext := range exts {
			if ext.Id.String() == oid {
				var val int
				if _, err := asn1.Unmarshal(ext.Value, &val); err == nil {
					return val
				}
			}
		}
		return 0
	}

	// OID definitions for comparison
	oidCallsign := "1.3.6.1.4.1.12348.1.1"
	oidQSONotBefore := "1.3.6.1.4.1.12348.1.2"
	oidQSONotAfter := "1.3.6.1.4.1.12348.1.3"
	oidDXCC := "1.3.6.1.4.1.12348.1.4"
	oidEmail := "1.3.6.1.4.1.12348.1.8"
	oidAddress1 := "1.3.6.1.4.1.12348.1.9"
	oidCity := "1.3.6.1.4.1.12348.1.11"
	oidState := "1.3.6.1.4.1.12348.1.12"
	oidPostal := "1.3.6.1.4.1.12348.1.13"
	oidCountry := "1.3.6.1.4.1.12348.1.14"

	// Expected values from generate.go
	expected := struct {
		CN           string
		Email        string
		Callsign     string
		DXCC         int
		QSONotBefore string
		QSONotAfter  string
		Address1     string
		City         string
		State        string
		PostalCode   string
		Country      string
	}{
		CN:           "TEST OPERATOR",
		Email:        "csr@example.com",
		Callsign:     "N0CALL",
		DXCC:         291,
		QSONotBefore: "20200101",
		QSONotAfter:  "20301231",
		Address1:     "123 Main St",
		City:         "Anytown",
		State:        "NY",
		PostalCode:   "12345",
		Country:      "USA",
	}

	testCases := []struct {
		file string
	}{
		{"cert_request.tq8"},
		{"cert_request_xml.tq8"},
		{"cert_request_gzip.tq8"},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(syntheticDir, tc.file))
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			csr, err := LoadTQ8(data)
			if err != nil {
				t.Fatalf("LoadTQ8 failed: %v", err)
			}

			// Verify standard CSR fields
			if csr.Subject.CommonName != expected.CN {
				t.Errorf("CSR CN: got %q, want %q", csr.Subject.CommonName, expected.CN)
			}
			if len(csr.EmailAddresses) == 0 || csr.EmailAddresses[0] != expected.Email {
				t.Errorf("CSR email: got %v, want [%s]", csr.EmailAddresses, expected.Email)
			}

			// Verify all ham radio extension VALUES match expected
			stringTests := []struct {
				name     string
				oid      string
				got      string
				expected string
			}{
				{"Callsign", oidCallsign, getCSRExtString(csr.Extensions, oidCallsign), expected.Callsign},
				{"Email", oidEmail, getCSRExtString(csr.Extensions, oidEmail), expected.Email},
				{"Address1", oidAddress1, getCSRExtString(csr.Extensions, oidAddress1), expected.Address1},
				{"City", oidCity, getCSRExtString(csr.Extensions, oidCity), expected.City},
				{"State", oidState, getCSRExtString(csr.Extensions, oidState), expected.State},
				{"PostalCode", oidPostal, getCSRExtString(csr.Extensions, oidPostal), expected.PostalCode},
				{"Country", oidCountry, getCSRExtString(csr.Extensions, oidCountry), expected.Country},
				{"QSONotBefore", oidQSONotBefore, getCSRExtString(csr.Extensions, oidQSONotBefore), expected.QSONotBefore},
				{"QSONotAfter", oidQSONotAfter, getCSRExtString(csr.Extensions, oidQSONotAfter), expected.QSONotAfter},
			}

			for _, st := range stringTests {
				if st.got != st.expected {
					t.Errorf("%s: got %q, want %q", st.name, st.got, st.expected)
				}
			}

			// Verify DXCC integer value
			gotDXCC := getCSRExtInt(csr.Extensions, oidDXCC)
			if gotDXCC != expected.DXCC {
				t.Errorf("DXCC: got %d, want %d", gotDXCC, expected.DXCC)
			}

			t.Logf("CSR has %d extensions, all values match", len(csr.Extensions))
		})
	}
}

func TestTestdata_TQ8Invalid(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	// Test with data that has no CSR
	_, err := LoadTQ8([]byte("not a valid CSR"))
	if err == nil {
		t.Error("LoadTQ8 should fail with invalid data")
	}

	// Test with corrupted gzip
	corruptedGzip, _ := os.ReadFile(filepath.Join(syntheticDir, "corrupted_gzip.tq6"))
	_, err = LoadTQ8(corruptedGzip)
	if err == nil {
		t.Error("LoadTQ8 should fail with corrupted gzip")
	}
}

func TestTestdata_TQ8RoundTrip(t *testing.T) {
	// Test that we can generate a TQ8 and then load it back with all fields preserved
	req := &CertificateRequest{
		Callsign:     "N0CALL",
		Name:         "Test Operator",
		Email:        "test@example.com",
		DXCC:         291,
		QSONotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		QSONotAfter:  time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		Address1:     "123 Main St",
		Address2:     "Suite 100",
		City:         "Anytown",
		State:        "NY",
		PostalCode:   "12345",
		Country:      "USA",
	}

	// Generate the request (returns PEM-encoded CSR)
	tq8Data, encryptedKey, err := GenerateRequest(req, "testpassword")
	if err != nil {
		t.Fatalf("GenerateRequest failed: %v", err)
	}

	// Verify encrypted key is present
	if len(encryptedKey) == 0 {
		t.Error("encrypted key is empty")
	}

	// Load it back using LoadTQ8
	csr, err := LoadTQ8(tq8Data)
	if err != nil {
		t.Fatalf("LoadTQ8 failed: %v", err)
	}

	// Verify standard CSR fields
	if csr.Subject.CommonName != req.Name {
		t.Errorf("CSR CN: got %q, want %q", csr.Subject.CommonName, req.Name)
	}
	if len(csr.EmailAddresses) == 0 || csr.EmailAddresses[0] != req.Email {
		t.Errorf("CSR email: got %v, want [%s]", csr.EmailAddresses, req.Email)
	}

	// Helper functions to decode extension values
	getCSRExtString := func(exts []pkix.Extension, oid string) string {
		for _, ext := range exts {
			if ext.Id.String() == oid {
				var str string
				if _, err := asn1.Unmarshal(ext.Value, &str); err == nil {
					return str
				}
			}
		}
		return ""
	}
	getCSRExtInt := func(exts []pkix.Extension, oid string) int {
		for _, ext := range exts {
			if ext.Id.String() == oid {
				var val int
				if _, err := asn1.Unmarshal(ext.Value, &val); err == nil {
					return val
				}
			}
		}
		return 0
	}

	// OID definitions for comparison
	oidCallsign := "1.3.6.1.4.1.12348.1.1"
	oidQSONotBefore := "1.3.6.1.4.1.12348.1.2"
	oidQSONotAfter := "1.3.6.1.4.1.12348.1.3"
	oidDXCC := "1.3.6.1.4.1.12348.1.4"
	oidEmail := "1.3.6.1.4.1.12348.1.8"
	oidAddress1 := "1.3.6.1.4.1.12348.1.9"
	oidAddress2 := "1.3.6.1.4.1.12348.1.10"
	oidCity := "1.3.6.1.4.1.12348.1.11"
	oidState := "1.3.6.1.4.1.12348.1.12"
	oidPostal := "1.3.6.1.4.1.12348.1.13"
	oidCountry := "1.3.6.1.4.1.12348.1.14"

	// Verify all ham radio extension VALUES match the original request
	stringTests := []struct {
		name     string
		oid      string
		got      string
		expected string
	}{
		{"Callsign", oidCallsign, getCSRExtString(csr.Extensions, oidCallsign), req.Callsign},
		{"Email", oidEmail, getCSRExtString(csr.Extensions, oidEmail), req.Email},
		{"Address1", oidAddress1, getCSRExtString(csr.Extensions, oidAddress1), req.Address1},
		{"Address2", oidAddress2, getCSRExtString(csr.Extensions, oidAddress2), req.Address2},
		{"City", oidCity, getCSRExtString(csr.Extensions, oidCity), req.City},
		{"State", oidState, getCSRExtString(csr.Extensions, oidState), req.State},
		{"PostalCode", oidPostal, getCSRExtString(csr.Extensions, oidPostal), req.PostalCode},
		{"Country", oidCountry, getCSRExtString(csr.Extensions, oidCountry), req.Country},
		{"QSONotBefore", oidQSONotBefore, getCSRExtString(csr.Extensions, oidQSONotBefore), req.QSONotBefore.Format("20060102")},
		{"QSONotAfter", oidQSONotAfter, getCSRExtString(csr.Extensions, oidQSONotAfter), req.QSONotAfter.Format("20060102")},
	}

	for _, tc := range stringTests {
		if tc.got != tc.expected {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.expected)
		}
	}

	// Verify DXCC integer value
	gotDXCC := getCSRExtInt(csr.Extensions, oidDXCC)
	if gotDXCC != req.DXCC {
		t.Errorf("DXCC: got %d, want %d", gotDXCC, req.DXCC)
	}

	t.Logf("CSR has %d extensions, all values match", len(csr.Extensions))
}

func TestTestdata_InvalidFiles(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	// Get a valid key for testing
	validKeyData, _ := os.ReadFile(filepath.Join(syntheticDir, "valid_key.pem"))
	validCertData, _ := os.ReadFile(filepath.Join(syntheticDir, "valid_cert.pem"))

	t.Run("invalid_not_pem", func(t *testing.T) {
		data, _ := os.ReadFile(filepath.Join(syntheticDir, "invalid_not_pem.pem"))
		_, _, err := LoadPEM(data, validKeyData)
		if err == nil {
			t.Error("LoadPEM should fail for non-PEM data")
		}
	})

	t.Run("invalid_corrupted_cert", func(t *testing.T) {
		data, _ := os.ReadFile(filepath.Join(syntheticDir, "invalid_corrupted_cert.pem"))
		_, _, err := LoadPEM(data, validKeyData)
		if err == nil {
			t.Error("LoadPEM should fail for corrupted cert")
		}
	})

	t.Run("invalid_corrupted_key", func(t *testing.T) {
		data, _ := os.ReadFile(filepath.Join(syntheticDir, "invalid_corrupted_key.pem"))
		_, _, err := LoadPEM(validCertData, data)
		if err == nil {
			t.Error("LoadPEM should fail for corrupted key")
		}
	})

	t.Run("no_certs_tq6", func(t *testing.T) {
		data, _ := os.ReadFile(filepath.Join(syntheticDir, "no_certs.tq6"))
		_, err := LoadTQ6(data)
		if err == nil {
			t.Error("LoadTQ6 should fail when no certs found")
		}
	})

	t.Run("corrupted_gzip", func(t *testing.T) {
		data, _ := os.ReadFile(filepath.Join(syntheticDir, "corrupted_gzip.tq6"))
		_, err := LoadTQ6(data)
		if err == nil {
			t.Error("LoadTQ6 should fail for corrupted gzip")
		}
	})

	t.Run("empty_file", func(t *testing.T) {
		data, _ := os.ReadFile(filepath.Join(syntheticDir, "empty.pem"))
		_, _, err := LoadPEM(data, validKeyData)
		if err == nil {
			t.Error("LoadPEM should fail for empty file")
		}
	})
}

func TestTestdata_QSODateRange(t *testing.T) {
	if !syntheticDataExists(t) {
		return
	}

	certData, _ := os.ReadFile(filepath.Join(syntheticDir, "valid_cert.pem"))
	keyData, _ := os.ReadFile(filepath.Join(syntheticDir, "valid_key.pem"))
	cert, _, _ := LoadPEM(certData, keyData)

	info, _ := ParseStationInfo(cert)
	t.Logf("QSO range: %s to %s", info.QSONotBefore, info.QSONotAfter)

	testCases := []struct {
		name     string
		date     time.Time
		expected bool
	}{
		{"within range", time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC), true},
		{"start boundary", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"end boundary", time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC), true},
		{"before range", time.Date(2019, 12, 31, 0, 0, 0, 0, time.UTC), false},
		{"after range", time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := QSODateRangeValid(cert, tc.date)
			if result != tc.expected {
				t.Errorf("QSODateRangeValid(%v) = %v, want %v", tc.date, result, tc.expected)
			}
		})
	}
}
