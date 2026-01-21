//go:build ignore

// This program generates synthetic test data files for the hamsign package.
// Run with: go run generate.go
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// OIDs for amateur radio certificate extensions
var (
	oidCallsign     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 1}
	oidQSONotBefore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 2}
	oidQSONotAfter  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 3}
	oidDXCCEntity   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 4}
	oidCRQEmail     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 8}
	oidCRQAddress1  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 9}
	oidCRQCity      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 11}
	oidCRQState     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 12}
	oidCRQPostal    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 13}
	oidCRQCountry   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 14}
)

func main() {
	// Get the directory where this script is located
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	fmt.Println("Generating synthetic test data...")

	// Generate valid certificate and key
	generateValidCert(dir)

	// Generate expired certificate
	generateExpiredCert(dir)

	// Generate certificate with full ham radio extensions
	generateFullHamCert(dir)

	// Generate PKCS12 files
	generatePKCS12Files(dir)

	// Generate TQ6 files (various formats)
	generateTQ6Files(dir)

	// Generate multi-cert PEM file
	generateMultiCertPEM(dir)

	// Generate TQ8 certificate request files
	generateTQ8Files(dir)

	// Generate invalid/corrupted files for error testing
	generateInvalidFiles(dir)

	fmt.Println("Done!")
}

func generateValidCert(dir string) {
	fmt.Println("  Creating valid_cert.pem and valid_key.pem...")

	key, cert := createCert(certConfig{
		callsign:      "W1TEST",
		operatorName:  "TEST OPERATOR",
		dxcc:          291,
		qsoNotBefore:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		qsoNotAfter:   time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		certNotBefore: time.Now().Add(-24 * time.Hour),
		certNotAfter:  time.Now().Add(365 * 24 * time.Hour),
		serialNumber:  1001,
	})

	writePEM(filepath.Join(dir, "valid_cert.pem"), "CERTIFICATE", cert.Raw)
	writeKeyPEM(filepath.Join(dir, "valid_key.pem"), key)
}

func generateExpiredCert(dir string) {
	fmt.Println("  Creating expired_cert.pem and expired_key.pem...")

	key, cert := createCert(certConfig{
		callsign:      "W1EXPIRED",
		operatorName:  "EXPIRED OPERATOR",
		dxcc:          291,
		qsoNotBefore:  time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		qsoNotAfter:   time.Date(2020, 12, 31, 0, 0, 0, 0, time.UTC),
		certNotBefore: time.Now().Add(-730 * 24 * time.Hour), // 2 years ago
		certNotAfter:  time.Now().Add(-365 * 24 * time.Hour), // 1 year ago (expired)
		serialNumber:  1002,
	})

	writePEM(filepath.Join(dir, "expired_cert.pem"), "CERTIFICATE", cert.Raw)
	writeKeyPEM(filepath.Join(dir, "expired_key.pem"), key)
}

func generateFullHamCert(dir string) {
	fmt.Println("  Creating full_ham_cert.pem and full_ham_key.pem...")

	// Using USPS sample address data (https://www.usps.com/) and fake email
	key, cert := createCert(certConfig{
		callsign:      "N0CALL",
		operatorName:  "JANE Q HAMOPERATOR",
		email:         "ham@example.com",
		dxcc:          291,
		qsoNotBefore:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		qsoNotAfter:   time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		certNotBefore: time.Now().Add(-24 * time.Hour),
		certNotAfter:  time.Now().Add(365 * 24 * time.Hour),
		address1:      "123 Main St",
		city:          "Anytown",
		state:         "NY",
		postalCode:    "12345",
		country:       "USA",
		serialNumber:  1003,
	})

	writePEM(filepath.Join(dir, "full_ham_cert.pem"), "CERTIFICATE", cert.Raw)
	writeKeyPEM(filepath.Join(dir, "full_ham_key.pem"), key)
}

func generatePKCS12Files(dir string) {
	fmt.Println("  Creating PKCS12 files...")

	// With password
	key, cert := createCert(certConfig{
		callsign:      "K1P12",
		operatorName:  "PKCS12 TEST",
		dxcc:          291,
		certNotBefore: time.Now().Add(-24 * time.Hour),
		certNotAfter:  time.Now().Add(365 * 24 * time.Hour),
		serialNumber:  2001,
	})

	p12Data, err := pkcs12.Encode(rand.Reader, key, cert, nil, "testpassword")
	if err != nil {
		panic(err)
	}
	os.WriteFile(filepath.Join(dir, "with_password.p12"), p12Data, 0644)

	// Without password (empty string)
	p12Data, err = pkcs12.Encode(rand.Reader, key, cert, nil, "")
	if err != nil {
		panic(err)
	}
	os.WriteFile(filepath.Join(dir, "no_password.p12"), p12Data, 0644)
}

func generateTQ6Files(dir string) {
	fmt.Println("  Creating TQ6 files...")

	// Create a certificate for TQ6 files
	_, cert := createCert(certConfig{
		callsign:      "W1TQ6",
		operatorName:  "TQ6 TEST OPERATOR",
		dxcc:          291,
		certNotBefore: time.Now().Add(-24 * time.Hour),
		certNotAfter:  time.Now().Add(365 * 24 * time.Hour),
		serialNumber:  3001,
	})

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// Raw PEM format
	os.WriteFile(filepath.Join(dir, "raw_pem.tq6"), certPEM, 0644)

	// XML-embedded PEM format
	xmlData := fmt.Sprintf(`<?xml version="1.0"?>
<tQSL_Certificates>
  <Certificates>
%s
  </Certificates>
</tQSL_Certificates>
`, string(certPEM))
	os.WriteFile(filepath.Join(dir, "xml_embedded.tq6"), []byte(xmlData), 0644)

	// Gzip-compressed PEM
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	gz.Write(certPEM)
	gz.Close()
	os.WriteFile(filepath.Join(dir, "gzip_compressed.tq6"), gzBuf.Bytes(), 0644)

	// Gzip-compressed XML
	var gzXmlBuf bytes.Buffer
	gz2 := gzip.NewWriter(&gzXmlBuf)
	gz2.Write([]byte(xmlData))
	gz2.Close()
	os.WriteFile(filepath.Join(dir, "gzip_xml.tq6"), gzXmlBuf.Bytes(), 0644)
}

func generateMultiCertPEM(dir string) {
	fmt.Println("  Creating multi_cert.pem...")

	callsigns := []string{"W1AA", "W2BB", "K3CC"}
	var buf bytes.Buffer

	for i, call := range callsigns {
		_, cert := createCert(certConfig{
			callsign:      call,
			operatorName:  "OPERATOR " + call,
			dxcc:          291,
			certNotBefore: time.Now().Add(-24 * time.Hour),
			certNotAfter:  time.Now().Add(365 * 24 * time.Hour),
			serialNumber:  int64(4001 + i),
		})
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}

	os.WriteFile(filepath.Join(dir, "multi_cert.pem"), buf.Bytes(), 0644)
}

func generateTQ8Files(dir string) {
	fmt.Println("  Creating TQ8 certificate request files...")

	// Generate a private key for the CSR
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Build ham radio extensions for the CSR
	// Using sample data that matches our test expectations
	csrExtensions := []pkix.Extension{
		makeStringExt(oidCallsign, "N0CALL"),
		makeIntExt(oidDXCCEntity, 291),
		makeStringExt(oidQSONotBefore, "20200101"),
		makeStringExt(oidQSONotAfter, "20301231"),
		makeStringExt(oidCRQEmail, "csr@example.com"),
		makeStringExt(oidCRQAddress1, "123 Main St"),
		makeStringExt(oidCRQCity, "Anytown"),
		makeStringExt(oidCRQState, "NY"),
		makeStringExt(oidCRQPostal, "12345"),
		makeStringExt(oidCRQCountry, "USA"),
	}

	// Create a certificate signing request (CSR) with ham radio extensions
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "TEST OPERATOR",
			Country:    []string{"USA"},
		},
		EmailAddresses:  []string{"csr@example.com"},
		ExtraExtensions: csrExtensions,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		panic(err)
	}

	// Raw PEM CSR
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	os.WriteFile(filepath.Join(dir, "cert_request.tq8"), csrPEM, 0644)

	// Also write the key for the CSR
	writeKeyPEM(filepath.Join(dir, "cert_request_key.pem"), key)

	// XML-wrapped CSR (TQSL style)
	xmlCSR := fmt.Sprintf(`<?xml version="1.0"?>
<tQSL_CertRequest>
  <Request>
%s
  </Request>
</tQSL_CertRequest>
`, string(csrPEM))
	os.WriteFile(filepath.Join(dir, "cert_request_xml.tq8"), []byte(xmlCSR), 0644)

	// Gzip-compressed CSR
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	gz.Write(csrPEM)
	gz.Close()
	os.WriteFile(filepath.Join(dir, "cert_request_gzip.tq8"), gzBuf.Bytes(), 0644)
}

func generateInvalidFiles(dir string) {
	fmt.Println("  Creating invalid test files...")

	// Invalid PEM (not PEM format)
	os.WriteFile(filepath.Join(dir, "invalid_not_pem.pem"), []byte("This is not a PEM file"), 0644)

	// Invalid certificate (PEM format but corrupted data)
	invalidCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("corrupted certificate data"),
	})
	os.WriteFile(filepath.Join(dir, "invalid_corrupted_cert.pem"), invalidCert, 0644)

	// Invalid key (PEM format but corrupted data)
	invalidKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("corrupted key data"),
	})
	os.WriteFile(filepath.Join(dir, "invalid_corrupted_key.pem"), invalidKey, 0644)

	// TQ6 with no certificates
	os.WriteFile(filepath.Join(dir, "no_certs.tq6"), []byte("<xml>no certificates here</xml>"), 0644)

	// Corrupted gzip
	os.WriteFile(filepath.Join(dir, "corrupted_gzip.tq6"), []byte{0x1f, 0x8b, 0x00, 0x00, 0x00}, 0644)

	// Empty file
	os.WriteFile(filepath.Join(dir, "empty.pem"), []byte{}, 0644)
}

type certConfig struct {
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
	serialNumber  int64
}

func createCert(cfg certConfig) (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(cfg.serialNumber),
		Subject: pkix.Name{
			CommonName: cfg.operatorName,
		},
		NotBefore:             cfg.certNotBefore,
		NotAfter:              cfg.certNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{},
	}

	// Add callsign
	if cfg.callsign != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidCallsign, cfg.callsign))
	}

	// Add DXCC
	if cfg.dxcc != 0 {
		template.ExtraExtensions = append(template.ExtraExtensions, makeIntExt(oidDXCCEntity, cfg.dxcc))
	}

	// Add QSO dates
	if !cfg.qsoNotBefore.IsZero() {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidQSONotBefore, cfg.qsoNotBefore.Format("2006-01-02")))
	}
	if !cfg.qsoNotAfter.IsZero() {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidQSONotAfter, cfg.qsoNotAfter.Format("2006-01-02")))
	}

	// Add optional fields
	if cfg.email != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidCRQEmail, cfg.email))
	}
	if cfg.address1 != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidCRQAddress1, cfg.address1))
	}
	if cfg.city != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidCRQCity, cfg.city))
	}
	if cfg.state != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidCRQState, cfg.state))
	}
	if cfg.postalCode != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidCRQPostal, cfg.postalCode))
	}
	if cfg.country != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, makeStringExt(oidCRQCountry, cfg.country))
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}

	return key, cert
}

func makeStringExt(oid asn1.ObjectIdentifier, value string) pkix.Extension {
	data, _ := asn1.Marshal(value)
	return pkix.Extension{Id: oid, Value: data}
}

func makeIntExt(oid asn1.ObjectIdentifier, value int) pkix.Extension {
	data, _ := asn1.Marshal(value)
	return pkix.Extension{Id: oid, Value: data}
}

func writePEM(path, blockType string, data []byte) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}

func writeKeyPEM(path string, key *rsa.PrivateKey) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
