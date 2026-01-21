package hamsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Key size for generated RSA keys
const rsaKeySize = 2048

// OID definitions for certificate request extensions
var (
	oidBase = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1}

	oidCallsign     = append(append(asn1.ObjectIdentifier{}, oidBase...), 1)
	oidQSONotBefore = append(append(asn1.ObjectIdentifier{}, oidBase...), 2)
	oidQSONotAfter  = append(append(asn1.ObjectIdentifier{}, oidBase...), 3)
	oidDXCCEntity   = append(append(asn1.ObjectIdentifier{}, oidBase...), 4)
	oidCRQEmail     = append(append(asn1.ObjectIdentifier{}, oidBase...), 8)
	oidCRQAddress1  = append(append(asn1.ObjectIdentifier{}, oidBase...), 9)
	oidCRQAddress2  = append(append(asn1.ObjectIdentifier{}, oidBase...), 10)
	oidCRQCity      = append(append(asn1.ObjectIdentifier{}, oidBase...), 11)
	oidCRQState     = append(append(asn1.ObjectIdentifier{}, oidBase...), 12)
	oidCRQPostal    = append(append(asn1.ObjectIdentifier{}, oidBase...), 13)
	oidCRQCountry   = append(append(asn1.ObjectIdentifier{}, oidBase...), 14)
)

// CertificateRequest contains information for a new certificate request.
type CertificateRequest struct {
	Callsign     string
	Name         string
	Address1     string
	Address2     string
	City         string
	State        string
	PostalCode   string
	Country      string
	Email        string
	DXCC         int
	QSONotBefore time.Time
	QSONotAfter  time.Time
}

// GenerateRequest creates a new certificate request and RSA key pair.
// Returns the request in TQ5 format (PEM-encoded CSR) and the encrypted private key.
func GenerateRequest(req *CertificateRequest, password string) (tq5 []byte, encryptedKey []byte, err error) {
	if req == nil {
		return nil, nil, errors.New("request is nil")
	}
	if req.Callsign == "" {
		return nil, nil, errors.New("callsign is required")
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Build the CSR
	csr, err := buildCSR(req, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode CSR as PEM (TQ5 format)
	tq5 = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	// Encrypt and encode private key
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	//nolint:staticcheck // SA1019: x509.EncryptPEMBlock required for TQSL compatibility
	encryptedBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		keyBytes,
		[]byte(password),
		x509.PEMCipherAES256,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	encryptedKey = pem.EncodeToMemory(encryptedBlock)

	return tq5, encryptedKey, nil
}

// RenewRequest creates a renewal request signed by an existing certificate.
// The renewal request references the existing certificate to prove identity.
func RenewRequest(req *CertificateRequest, signingCert *x509.Certificate, signingKey crypto.PrivateKey, password string) (tq5 []byte, encryptedKey []byte, err error) {
	if req == nil {
		return nil, nil, errors.New("request is nil")
	}
	if signingCert == nil {
		return nil, nil, errors.New("signing certificate is nil")
	}
	if signingKey == nil {
		return nil, nil, errors.New("signing key is nil")
	}

	// Generate new RSA key pair for the renewed certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Build the CSR with the new key
	csr, err := buildCSR(req, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Sign the CSR with the existing certificate's key to prove identity
	// This creates a self-signed renewal request
	rsaSigningKey, ok := signingKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("signing key is not RSA")
	}

	// Create signature over the CSR
	hash := sha1Hash(csr)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaSigningKey, crypto.SHA1, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign renewal request: %w", err)
	}

	// Encode CSR as PEM with renewal signature attribute
	tq5Block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
		Headers: map[string]string{
			"X-Renewal-Signature": encodeBase64(signature),
			"X-Renewal-Serial":    signingCert.SerialNumber.String(),
		},
	}
	tq5 = pem.EncodeToMemory(tq5Block)

	// Encrypt and encode private key
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	//nolint:staticcheck // SA1019: x509.EncryptPEMBlock required for TQSL compatibility
	encryptedBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		keyBytes,
		[]byte(password),
		x509.PEMCipherAES256,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	encryptedKey = pem.EncodeToMemory(encryptedBlock)

	return tq5, encryptedKey, nil
}

// buildCSR creates an X.509 certificate signing request.
func buildCSR(req *CertificateRequest, key *rsa.PrivateKey) ([]byte, error) {
	// Build extra extensions for amateur radio fields
	var extraExtensions []pkix.Extension

	// Callsign (required)
	if ext, err := makeStringExtension(oidCallsign, req.Callsign); err == nil {
		extraExtensions = append(extraExtensions, ext)
	}

	// DXCC Entity
	if req.DXCC > 0 {
		if ext, err := makeIntExtension(oidDXCCEntity, req.DXCC); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}

	// QSO date range
	if !req.QSONotBefore.IsZero() {
		if ext, err := makeDateExtension(oidQSONotBefore, req.QSONotBefore); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}
	if !req.QSONotAfter.IsZero() {
		if ext, err := makeDateExtension(oidQSONotAfter, req.QSONotAfter); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}

	// Email
	if req.Email != "" {
		if ext, err := makeStringExtension(oidCRQEmail, req.Email); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}

	// Address fields
	if req.Address1 != "" {
		if ext, err := makeStringExtension(oidCRQAddress1, req.Address1); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}
	if req.Address2 != "" {
		if ext, err := makeStringExtension(oidCRQAddress2, req.Address2); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}
	if req.City != "" {
		if ext, err := makeStringExtension(oidCRQCity, req.City); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}
	if req.State != "" {
		if ext, err := makeStringExtension(oidCRQState, req.State); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}
	if req.PostalCode != "" {
		if ext, err := makeStringExtension(oidCRQPostal, req.PostalCode); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}
	if req.Country != "" {
		if ext, err := makeStringExtension(oidCRQCountry, req.Country); err == nil {
			extraExtensions = append(extraExtensions, ext)
		}
	}

	// Build subject
	subject := pkix.Name{
		CommonName: req.Name,
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA1WithRSA,
		ExtraExtensions:    extraExtensions,
	}

	if req.Email != "" {
		template.EmailAddresses = []string{req.Email}
	}

	// Generate CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return csr, nil
}

// makeStringExtension creates an extension with a string value.
func makeStringExtension(oid asn1.ObjectIdentifier, value string) (pkix.Extension, error) {
	val, err := asn1.Marshal(value)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    oid,
		Value: val,
	}, nil
}

// makeIntExtension creates an extension with an integer value.
func makeIntExtension(oid asn1.ObjectIdentifier, value int) (pkix.Extension, error) {
	val, err := asn1.Marshal(value)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    oid,
		Value: val,
	}, nil
}

// makeDateExtension creates an extension with a date value (YYYYMMDD format).
func makeDateExtension(oid asn1.ObjectIdentifier, t time.Time) (pkix.Extension, error) {
	dateStr := t.Format("20060102")
	return makeStringExtension(oid, dateStr)
}

// sha1Hash computes SHA-1 hash of data.
func sha1Hash(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// encodeBase64 encodes data to base64 string.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
