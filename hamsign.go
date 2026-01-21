// Package hamsign provides digital signing for amateur radio certificates.
//
// This package handles X.509 certificate operations including loading,
// signing, verification, and export. It includes embedded CA certificates
// for offline operation with an option to override them at runtime.
//
// Basic usage:
//
//	// Load certificate and key from PKCS#12 file
//	cert, key, err := hamsign.LoadPKCS12(data, "password")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create a signer
//	signer, err := hamsign.NewSigner(cert, key, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Sign data
//	signature, err := signer.Sign([]byte("data to sign"))
package hamsign

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/radiolabme/hamsign/hamcert"
	"software.sslmate.com/src/go-pkcs12"
)

//go:embed certs/root.pem
var defaultRootPEM []byte

//go:embed certs/intermediate.pem
var defaultIntermediatePEM []byte

// ExpiryPolicy controls how certificate expiration is handled during verification.
type ExpiryPolicy int

const (
	// ExpiryPolicyStrict fails verification if any certificate in the chain has expired.
	ExpiryPolicyStrict ExpiryPolicy = iota

	// ExpiryPolicyIgnoreCA ignores expiration on root and intermediate certificates,
	// but enforces expiration on the user certificate. This is the default to maintain
	// compatibility with existing deployments using older CA certificates.
	ExpiryPolicyIgnoreCA

	// ExpiryPolicyIgnoreAll ignores expiration on all certificates in the chain.
	ExpiryPolicyIgnoreAll
)

// VerifyOptions controls certificate chain verification.
type VerifyOptions struct {
	// Roots is the set of trusted root certificates.
	// If nil, DefaultRoots() is used.
	Roots *x509.CertPool

	// Intermediates is the set of intermediate certificates.
	// If nil, DefaultIntermediates() is used.
	Intermediates *x509.CertPool

	// Expiry controls how certificate expiration is handled.
	// Default is ExpiryPolicyIgnoreCA.
	Expiry ExpiryPolicy
}

// DefaultRoots returns a CertPool containing the embedded root CA.
func DefaultRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(defaultRootPEM)
	return pool
}

// DefaultIntermediates returns a CertPool containing the embedded intermediate CA.
func DefaultIntermediates() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(defaultIntermediatePEM)
	return pool
}

// Signer signs data using an X.509 certificate and private key.
type Signer struct {
	cert          *x509.Certificate
	key           crypto.PrivateKey
	roots         *x509.CertPool
	intermediates *x509.CertPool
	expiryPolicy  ExpiryPolicy
}

// NewSigner creates a Signer with the given user certificate and private key.
// If opts is nil, embedded CA certificates are used with ExpiryPolicyIgnoreCA.
func NewSigner(cert *x509.Certificate, key crypto.PrivateKey, opts *VerifyOptions) (*Signer, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}
	if key == nil {
		return nil, errors.New("private key is nil")
	}

	s := &Signer{
		cert:          cert,
		key:           key,
		roots:         DefaultRoots(),
		intermediates: DefaultIntermediates(),
		expiryPolicy:  ExpiryPolicyIgnoreCA,
	}

	if opts != nil {
		if opts.Roots != nil {
			s.roots = opts.Roots
		}
		if opts.Intermediates != nil {
			s.intermediates = opts.Intermediates
		}
		s.expiryPolicy = opts.Expiry
	}

	return s, nil
}

// Sign signs the given data and returns the signature.
// Uses SHA-1 with RSA for compatibility with existing systems.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	rsaKey, ok := s.key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	hash := sha1.Sum(data)
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA1, hash[:])
}

// Verify verifies a signature against the given data using the certificate's public key.
func (s *Signer) Verify(data, signature []byte) error {
	rsaKey, ok := s.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("certificate public key is not RSA")
	}

	hash := sha1.Sum(data)
	return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA1, hash[:], signature)
}

// Certificate returns the signer's certificate.
func (s *Signer) Certificate() *x509.Certificate {
	return s.cert
}

// VerifyChain verifies the certificate chain according to the configured options.
func (s *Signer) VerifyChain() error {
	opts := x509.VerifyOptions{
		Roots:         s.roots,
		Intermediates: s.intermediates,
	}

	// Handle expiry policy
	switch s.expiryPolicy {
	case ExpiryPolicyIgnoreCA, ExpiryPolicyIgnoreAll:
		// Set CurrentTime to within the validity period for verification
		// This effectively ignores expiration during chain building
		opts.CurrentTime = s.cert.NotBefore.Add(time.Hour)
	}

	_, err := s.cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// For ExpiryPolicyIgnoreCA, still check user cert expiration
	if s.expiryPolicy == ExpiryPolicyIgnoreCA || s.expiryPolicy == ExpiryPolicyStrict {
		if IsExpired(s.cert) {
			return errors.New("user certificate has expired")
		}
	}

	return nil
}

// LoadPKCS12 loads a certificate and private key from PKCS#12 data.
// If the PKCS#12 file contains CA certificates, they are ignored.
func LoadPKCS12(data []byte, password string) (*x509.Certificate, crypto.PrivateKey, error) {
	// Use DecodeChain to handle PKCS#12 files that include CA certificates
	key, cert, _, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode PKCS#12: %w", err)
	}
	return cert, key, nil
}

// LoadPEM loads a certificate and private key from PEM-encoded data.
func LoadPEM(certPEM, keyPEM []byte) (*x509.Certificate, crypto.PrivateKey, error) {
	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, errors.New("failed to decode private key PEM")
	}

	var key crypto.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return cert, key, nil
}

// LoadTQ6 loads certificates from a TQ6 file.
// TQ6 files may be gzip-compressed XML containing PEM certificates,
// or concatenated PEM certificates directly.
func LoadTQ6(data []byte) ([]*x509.Certificate, error) {
	// Check for gzip magic bytes and decompress if needed
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() { _ = gr.Close() }()

		data, err = io.ReadAll(gr)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress TQ6: %w", err)
		}
	}

	var certs []*x509.Certificate

	// TQ6 files can contain PEM certs embedded in XML or as raw PEM
	// Search for all PEM certificate blocks in the data
	remaining := data
	for {
		// Find the start of a PEM block
		idx := bytes.Index(remaining, []byte("-----BEGIN CERTIFICATE-----"))
		if idx == -1 {
			break
		}
		remaining = remaining[idx:]

		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in TQ6 data")
	}

	return certs, nil
}

// LoadTQ8 loads a certificate signing request from a TQ8 file.
// TQ8 files may be gzip-compressed XML containing a PEM CSR,
// or a PEM CSR directly.
func LoadTQ8(data []byte) (*x509.CertificateRequest, error) {
	// Check for gzip magic bytes and decompress if needed
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() { _ = gr.Close() }()

		data, err = io.ReadAll(gr)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress gzip data: %w", err)
		}
	}

	// Find the CSR PEM block
	remaining := data
	for {
		// Find the start of a PEM block
		idx := bytes.Index(remaining, []byte("-----BEGIN CERTIFICATE REQUEST-----"))
		if idx == -1 {
			break
		}
		remaining = remaining[idx:]

		block, _ := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE REQUEST" {
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate request: %w", err)
			}
			return csr, nil
		}
	}

	return nil, errors.New("no certificate request found in TQ8 data")
}

// ExportPKCS12 exports a certificate and private key to PKCS#12 format.
// Uses legacy encoding for compatibility with TQSL and other existing tools.
func ExportPKCS12(cert *x509.Certificate, key crypto.PrivateKey, password string) ([]byte, error) {
	return pkcs12.Legacy.Encode(key, cert, nil, password)
}

// IsExpired checks if a certificate has expired.
func IsExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

// QSODateRangeValid checks if a QSO date falls within the certificate's allowed range.
func QSODateRangeValid(cert *x509.Certificate, qsoDate time.Time) bool {
	info, err := hamcert.ParseStationInfo(cert)
	if err != nil {
		return false
	}

	// If no QSO date range is specified, any date is valid
	if info.QSONotBefore.IsZero() && info.QSONotAfter.IsZero() {
		return true
	}

	// Check bounds
	if !info.QSONotBefore.IsZero() && qsoDate.Before(info.QSONotBefore) {
		return false
	}
	if !info.QSONotAfter.IsZero() && qsoDate.After(info.QSONotAfter) {
		return false
	}

	return true
}

// Re-export hamcert types for convenience
type (
	StationInfo    = hamcert.StationInfo
	RequestAddress = hamcert.RequestAddress
)

// Re-export hamcert functions
var (
	ParseStationInfo    = hamcert.ParseStationInfo
	ParseRequestAddress = hamcert.ParseRequestAddress
)
