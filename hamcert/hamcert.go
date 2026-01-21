// Package hamcert provides parsing of amateur radio certificate extensions.
//
// This package extracts custom X.509 certificate extensions used by amateur
// radio digital signing systems. It can be used independently of the hamsign
// signing functionality.
package hamcert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// OID base: 1.3.6.1.4.1.12348.1
// This is the private enterprise number assigned for amateur radio QSL signing.
var (
	oidBase = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1}

	oidCallsign     = append(oidBase, 1)
	oidQSONotBefore = append(oidBase, 2)
	oidQSONotAfter  = append(oidBase, 3)
	oidDXCCEntity   = append(oidBase, 4)
	// Reserved OIDs (defined in spec but not yet implemented)
	_              = append(oidBase, 5) // superceded cert
	_              = append(oidBase, 6) // CRQ issuer org
	_              = append(oidBase, 7) // CRQ issuer OU
	oidCRQEmail    = append(oidBase, 8)
	oidCRQAddress1 = append(oidBase, 9)
	oidCRQAddress2 = append(oidBase, 10)
	oidCRQCity     = append(oidBase, 11)
	oidCRQState    = append(oidBase, 12)
	oidCRQPostal   = append(oidBase, 13)
	oidCRQCountry  = append(oidBase, 14)
)

// StationInfo contains amateur radio-specific certificate extensions.
type StationInfo struct {
	Callsign     string
	OperatorName string
	Email        string
	DXCC         int
	QSONotBefore time.Time
	QSONotAfter  time.Time
}

// RequestAddress contains the address from the certificate request.
type RequestAddress struct {
	Address1   string
	Address2   string
	City       string
	State      string
	PostalCode string
	Country    string
}

// ErrExtensionNotFound is returned when a required extension is not present.
var ErrExtensionNotFound = errors.New("extension not found")

// ParseStationInfo extracts amateur radio extensions from an X.509 certificate.
func ParseStationInfo(cert *x509.Certificate) (*StationInfo, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	info := &StationInfo{}

	// Extract callsign (required)
	// First try extensions, then check Subject DN for the callsign OID
	callsign, err := getExtensionString(cert, oidCallsign)
	if err != nil {
		// Check Subject DN for callsign OID
		callsign = getSubjectAttribute(cert, oidCallsign)
	}
	if callsign == "" {
		return nil, fmt.Errorf("callsign: %w", ErrExtensionNotFound)
	}
	info.Callsign = callsign

	// Extract operator name from subject CN
	if len(cert.Subject.CommonName) > 0 {
		info.OperatorName = cert.Subject.CommonName
	}

	// Extract email
	if email, err := getExtensionString(cert, oidCRQEmail); err == nil {
		info.Email = email
	} else if len(cert.EmailAddresses) > 0 {
		info.Email = cert.EmailAddresses[0]
	}

	// Extract DXCC entity
	if dxcc, err := getExtensionInt(cert, oidDXCCEntity); err == nil {
		info.DXCC = dxcc
	}

	// Extract QSO date range
	if notBefore, err := getExtensionDate(cert, oidQSONotBefore); err == nil {
		info.QSONotBefore = notBefore
	}
	if notAfter, err := getExtensionDate(cert, oidQSONotAfter); err == nil {
		info.QSONotAfter = notAfter
	}

	return info, nil
}

// ParseRequestAddress extracts the request address from an X.509 certificate.
func ParseRequestAddress(cert *x509.Certificate) (*RequestAddress, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	addr := &RequestAddress{}

	if v, err := getExtensionString(cert, oidCRQAddress1); err == nil {
		addr.Address1 = v
	}
	if v, err := getExtensionString(cert, oidCRQAddress2); err == nil {
		addr.Address2 = v
	}
	if v, err := getExtensionString(cert, oidCRQCity); err == nil {
		addr.City = v
	}
	if v, err := getExtensionString(cert, oidCRQState); err == nil {
		addr.State = v
	}
	if v, err := getExtensionString(cert, oidCRQPostal); err == nil {
		addr.PostalCode = v
	}
	if v, err := getExtensionString(cert, oidCRQCountry); err == nil {
		addr.Country = v
	}

	return addr, nil
}

// findExtension finds an extension by OID in the certificate.
func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return &ext
		}
	}
	return nil
}

// getSubjectAttribute finds an attribute in the Subject DN by OID.
// This handles cases where amateur radio OIDs are embedded in the Subject.
func getSubjectAttribute(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(oid) {
			if s, ok := name.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

// getExtensionString extracts a string value from an extension.
func getExtensionString(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	ext := findExtension(cert, oid)
	if ext == nil {
		return "", ErrExtensionNotFound
	}

	// Try to decode as ASN.1 string types
	var str string
	if _, err := asn1.Unmarshal(ext.Value, &str); err == nil {
		return str, nil
	}

	// Try as raw bytes (some implementations use OCTET STRING)
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(ext.Value, &raw); err == nil && len(raw.Bytes) > 0 {
		return string(raw.Bytes), nil
	}

	// Some TQSL certificates store values as raw ASCII without ASN.1 encoding
	// Check if the raw bytes appear to be printable ASCII
	if len(ext.Value) > 0 && isPrintableASCII(ext.Value) {
		return string(ext.Value), nil
	}

	return "", fmt.Errorf("unable to decode extension as string")
}

// isPrintableASCII checks if all bytes are printable ASCII characters.
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		// Allow printable ASCII (space through tilde) plus common special chars
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// getExtensionInt extracts an integer value from an extension.
func getExtensionInt(cert *x509.Certificate, oid asn1.ObjectIdentifier) (int, error) {
	ext := findExtension(cert, oid)
	if ext == nil {
		return 0, ErrExtensionNotFound
	}

	// Try to decode as ASN.1 integer
	var val int
	if _, err := asn1.Unmarshal(ext.Value, &val); err == nil {
		return val, nil
	}

	// Try as string and convert
	str, err := getExtensionString(cert, oid)
	if err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(str)); err == nil {
			return v, nil
		}
	}

	return 0, fmt.Errorf("unable to decode extension as integer")
}

// getExtensionDate extracts a date value from an extension.
// The date format used is YYYYMMDD.
func getExtensionDate(cert *x509.Certificate, oid asn1.ObjectIdentifier) (time.Time, error) {
	str, err := getExtensionString(cert, oid)
	if err != nil {
		return time.Time{}, err
	}

	// Parse YYYYMMDD format
	str = strings.TrimSpace(str)
	if len(str) == 8 {
		return time.Parse("20060102", str)
	}

	// Try ISO format
	if t, err := time.Parse("2006-01-02", str); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", str)
}
