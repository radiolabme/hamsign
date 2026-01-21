package hamsign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
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

func TestNewSigner(t *testing.T) {
	cert, key := generateTestCert(t)

	t.Run("valid inputs", func(t *testing.T) {
		signer, err := NewSigner(cert, key, nil)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		if signer == nil {
			t.Fatal("signer is nil")
		}
		if signer.Certificate() != cert {
			t.Error("certificate mismatch")
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		_, err := NewSigner(nil, key, nil)
		if err == nil {
			t.Error("expected error for nil certificate")
		}
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := NewSigner(cert, nil, nil)
		if err == nil {
			t.Error("expected error for nil key")
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		opts := &VerifyOptions{
			Expiry: ExpiryPolicyStrict,
		}
		signer, err := NewSigner(cert, key, opts)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		if signer.expiryPolicy != ExpiryPolicyStrict {
			t.Error("expiry policy not set")
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	cert, key := generateTestCert(t)
	signer, err := NewSigner(cert, key, nil)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	data := []byte("test data to sign")

	t.Run("sign and verify", func(t *testing.T) {
		sig, err := signer.Sign(data)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("signature is empty")
		}

		err = signer.Verify(data, sig)
		if err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})

	t.Run("verify with wrong data", func(t *testing.T) {
		sig, _ := signer.Sign(data)
		err := signer.Verify([]byte("different data"), sig)
		if err == nil {
			t.Error("expected verification to fail with wrong data")
		}
	})

	t.Run("verify with corrupted signature", func(t *testing.T) {
		sig, _ := signer.Sign(data)
		sig[0] ^= 0xFF // corrupt first byte
		err := signer.Verify(data, sig)
		if err == nil {
			t.Error("expected verification to fail with corrupted signature")
		}
	})
}

func TestDefaultCertPools(t *testing.T) {
	t.Run("DefaultRoots", func(t *testing.T) {
		pool := DefaultRoots()
		if pool == nil {
			t.Fatal("DefaultRoots returned nil")
		}
	})

	t.Run("DefaultIntermediates", func(t *testing.T) {
		pool := DefaultIntermediates()
		if pool == nil {
			t.Fatal("DefaultIntermediates returned nil")
		}
	})
}

func TestIsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(time.Hour),
		}
		if IsExpired(cert) {
			t.Error("certificate should not be expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(-time.Hour),
		}
		if !IsExpired(cert) {
			t.Error("certificate should be expired")
		}
	})
}

func TestPKCS12RoundTrip(t *testing.T) {
	cert, key := generateTestCert(t)
	password := "testpassword"

	// Export
	p12, err := ExportPKCS12(cert, key, password)
	if err != nil {
		t.Fatalf("ExportPKCS12 failed: %v", err)
	}
	if len(p12) == 0 {
		t.Fatal("PKCS12 data is empty")
	}

	// Import
	loadedCert, loadedKey, err := LoadPKCS12(p12, password)
	if err != nil {
		t.Fatalf("LoadPKCS12 failed: %v", err)
	}

	// Verify certificate
	if loadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("certificate serial number mismatch")
	}

	// Verify key works for signing
	signer, err := NewSigner(loadedCert, loadedKey, nil)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	data := []byte("test")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if err := signer.Verify(data, sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}
