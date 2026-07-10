package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-certificate",
		},
		Issuer: pkix.Name{
			CommonName: "test-issuer",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return certPEM
}

func TestCertificateService_GetInfo(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(30 * 24 * time.Hour) // 30 days

	certPEM := generateTestCert(t, notBefore, notAfter)
	svc := NewCertificateService(certPEM)

	info, err := svc.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	if info.Subject != "test-certificate" {
		t.Errorf("expected subject=test-certificate, got %s", info.Subject)
	}

	// Self-signed certificate has same issuer as subject
	if info.Issuer != "test-certificate" {
		t.Errorf("expected issuer=test-certificate, got %s", info.Issuer)
	}

	if info.IsExpired {
		t.Error("certificate should not be expired")
	}

	// Days remaining should be approximately 30 (allow ±1 for timing)
	if info.DaysRemaining < 29 || info.DaysRemaining > 31 {
		t.Errorf("expected daysRemaining~30, got %d", info.DaysRemaining)
	}

	// Verify fingerprint format (SHA-256 should be 64 hex chars + 31 colons)
	if len(info.Fingerprint) != 95 {
		t.Errorf("expected fingerprint length=95, got %d", len(info.Fingerprint))
	}
	if !strings.Contains(info.Fingerprint, ":") {
		t.Error("fingerprint should contain colons")
	}

	// Verify PemBase64 is not empty
	if info.PemBase64 == "" {
		t.Error("PemBase64 should not be empty")
	}
}

func TestCertificateService_GetInfo_Expired(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(-24 * time.Hour) // Expired yesterday

	certPEM := generateTestCert(t, notBefore, notAfter)
	svc := NewCertificateService(certPEM)

	info, err := svc.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	if !info.IsExpired {
		t.Error("certificate should be expired")
	}

	if info.DaysRemaining > 0 {
		t.Errorf("expired cert should have negative or zero days remaining, got %d", info.DaysRemaining)
	}
}

func TestCertificateService_GetInfo_NoCertificate(t *testing.T) {
	svc := NewCertificateService(nil)

	_, err := svc.GetInfo()
	if err == nil {
		t.Fatal("expected error when certificate is not available")
	}
}

func TestCertificateService_GetInfo_InvalidPEM(t *testing.T) {
	svc := NewCertificateService([]byte("not a valid PEM"))

	_, err := svc.GetInfo()
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestFormatFingerprint(t *testing.T) {
	hash := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34}
	result := formatFingerprint(hash)

	expected := "AB:CD:EF:12:34"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}
