package service

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"
)

// CertInfo contains certificate status information.
type CertInfo struct {
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	Fingerprint   string
	DaysRemaining int
	IsExpired     bool
	PemBase64     string
}

// CertificateService provides certificate information and validation.
type CertificateService struct {
	certPEM []byte
}

// NewCertificateService creates a new certificate service with the given PEM-encoded certificate.
func NewCertificateService(certPEM []byte) *CertificateService {
	return &CertificateService{
		certPEM: certPEM,
	}
}

// GetInfo returns detailed information about the certificate.
func (s *CertificateService) GetInfo() (*CertInfo, error) {
	if len(s.certPEM) == 0 {
		return nil, fmt.Errorf("certificate not available")
	}

	// Parse PEM certificate
	block, _ := pem.Decode(s.certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return BuildCertInfo(cert), nil
}

// BuildCertInfo computes status information for a parsed certificate.
func BuildCertInfo(cert *x509.Certificate) *CertInfo {
	// Compute SHA-256 fingerprint
	hash := sha256.Sum256(cert.Raw)
	fingerprint := formatFingerprint(hash[:])

	// Calculate days remaining
	now := time.Now()
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)

	// Base64-encode DER for download
	pemBase64 := base64.StdEncoding.EncodeToString(cert.Raw)

	return &CertInfo{
		Subject:       cert.Subject.CommonName,
		Issuer:        cert.Issuer.CommonName,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		Fingerprint:   fingerprint,
		DaysRemaining: daysRemaining,
		IsExpired:     isExpired,
		PemBase64:     pemBase64,
	}
}

// formatFingerprint formats a hash as colon-separated hex (e.g., AB:CD:EF:...).
func formatFingerprint(hash []byte) string {
	result := ""
	for i, b := range hash {
		if i > 0 {
			result += ":"
		}
		result += fmt.Sprintf("%02X", b)
	}
	return result
}
