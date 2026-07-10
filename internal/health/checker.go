package health

import (
	"crypto/x509"
	"time"
)

// CertStatus represents the health status of an X.509 certificate
type CertStatus struct {
	Subject   string    `json:"subject"`
	NotAfter  time.Time `json:"notAfter"`
	DaysLeft  int       `json:"daysLeft"`
	IsExpired bool      `json:"isExpired"`
}

// CheckCert returns the health status of a certificate
func CheckCert(cert *x509.Certificate) CertStatus {
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	return CertStatus{
		Subject:   cert.Subject.CommonName,
		NotAfter:  cert.NotAfter,
		DaysLeft:  daysLeft,
		IsExpired: now.After(cert.NotAfter),
	}
}
