package health

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCert generates a self-signed X.509 certificate for testing.
func createTestCert(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	return cert
}

func TestCheckCert_ValidCert(t *testing.T) {
	cert := createTestCert(t, "test.example.com",
		time.Now().Add(-1*time.Hour),
		time.Now().Add(365*24*time.Hour),
	)

	status := CheckCert(cert)

	assert.Equal(t, "test.example.com", status.Subject)
	assert.False(t, status.IsExpired)
	assert.Greater(t, status.DaysLeft, 0)
	assert.Equal(t, cert.NotAfter, status.NotAfter)
}

func TestCheckCert_ExpiredCert(t *testing.T) {
	cert := createTestCert(t, "expired.example.com",
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour),
	)

	status := CheckCert(cert)

	assert.Equal(t, "expired.example.com", status.Subject)
	assert.True(t, status.IsExpired)
	assert.Less(t, status.DaysLeft, 0)
}

func TestCheckCert_SubjectMatchesCN(t *testing.T) {
	cert := createTestCert(t, "my-service.internal",
		time.Now().Add(-1*time.Hour),
		time.Now().Add(30*24*time.Hour),
	)

	status := CheckCert(cert)

	assert.Equal(t, "my-service.internal", status.Subject)
}

func TestCheckCert_DaysLeftCalculation(t *testing.T) {
	// Certificate expires in exactly 10 days (roughly)
	cert := createTestCert(t, "ten-days.example.com",
		time.Now().Add(-1*time.Hour),
		time.Now().Add(10*24*time.Hour),
	)

	status := CheckCert(cert)

	// Should be approximately 10 days (allow for rounding)
	assert.InDelta(t, 10, status.DaysLeft, 1)
	assert.False(t, status.IsExpired)
}
