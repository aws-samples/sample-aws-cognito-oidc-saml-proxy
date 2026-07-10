package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestCertPEM generates a self-signed cert PEM for testing.
func makeTestCertPEM(t *testing.T, cn string, notBefore, notAfter time.Time) string {
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

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}

func TestValidatePEMCert_Valid(t *testing.T) {
	certPEM := makeTestCertPEM(t, "test.example.com",
		time.Now().Add(-1*time.Hour),
		time.Now().Add(365*24*time.Hour),
	)

	errs, warns := validatePEMCert(certPEM, "signing")
	assert.Empty(t, errs)
	assert.Empty(t, warns)
}

func TestValidatePEMCert_Expired(t *testing.T) {
	certPEM := makeTestCertPEM(t, "expired.example.com",
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour),
	)

	errs, _ := validatePEMCert(certPEM, "signing")
	assert.NotEmpty(t, errs)
	assert.Contains(t, errs[0], "signing certificate expired")
}

func TestValidatePEMCert_ExpiresSoon(t *testing.T) {
	certPEM := makeTestCertPEM(t, "expiring.example.com",
		time.Now().Add(-1*time.Hour),
		time.Now().Add(10*24*time.Hour), // expires in 10 days, within 30-day window
	)

	errs, warns := validatePEMCert(certPEM, "encryption")
	assert.Empty(t, errs)
	assert.NotEmpty(t, warns)
	assert.Contains(t, warns[0], "encryption certificate expires soon")
}

func TestValidatePEMCert_InvalidPEM(t *testing.T) {
	errs, warns := validatePEMCert("not valid PEM data", "signing")
	assert.NotEmpty(t, errs)
	assert.Contains(t, errs[0], "signing certificate is not valid PEM")
	assert.Empty(t, warns)
}

func TestToPEM(t *testing.T) {
	base64Data := "MIIBhTCCASmgAwIBAgIBADAK"
	result := toPEM(base64Data)
	assert.Contains(t, result, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, result, "-----END CERTIFICATE-----")
	assert.Contains(t, result, base64Data)
}

func TestToPEM_WithWhitespace(t *testing.T) {
	base64Data := "MIIB hTCC ASmg AwIB AgIB ADAK"
	result := toPEM(base64Data)
	assert.Contains(t, result, "-----BEGIN CERTIFICATE-----")
	// Whitespace should be stripped
	assert.Contains(t, result, "MIIBhTCCASmgAwIBAgIBADAK")
}

func TestSetBoolDefault(t *testing.T) {
	trueVal := true
	falseVal := false

	assert.True(t, setBoolDefault(&trueVal, false))
	assert.False(t, setBoolDefault(&falseVal, true))
	assert.True(t, setBoolDefault(nil, true))
	assert.False(t, setBoolDefault(nil, false))
}

func TestSetStringDefault(t *testing.T) {
	assert.Equal(t, "value", setStringDefault("value", "default"))
	assert.Equal(t, "default", setStringDefault("", "default"))
}

func TestSetIntDefault(t *testing.T) {
	assert.Equal(t, 42, setIntDefault(42, 10))
	assert.Equal(t, 10, setIntDefault(0, 10))
}
