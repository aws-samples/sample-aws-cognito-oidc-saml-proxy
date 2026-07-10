package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)
	entityID := "https://example.com/saml/idp"

	cert, err := GenerateSelfSignedCert(signer, entityID)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify Subject CN matches entityID
	assert.Equal(t, entityID, cert.Subject.CommonName)

	// Verify serial number is non-zero
	assert.NotNil(t, cert.SerialNumber)
	assert.True(t, cert.SerialNumber.Sign() > 0, "Serial number should be positive")

	// Verify validity period (approximately 2 years)
	now := time.Now()
	assert.True(t, cert.NotBefore.Before(now) || cert.NotBefore.Equal(now))
	assert.True(t, cert.NotAfter.After(now))

	duration := cert.NotAfter.Sub(cert.NotBefore)
	expectedDuration := 2 * 365 * 24 * time.Hour
	tolerance := 24 * time.Hour
	assert.InDelta(t, expectedDuration, duration, float64(tolerance),
		"Validity period should be approximately 2 years")

	// Verify KeyUsage includes DigitalSignature
	assert.True(t, cert.KeyUsage&x509.KeyUsageDigitalSignature != 0,
		"KeyUsage should include DigitalSignature")

	// Verify it's self-signed (Issuer == Subject)
	assert.Equal(t, cert.Subject.String(), cert.Issuer.String())

	// Verify public key matches signer's public key
	assert.Equal(t, signer.Public(), cert.PublicKey)
}

func TestGenerateSelfSignedCert_UniqueSerials(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)
	entityID := "https://example.com/saml/idp"

	// Generate two certificates
	cert1, err := GenerateSelfSignedCert(signer, entityID)
	require.NoError(t, err)

	cert2, err := GenerateSelfSignedCert(signer, entityID)
	require.NoError(t, err)

	// Serial numbers should be different
	assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber,
		"Each certificate should have a unique serial number")
}

func TestCertToPEM(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)
	cert, err := GenerateSelfSignedCert(signer, "https://example.com/saml/idp")
	require.NoError(t, err)

	pemData := CertToPEM(cert)
	require.NotEmpty(t, pemData)

	// Verify it's valid PEM format
	block, rest := pem.Decode(pemData)
	require.NotNil(t, block, "Should decode to a PEM block")
	assert.Empty(t, rest, "Should not have trailing data")
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, cert.Raw, block.Bytes)
}

func TestPEMToCert(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)
	originalCert, err := GenerateSelfSignedCert(signer, "https://example.com/saml/idp")
	require.NoError(t, err)

	pemData := CertToPEM(originalCert)

	// Parse back from PEM
	parsedCert, err := PEMToCert(pemData)
	require.NoError(t, err)
	require.NotNil(t, parsedCert)

	// Verify the parsed certificate matches the original
	assert.Equal(t, originalCert.Subject.CommonName, parsedCert.Subject.CommonName)
	assert.Equal(t, originalCert.SerialNumber, parsedCert.SerialNumber)
	assert.Equal(t, originalCert.NotBefore.Unix(), parsedCert.NotBefore.Unix())
	assert.Equal(t, originalCert.NotAfter.Unix(), parsedCert.NotAfter.Unix())
	assert.Equal(t, originalCert.KeyUsage, parsedCert.KeyUsage)
}

func TestPEMToCert_RoundTrip(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)
	cert1, err := GenerateSelfSignedCert(signer, "https://example.com/saml/idp")
	require.NoError(t, err)

	// Convert to PEM and back
	pemData := CertToPEM(cert1)
	cert2, err := PEMToCert(pemData)
	require.NoError(t, err)

	// Convert to PEM again
	pemData2 := CertToPEM(cert2)

	// PEM data should be identical
	assert.Equal(t, pemData, pemData2)
}

func TestPEMToCert_InvalidPEM(t *testing.T) {
	invalidPEM := []byte("not a PEM certificate")
	cert, err := PEMToCert(invalidPEM)
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestPEMToCert_InvalidCertificate(t *testing.T) {
	// Valid PEM block but invalid certificate data
	invalidPEM := []byte(`-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----`)

	cert, err := PEMToCert(invalidPEM)
	assert.Error(t, err)
	assert.Nil(t, cert)
}
