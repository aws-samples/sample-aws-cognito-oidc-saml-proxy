package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCSR_ValidAndVerifiable(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)
	signer := NewKMSSigner(mockClient)

	csrPEM, err := GenerateCSR(signer, "https://idp.example.com")
	require.NoError(t, err)
	require.NotEmpty(t, csrPEM)

	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com", csr.Subject.CommonName)

	// The CSR self-signature must validate against the embedded (KMS) public key.
	require.NoError(t, csr.CheckSignature())
}

func TestGenerateCSR_NilSigner(t *testing.T) {
	_, err := GenerateCSR(nil, "https://idp.example.com")
	assert.Error(t, err)
}

func TestParseCertChainPEM_SingleAndMultiple(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)
	signer := NewKMSSigner(mockClient)

	leaf, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	single := CertToPEM(leaf)
	certs, err := ParseCertChainPEM(single)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, leaf.SerialNumber, certs[0].SerialNumber)

	// Two concatenated certs preserve order.
	other, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	chain := append(CertToPEM(leaf), CertToPEM(other)...)
	parsed, err := ParseCertChainPEM(chain)
	require.NoError(t, err)
	require.Len(t, parsed, 2)
	assert.Equal(t, leaf.SerialNumber, parsed[0].SerialNumber)
	assert.Equal(t, other.SerialNumber, parsed[1].SerialNumber)
}

func TestParseCertChainPEM_NoCert(t *testing.T) {
	_, err := ParseCertChainPEM([]byte("not a pem"))
	assert.Error(t, err)
}

func TestPublicKeyMatchesSigner_Match(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)
	signer := NewKMSSigner(mockClient)

	// A cert generated from this signer wraps the signer's public key.
	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	match, err := PublicKeyMatchesSigner(cert, signer)
	require.NoError(t, err)
	assert.True(t, match)
}

func TestPublicKeyMatchesSigner_Mismatch(t *testing.T) {
	client1, err := newMockKMSClient()
	require.NoError(t, err)
	signer1 := NewKMSSigner(client1)

	client2, err := newMockKMSClient()
	require.NoError(t, err)
	signer2 := NewKMSSigner(client2)

	// Cert wraps signer1's key; comparing against signer2 must not match.
	cert, err := GenerateSelfSignedCert(signer1, "https://idp.example.com")
	require.NoError(t, err)

	match, err := PublicKeyMatchesSigner(cert, signer2)
	require.NoError(t, err)
	assert.False(t, match)
}
