package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKMSClient implements KMSSignerClient using an in-memory RSA key pair
type mockKMSClient struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func newMockKMSClient() (*mockKMSClient, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &mockKMSClient{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

func (m *mockKMSClient) Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, m.privateKey, opts.HashFunc(), digest)
}

func (m *mockKMSClient) PublicKey() (*rsa.PublicKey, error) {
	return m.publicKey, nil
}

func TestKMSSigner_ImplementsCryptoSigner(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)

	// Verify that KMSSigner implements crypto.Signer interface
	var _ crypto.Signer = signer
}

func TestKMSSigner_Public(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)

	pubKey := signer.Public()
	require.NotNil(t, pubKey)

	// Verify it returns an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	require.True(t, ok, "Public key should be *rsa.PublicKey")
	assert.Equal(t, mockClient.publicKey, rsaPubKey)
}

func TestKMSSigner_PublicKeyCaching(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)

	// Call Public() multiple times
	pub1 := signer.Public()
	pub2 := signer.Public()

	// Should return the same cached instance
	assert.Same(t, pub1, pub2)
}

func TestKMSSigner_Sign(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)

	// Create a digest to sign
	message := []byte("test message")
	hash := sha256.Sum256(message)
	digest := hash[:]

	// Sign the digest
	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify the signature using the public key
	pubKey := signer.Public().(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
	assert.NoError(t, err, "Signature should be valid")
}

func TestKMSSigner_SignMultipleTimes(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer := NewKMSSigner(mockClient)

	message := []byte("test message")
	hash := sha256.Sum256(message)
	digest := hash[:]

	// Sign multiple times
	sig1, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	sig2, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	// Both signatures should be valid (but may differ due to randomness in signing)
	pubKey := signer.Public().(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, sig1)
	assert.NoError(t, err)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, sig2)
	assert.NoError(t, err)
}
