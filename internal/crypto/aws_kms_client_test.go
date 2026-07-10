package crypto

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKMSAPI is a mock implementation of KMSClientAPI for unit testing.
type fakeKMSAPI struct {
	privateKey *rsa.PrivateKey
}

func newFakeKMSAPI(t *testing.T) *fakeKMSAPI {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &fakeKMSAPI{privateKey: key}
}

func (f *fakeKMSAPI) Sign(_ context.Context, params *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	// Sign the digest the same way real KMS would
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.privateKey, crypto.SHA256, params.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{
		Signature:        sig,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}, nil
}

func (f *fakeKMSAPI) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		PublicKey: der,
		KeySpec:   types.KeySpecRsa2048,
		KeyUsage:  types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	}, nil
}

func TestAWSKMSClient_ImplementsInterface(t *testing.T) {
	// Compile-time check that AWSKMSClient implements KMSSignerClient
	var _ KMSSignerClient = (*AWSKMSClient)(nil)
}

func TestAWSKMSClient_Sign(t *testing.T) {
	fake := newFakeKMSAPI(t)
	client := NewAWSKMSClientFromAPI(fake, "test-key-id")

	message := []byte("test message to sign")
	hash := sha256.Sum256(message)
	digest := hash[:]

	sig, err := client.Sign(digest, crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Verify the signature with the public key
	err = rsa.VerifyPKCS1v15(&fake.privateKey.PublicKey, crypto.SHA256, digest, sig)
	assert.NoError(t, err, "signature should be valid")
}

func TestAWSKMSClient_PublicKey(t *testing.T) {
	fake := newFakeKMSAPI(t)
	client := NewAWSKMSClientFromAPI(fake, "test-key-id")

	pub, err := client.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, pub)

	// Verify the returned key matches the fake's key
	assert.Equal(t, fake.privateKey.N, pub.N)
	assert.Equal(t, fake.privateKey.E, pub.E)
}

func TestAWSKMSClient_SignAndVerifyRoundTrip(t *testing.T) {
	fake := newFakeKMSAPI(t)
	client := NewAWSKMSClientFromAPI(fake, "test-key-id")

	// Get the public key
	pub, err := client.PublicKey()
	require.NoError(t, err)

	// Sign a message
	message := []byte("round trip test message")
	hash := sha256.Sum256(message)
	digest := hash[:]

	sig, err := client.Sign(digest, crypto.SHA256)
	require.NoError(t, err)

	// Verify signature with the returned public key
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	assert.NoError(t, err, "round-trip sign/verify should succeed")
}

func TestAWSKMSClient_WithKMSSigner(t *testing.T) {
	fake := newFakeKMSAPI(t)
	client := NewAWSKMSClientFromAPI(fake, "test-key-id")

	// Wire the AWSKMSClient through KMSSigner
	signer := NewKMSSigner(client)

	// Verify it works as a crypto.Signer
	var _ crypto.Signer = signer

	pubKey := signer.Public()
	require.NotNil(t, pubKey)

	rsaPub, ok := pubKey.(*rsa.PublicKey)
	require.True(t, ok)

	// Sign through the KMSSigner
	message := []byte("signer integration test")
	hash := sha256.Sum256(message)
	digest := hash[:]

	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest, sig)
	assert.NoError(t, err)
}
