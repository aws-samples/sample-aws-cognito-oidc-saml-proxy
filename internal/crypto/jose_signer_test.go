package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKMSJoseSigner_Public(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer, err := NewKMSJoseSigner("test-key-id", mockClient)
	require.NoError(t, err)

	jwk := signer.Public()
	require.NotNil(t, jwk)

	assert.Equal(t, "test-key-id", jwk.KeyID)
	assert.Equal(t, string(jose.RS256), jwk.Algorithm)
	assert.Equal(t, "sig", jwk.Use)

	// Verify the public key is an RSA key matching the mock
	rsaKey, ok := jwk.Key.(*rsa.PublicKey)
	require.True(t, ok, "JWK key should be *rsa.PublicKey")
	assert.Equal(t, mockClient.publicKey, rsaKey)
}

func TestKMSJoseSigner_PublicJWKSerializable(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer, err := NewKMSJoseSigner("test-key-id", mockClient)
	require.NoError(t, err)

	jwk := signer.Public()

	// Verify the JWK can be serialized to JSON (required for JWKS endpoint)
	data, err := json.Marshal(jwk)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"kid":"test-key-id"`)
	assert.Contains(t, string(data), `"alg":"RS256"`)
	assert.Contains(t, string(data), `"use":"sig"`)
	assert.Contains(t, string(data), `"kty":"RSA"`)
}

func TestKMSJoseSigner_Algs(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer, err := NewKMSJoseSigner("test-key-id", mockClient)
	require.NoError(t, err)

	algs := signer.Algs()
	require.Len(t, algs, 1)
	assert.Equal(t, jose.RS256, algs[0])
}

func TestKMSJoseSigner_SignPayload(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	signer, err := NewKMSJoseSigner("test-key-id", mockClient)
	require.NoError(t, err)

	payload := []byte("test payload to sign")
	sig, err := signer.SignPayload(payload, jose.RS256)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Verify the signature is valid using the public key
	digest := sha256.Sum256(payload)
	err = rsa.VerifyPKCS1v15(mockClient.publicKey, crypto.SHA256, digest[:], sig)
	assert.NoError(t, err, "Signature produced by KMSJoseSigner should be verifiable")
}

func TestKMSJoseSigner_ProducesValidJWS(t *testing.T) {
	mockClient, err := newMockKMSClient()
	require.NoError(t, err)

	kmsSigner, err := NewKMSJoseSigner("test-key-id", mockClient)
	require.NoError(t, err)

	// Create a jose.Signer using the OpaqueSigner.
	// go-jose accepts any OpaqueSigner directly as the Key in SigningKey.
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: kmsSigner},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	// Sign a test payload
	payload := []byte(`{"sub":"user123","iss":"https://example.com"}`)
	jws, err := joseSigner.Sign(payload)
	require.NoError(t, err)

	// Serialize to compact form
	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	assert.NotEmpty(t, compact)

	// Verify the JWS using the public key
	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	verified, err := parsed.Verify(mockClient.publicKey)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}
