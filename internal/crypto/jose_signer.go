package crypto

import (
	"crypto"
	"crypto/sha256"

	"github.com/go-jose/go-jose/v4"
)

// KMSJoseSigner implements jose.OpaqueSigner for AWS KMS keys.
// It delegates the actual cryptographic signing to a KMSSignerClient, allowing
// JWTs to be signed using keys stored in AWS KMS without exposing private key material.
type KMSJoseSigner struct {
	keyID     string
	client    KMSSignerClient
	publicJWK jose.JSONWebKey
}

// NewKMSJoseSigner creates a KMSJoseSigner that wraps a KMS key for use with go-jose.
// The keyID is used as the JWK kid (key identifier) in signed tokens.
func NewKMSJoseSigner(keyID string, client KMSSignerClient) (*KMSJoseSigner, error) {
	pub, err := client.PublicKey()
	if err != nil {
		return nil, err
	}
	jwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	return &KMSJoseSigner{keyID: keyID, client: client, publicJWK: jwk}, nil
}

// Public returns the public JWK for this signer. This is used by go-jose to
// populate the JWT header and by JWKS endpoints to advertise the verification key.
func (s *KMSJoseSigner) Public() *jose.JSONWebKey {
	return &s.publicJWK
}

// Algs returns the signing algorithms supported by this signer.
func (s *KMSJoseSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

// SignPayload signs the payload using the KMS key. go-jose calls this method
// during JWS creation; the payload is the compact-serialization header.payload
// bytes that need to be signed.
func (s *KMSJoseSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return s.client.Sign(digest[:], crypto.SHA256)
}
