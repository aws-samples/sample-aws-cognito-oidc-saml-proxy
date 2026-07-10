package crypto

import (
	"crypto"
	"crypto/rsa"
	"io"
	"sync"
)

// KMSSignerClient abstracts AWS KMS signing operations
type KMSSignerClient interface {
	// Sign signs the digest using the KMS key
	Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error)

	// PublicKey retrieves the public key from KMS
	PublicKey() (*rsa.PublicKey, error)
}

// KMSSigner implements crypto.Signer interface using AWS KMS
type KMSSigner struct {
	client    KMSSignerClient
	publicKey crypto.PublicKey
	once      sync.Once
	err       error
}

// NewKMSSigner creates a new KMSSigner
func NewKMSSigner(client KMSSignerClient) *KMSSigner {
	return &KMSSigner{
		client: client,
	}
}

// Client returns the underlying KMSSignerClient.
func (s *KMSSigner) Client() KMSSignerClient {
	return s.client
}

// Public returns the public key, caching it after the first call
func (s *KMSSigner) Public() crypto.PublicKey {
	s.once.Do(func() {
		s.publicKey, s.err = s.client.PublicKey()
	})
	if s.err != nil {
		// In a real implementation, we might want to handle this error differently
		// For now, return nil if there was an error
		return nil
	}
	return s.publicKey
}

// Sign signs the digest using KMS. The io.Reader parameter is ignored as KMS
// provides its own randomness source.
func (s *KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.client.Sign(digest, opts)
}
