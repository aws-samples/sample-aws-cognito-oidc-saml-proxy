package crypto

import (
	"context"
	"crypto/x509"
)

// SelectActiveSigner returns the signer whose KMS key matches the active
// certificate, along with the active certificate and the key id in use.
//
// The active cert record carries the KMS key id its public key belongs to.
// When that id is empty (legacy/self-signed certs stored before dual-key
// support), the primary key id is used. newSigner builds a KMSSigner for a
// given key id (typically wrapping a fresh AWS KMS client).
//
// This makes promotion of a backup certificate backed by a different KMS key
// fully functional: the signing path follows the active certificate's key
// rather than always using the primary key.
func SelectActiveSigner(
	ctx context.Context,
	store *CertStore,
	primaryKeyID string,
	newSigner func(keyID string) *KMSSigner,
) (*KMSSigner, *x509.Certificate, string, error) {
	rec, err := store.GetActiveCertRecord(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	keyID := primaryKeyID
	if rec.KMSKeyID != "" {
		keyID = rec.KMSKeyID
	}
	return newSigner(keyID), rec.Certificate, keyID, nil
}
