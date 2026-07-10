package oidc

import (
	"log/slog"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
)

// AddBackupVerificationKey advertises the non-active signing key(s) in the JWKS
// endpoint so relying parties can verify tokens signed by either key across a
// key roll. It publishes both the primary and backup KMS keys (whichever is not
// the active signing key); the active key is already published by KeySet.
//
// newSigner builds a KMSSigner for a key id (used only to obtain the public key).
func AddBackupVerificationKey(
	s *Storage,
	newSigner func(keyID string) *crypto.KMSSigner,
	primaryKeyID, backupKeyID, activeKeyID string,
) {
	for _, keyID := range []string{primaryKeyID, backupKeyID} {
		if keyID == "" || keyID == activeKeyID {
			continue
		}
		jose, err := crypto.NewKMSJoseSigner(keyID, newSigner(keyID).Client())
		if err != nil {
			slog.Warn("failed to load verification key for JWKS", "keyId", keyID, "error", err)
			continue
		}
		s.AddVerificationKey(keyID, jose.Public())
	}
}
