package service

import (
	"context"
	"fmt"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
)

// Certificate roles managed by CertManager.
const (
	RoleActive = "active"
	RoleBackup = "backup"
)

// ManagedCert describes a stored signing certificate and its provenance for the
// management API.
type ManagedCert struct {
	Role     string
	Source   string
	KMSKeyID string
	Info     *CertInfo
}

// CertManager handles the certificate lifecycle operations exposed by the
// management API: generating CSRs for an external CA, importing CA-issued
// leaf certificates, promoting the backup certificate, and listing certs.
//
// It keeps the private keys in KMS (the signers wrap KMS keys) and only ever
// stores public certificate material.
type CertManager struct {
	store         *crypto.CertStore
	primarySigner *crypto.KMSSigner
	backupSigner  *crypto.KMSSigner
	primaryKeyID  string
	backupKeyID   string
	entityID      string
}

// CertManagerConfig configures a CertManager. backupSigner/backupKeyID may be
// nil/empty, in which case the backup certificate role reuses the primary key
// (certificate renewal only, no key roll).
type CertManagerConfig struct {
	Store         *crypto.CertStore
	PrimarySigner *crypto.KMSSigner
	BackupSigner  *crypto.KMSSigner
	PrimaryKeyID  string
	BackupKeyID   string
	EntityID      string
}

// NewCertManager creates a CertManager.
func NewCertManager(cfg CertManagerConfig) *CertManager {
	return &CertManager{
		store:         cfg.Store,
		primarySigner: cfg.PrimarySigner,
		backupSigner:  cfg.BackupSigner,
		primaryKeyID:  cfg.PrimaryKeyID,
		backupKeyID:   cfg.BackupKeyID,
		entityID:      cfg.EntityID,
	}
}

// signerForRole returns the signer and KMS key id for a given role. The backup
// role falls back to the primary key when no dedicated backup key is configured.
func (m *CertManager) signerForRole(role string) (*crypto.KMSSigner, string, error) {
	switch role {
	case RoleActive:
		return m.primarySigner, m.primaryKeyID, nil
	case RoleBackup:
		if m.backupSigner != nil {
			return m.backupSigner, m.backupKeyID, nil
		}
		// No dedicated backup key configured: reuse primary.
		return m.primarySigner, m.primaryKeyID, nil
	default:
		return nil, "", fmt.Errorf("invalid certificate role %q", role)
	}
}

// GenerateCSR returns a PEM-encoded certificate signing request for the given
// role's KMS key, to be signed by an external corporate CA.
func (m *CertManager) GenerateCSR(role string) ([]byte, error) {
	signer, _, err := m.signerForRole(role)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, fmt.Errorf("no signing key available for role %q", role)
	}
	return crypto.GenerateCSR(signer, m.entityID)
}

// Import validates and stores a CA-issued leaf certificate for the given role.
// The leaf's public key must match the role's KMS key (pin-the-leaf): otherwise
// the KMS-held private key could not produce signatures that validate against
// the certificate.
func (m *CertManager) Import(ctx context.Context, role string, certPEM []byte) (*ManagedCert, error) {
	signer, keyID, err := m.signerForRole(role)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, fmt.Errorf("no signing key available for role %q", role)
	}

	chain, err := crypto.ParseCertChainPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}
	leaf := chain[0]

	match, err := crypto.PublicKeyMatchesSigner(leaf, signer)
	if err != nil {
		return nil, fmt.Errorf("cannot verify certificate key: %w", err)
	}
	if !match {
		return nil, fmt.Errorf("certificate public key does not match the %s signing key; the CA must sign the CSR generated for this key", role)
	}

	meta := crypto.CertMeta{Source: crypto.SourceCAIssued, KMSKeyID: keyID}
	switch role {
	case RoleActive:
		if err := m.store.StoreActiveCertMeta(ctx, leaf, meta); err != nil {
			return nil, fmt.Errorf("failed to store active certificate: %w", err)
		}
	case RoleBackup:
		if err := m.store.StoreBackupCertMeta(ctx, leaf, meta); err != nil {
			return nil, fmt.Errorf("failed to store backup certificate: %w", err)
		}
	}

	return &ManagedCert{
		Role:     role,
		Source:   crypto.SourceCAIssued,
		KMSKeyID: keyID,
		Info:     BuildCertInfo(leaf),
	}, nil
}

// PromoteBackup promotes the standby backup certificate to active.
func (m *CertManager) PromoteBackup(ctx context.Context) error {
	return m.store.PromoteBackupToActive(ctx)
}

// List returns the active and backup certificates (when present) with metadata.
func (m *CertManager) List(ctx context.Context) ([]ManagedCert, error) {
	var out []ManagedCert

	if rec, err := m.store.GetActiveCertRecord(ctx); err == nil {
		out = append(out, ManagedCert{
			Role:     RoleActive,
			Source:   defaultSource(rec.Source),
			KMSKeyID: rec.KMSKeyID,
			Info:     BuildCertInfo(rec.Certificate),
		})
	}
	if rec, err := m.store.GetBackupCertRecord(ctx); err == nil {
		out = append(out, ManagedCert{
			Role:     RoleBackup,
			Source:   defaultSource(rec.Source),
			KMSKeyID: rec.KMSKeyID,
			Info:     BuildCertInfo(rec.Certificate),
		})
	}
	return out, nil
}

// HasBackupKey reports whether a dedicated backup signing key is configured.
func (m *CertManager) HasBackupKey() bool {
	return m.backupSigner != nil && m.backupKeyID != ""
}

func defaultSource(s string) string {
	if s == "" {
		return crypto.SourceSelfSigned
	}
	return s
}
