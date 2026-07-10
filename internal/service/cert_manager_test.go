package service

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaKMSMock implements crypto.KMSSignerClient with an in-memory RSA key.
type rsaKMSMock struct {
	key *rsa.PrivateKey
}

func newRSAKMSMock(t *testing.T) *rsaKMSMock {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &rsaKMSMock{key: key}
}

func (m *rsaKMSMock) Sign(digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, m.key, opts.HashFunc(), digest)
}

func (m *rsaKMSMock) PublicKey() (*rsa.PublicKey, error) {
	return &m.key.PublicKey, nil
}

func newTestCertManager(t *testing.T) (*CertManager, *crypto.CertStore, *crypto.KMSSigner, *crypto.KMSSigner) {
	t.Helper()
	cs := crypto.NewCertStore(store.NewMemoryDB())
	primary := crypto.NewKMSSigner(newRSAKMSMock(t))
	backup := crypto.NewKMSSigner(newRSAKMSMock(t))
	mgr := NewCertManager(CertManagerConfig{
		Store:         cs,
		PrimarySigner: primary,
		BackupSigner:  backup,
		PrimaryKeyID:  "primary-key",
		BackupKeyID:   "backup-key",
		EntityID:      "https://idp.example.com",
	})
	return mgr, cs, primary, backup
}

func TestCertManager_GenerateCSR_PerRole(t *testing.T) {
	mgr, _, _, _ := newTestCertManager(t)

	activeCSR, err := mgr.GenerateCSR(RoleActive)
	require.NoError(t, err)
	assert.Contains(t, string(activeCSR), "CERTIFICATE REQUEST")

	backupCSR, err := mgr.GenerateCSR(RoleBackup)
	require.NoError(t, err)
	assert.Contains(t, string(backupCSR), "CERTIFICATE REQUEST")
}

func TestCertManager_Import_MatchingKey(t *testing.T) {
	mgr, cs, primary, _ := newTestCertManager(t)
	ctx := context.Background()

	// A cert wrapping the primary KMS public key (stand-in for CA-issued leaf).
	leaf, err := crypto.GenerateSelfSignedCert(primary, "https://idp.example.com")
	require.NoError(t, err)

	mc, err := mgr.Import(ctx, RoleActive, crypto.CertToPEM(leaf))
	require.NoError(t, err)
	assert.Equal(t, RoleActive, mc.Role)
	assert.Equal(t, crypto.SourceCAIssued, mc.Source)

	rec, err := cs.GetActiveCertRecord(ctx)
	require.NoError(t, err)
	assert.Equal(t, crypto.SourceCAIssued, rec.Source)
	assert.Equal(t, "primary-key", rec.KMSKeyID)
}

func TestCertManager_Import_WrongKeyRejected(t *testing.T) {
	mgr, _, _, backup := newTestCertManager(t)
	ctx := context.Background()

	// Cert wraps the BACKUP key but is imported into the ACTIVE role -> reject.
	leaf, err := crypto.GenerateSelfSignedCert(backup, "https://idp.example.com")
	require.NoError(t, err)

	_, err = mgr.Import(ctx, RoleActive, crypto.CertToPEM(leaf))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestCertManager_PromoteBackup(t *testing.T) {
	mgr, cs, _, backup := newTestCertManager(t)
	ctx := context.Background()

	leaf, err := crypto.GenerateSelfSignedCert(backup, "https://idp.example.com")
	require.NoError(t, err)
	_, err = mgr.Import(ctx, RoleBackup, crypto.CertToPEM(leaf))
	require.NoError(t, err)

	require.NoError(t, mgr.PromoteBackup(ctx))

	rec, err := cs.GetActiveCertRecord(ctx)
	require.NoError(t, err)
	assert.Equal(t, leaf.SerialNumber, rec.Certificate.SerialNumber)
	assert.Equal(t, "backup-key", rec.KMSKeyID)
}

func TestCertManager_List(t *testing.T) {
	mgr, cs, primary, backup := newTestCertManager(t)
	ctx := context.Background()

	active, err := crypto.GenerateSelfSignedCert(primary, "https://idp.example.com")
	require.NoError(t, err)
	require.NoError(t, cs.StoreActiveCert(ctx, active))

	bcert, err := crypto.GenerateSelfSignedCert(backup, "https://idp.example.com")
	require.NoError(t, err)
	require.NoError(t, cs.StoreBackupCertMeta(ctx, bcert, crypto.CertMeta{Source: crypto.SourceCAIssued, KMSKeyID: "backup-key"}))

	list, err := mgr.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, RoleActive, list[0].Role)
	assert.Equal(t, RoleBackup, list[1].Role)
	assert.Equal(t, crypto.SourceCAIssued, list[1].Source)
}

func TestCertManager_BackupFallsBackToPrimary(t *testing.T) {
	cs := crypto.NewCertStore(store.NewMemoryDB())
	primary := crypto.NewKMSSigner(newRSAKMSMock(t))
	mgr := NewCertManager(CertManagerConfig{
		Store:         cs,
		PrimarySigner: primary,
		PrimaryKeyID:  "primary-key",
		EntityID:      "https://idp.example.com",
	})

	assert.False(t, mgr.HasBackupKey())

	// Backup role without a dedicated key reuses the primary signer.
	csr, err := mgr.GenerateCSR(RoleBackup)
	require.NoError(t, err)
	assert.Contains(t, string(csr), "CERTIFICATE REQUEST")
}
