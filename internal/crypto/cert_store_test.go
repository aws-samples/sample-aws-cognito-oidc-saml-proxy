package crypto

import (
	"context"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCertStore creates a CertStore backed by MemoryDB and a test cert.
func newTestCertStore(t *testing.T) (*CertStore, *KMSSigner) {
	t.Helper()
	db := store.NewMemoryDB()
	cs := NewCertStore(db)

	mockClient, err := newMockKMSClient()
	require.NoError(t, err)
	signer := NewKMSSigner(mockClient)

	return cs, signer
}

func TestCertStore_StoreAndGetActive(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreActiveCert(ctx, cert)
	require.NoError(t, err)

	got, err := cs.GetActiveCert(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, cert.Subject.CommonName, got.Subject.CommonName)
	assert.Equal(t, cert.SerialNumber, got.SerialNumber)
	assert.Equal(t, cert.NotBefore.Unix(), got.NotBefore.Unix())
	assert.Equal(t, cert.NotAfter.Unix(), got.NotAfter.Unix())
}

func TestCertStore_StoreAndGetNext(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreNextCert(ctx, cert)
	require.NoError(t, err)

	got, err := cs.GetNextCert(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, cert.Subject.CommonName, got.Subject.CommonName)
	assert.Equal(t, cert.SerialNumber, got.SerialNumber)
}

func TestCertStore_GetAllCerts_Empty(t *testing.T) {
	cs, _ := newTestCertStore(t)
	ctx := context.Background()

	certs, err := cs.GetAllCerts(ctx)
	require.NoError(t, err)
	assert.Empty(t, certs)
}

func TestCertStore_GetAllCerts_ActiveOnly(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreActiveCert(ctx, cert)
	require.NoError(t, err)

	certs, err := cs.GetAllCerts(ctx)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, cert.SerialNumber, certs[0].SerialNumber)
}

func TestCertStore_GetAllCerts_ActiveAndNext(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	active, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	next, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreActiveCert(ctx, active)
	require.NoError(t, err)
	err = cs.StoreNextCert(ctx, next)
	require.NoError(t, err)

	certs, err := cs.GetAllCerts(ctx)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Equal(t, active.SerialNumber, certs[0].SerialNumber)
	assert.Equal(t, next.SerialNumber, certs[1].SerialNumber)
}

func TestCertStore_PromoteNextToActive(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	active, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	next, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreActiveCert(ctx, active)
	require.NoError(t, err)
	err = cs.StoreNextCert(ctx, next)
	require.NoError(t, err)

	// Promote next to active
	err = cs.PromoteNextToActive(ctx)
	require.NoError(t, err)

	// Active should now be the old next cert
	got, err := cs.GetActiveCert(ctx)
	require.NoError(t, err)
	assert.Equal(t, next.SerialNumber, got.SerialNumber)

	// Next slot should be empty
	_, err = cs.GetNextCert(ctx)
	assert.Error(t, err)
}

func TestCertStore_PromoteNextToActive_NoNext(t *testing.T) {
	cs, _ := newTestCertStore(t)
	ctx := context.Background()

	err := cs.PromoteNextToActive(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no next cert to promote")
}

func TestCertStore_GetActiveCertExpiry(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreActiveCert(ctx, cert)
	require.NoError(t, err)

	expiry, err := cs.GetActiveCertExpiry(ctx)
	require.NoError(t, err)

	// The expiry read from the item should match the cert's NotAfter (within 1s for serialization rounding)
	assert.InDelta(t, cert.NotAfter.Unix(), expiry.Unix(), 1)
}

func TestCertStore_GetActiveCertExpiry_NoCert(t *testing.T) {
	cs, _ := newTestCertStore(t)
	ctx := context.Background()

	_, err := cs.GetActiveCertExpiry(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active cert")
}

func TestCertStore_DeleteNext(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreNextCert(ctx, cert)
	require.NoError(t, err)

	// Verify it exists
	_, err = cs.GetNextCert(ctx)
	require.NoError(t, err)

	// Delete it
	err = cs.DeleteNext(ctx)
	require.NoError(t, err)

	// Verify it's gone
	_, err = cs.GetNextCert(ctx)
	assert.Error(t, err)
}

func TestCertStore_GetActiveCert_NoCert(t *testing.T) {
	cs, _ := newTestCertStore(t)
	ctx := context.Background()

	cert, err := cs.GetActiveCert(ctx)
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestCertStore_OverwriteActiveCert(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert1, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	cert2, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreActiveCert(ctx, cert1)
	require.NoError(t, err)

	// Overwrite with a new cert
	err = cs.StoreActiveCert(ctx, cert2)
	require.NoError(t, err)

	got, err := cs.GetActiveCert(ctx)
	require.NoError(t, err)
	assert.Equal(t, cert2.SerialNumber, got.SerialNumber)

	// Only one cert in GetAllCerts (active slot was overwritten, not appended)
	certs, err := cs.GetAllCerts(ctx)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

func TestCertStore_ExpiryFromItemNotCert(t *testing.T) {
	// Verifies GetActiveCertExpiry reads from the DynamoDB item metadata,
	// not by parsing the PEM. This is useful when we want fast expiry checks
	// without PEM decode overhead.
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreActiveCert(ctx, cert)
	require.NoError(t, err)

	expiry, err := cs.GetActiveCertExpiry(ctx)
	require.NoError(t, err)

	// Should be approximately 2 years from now
	expectedDuration := 2 * 365 * 24 * time.Hour
	tolerance := 24 * time.Hour
	actualDuration := time.Until(expiry)
	assert.InDelta(t, expectedDuration.Seconds(), actualDuration.Seconds(), tolerance.Seconds())
}

func TestCertStore_StoreAndGetBackup(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	err = cs.StoreBackupCertMeta(ctx, cert, CertMeta{Source: SourceCAIssued, KMSKeyID: "backup-key"})
	require.NoError(t, err)

	got, err := cs.GetBackupCert(ctx)
	require.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, got.SerialNumber)

	rec, err := cs.GetBackupCertRecord(ctx)
	require.NoError(t, err)
	assert.Equal(t, SourceCAIssued, rec.Source)
	assert.Equal(t, "backup-key", rec.KMSKeyID)
}

func TestCertStore_PromoteBackupToActive(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	active, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	backup, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	require.NoError(t, cs.StoreActiveCert(ctx, active))
	require.NoError(t, cs.StoreBackupCertMeta(ctx, backup, CertMeta{Source: SourceCAIssued, KMSKeyID: "backup-key"}))

	require.NoError(t, cs.PromoteBackupToActive(ctx))

	// Active is now the old backup, carrying its metadata.
	rec, err := cs.GetActiveCertRecord(ctx)
	require.NoError(t, err)
	assert.Equal(t, backup.SerialNumber, rec.Certificate.SerialNumber)
	assert.Equal(t, SourceCAIssued, rec.Source)
	assert.Equal(t, "backup-key", rec.KMSKeyID)

	// Backup slot is cleared.
	_, err = cs.GetBackupCert(ctx)
	assert.Error(t, err)
}

func TestCertStore_PromoteBackupToActive_NoBackup(t *testing.T) {
	cs, _ := newTestCertStore(t)
	ctx := context.Background()

	err := cs.PromoteBackupToActive(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backup cert to promote")
}

func TestCertStore_GetAllCerts_IncludesBackup(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	active, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	backup, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	require.NoError(t, cs.StoreActiveCert(ctx, active))
	require.NoError(t, cs.StoreBackupCertMeta(ctx, backup, CertMeta{Source: SourceCAIssued}))

	certs, err := cs.GetAllCerts(ctx)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestCertStore_ActiveCertSourceRoundTrip(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)

	require.NoError(t, cs.StoreActiveCertMeta(ctx, cert, CertMeta{Source: SourceCAIssued, KMSKeyID: "primary"}))

	rec, err := cs.GetActiveCertRecord(ctx)
	require.NoError(t, err)
	assert.Equal(t, SourceCAIssued, rec.Source)
	assert.Equal(t, "primary", rec.KMSKeyID)
}
