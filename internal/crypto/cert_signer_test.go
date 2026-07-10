package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectActiveSigner_DefaultsToPrimary(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	// Self-signed active cert with no explicit key id (legacy shape).
	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	require.NoError(t, cs.StoreActiveCert(ctx, cert))

	var built string
	newSigner := func(keyID string) *KMSSigner {
		built = keyID
		return signer
	}

	got, gotCert, keyID, err := SelectActiveSigner(ctx, cs, "primary-key", newSigner)
	require.NoError(t, err)
	assert.Equal(t, "primary-key", keyID)
	assert.Equal(t, "primary-key", built)
	assert.Equal(t, signer, got)
	assert.Equal(t, cert.SerialNumber, gotCert.SerialNumber)
}

func TestSelectActiveSigner_UsesCertKeyID(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	// Active cert bound to a backup key id (as after promoting a backup cert).
	cert, err := GenerateSelfSignedCert(signer, "https://idp.example.com")
	require.NoError(t, err)
	require.NoError(t, cs.StoreActiveCertMeta(ctx, cert, CertMeta{Source: SourceCAIssued, KMSKeyID: "backup-key"}))

	var built string
	newSigner := func(keyID string) *KMSSigner {
		built = keyID
		return signer
	}

	_, _, keyID, err := SelectActiveSigner(ctx, cs, "primary-key", newSigner)
	require.NoError(t, err)
	assert.Equal(t, "backup-key", keyID)
	assert.Equal(t, "backup-key", built)
}

func TestSelectActiveSigner_NoActiveCert(t *testing.T) {
	cs, _ := newTestCertStore(t)
	ctx := context.Background()

	_, _, _, err := SelectActiveSigner(ctx, cs, "primary-key", func(string) *KMSSigner { return nil })
	assert.Error(t, err)
}
