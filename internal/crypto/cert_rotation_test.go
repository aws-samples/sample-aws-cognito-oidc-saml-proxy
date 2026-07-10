package crypto

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errInjectDB wraps a store.TableAPI and forces a transient (non-NotFound)
// error on Get for a chosen sort key, leaving every other operation intact. It
// models throttling / 5xx / IAM-denial on the active-cert read so tests can
// prove CheckCertRotation fails closed instead of clobbering the live cert.
type errInjectDB struct {
	store.TableAPI
	failGetSK string
	err       error
}

func (d *errInjectDB) Get(ctx context.Context, pk, sk string, out interface{}) error {
	if sk == d.failGetSK {
		return d.err
	}
	return d.TableAPI.Get(ctx, pk, sk, out)
}

const testEntityID = "https://idp.example.com"

// generateCertWithExpiry creates a self-signed cert that expires at the given time.
// This lets tests control the rotation state machine without waiting for real time.
func generateCertWithExpiry(t *testing.T, signer *KMSSigner, entityID string, notAfter time.Time) *x509.Certificate {
	t.Helper()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: entityID},
		NotBefore:    notAfter.Add(-2 * 365 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func TestCheckCertRotation_NoActiveCert(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig()

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "generated_initial", result.Action)
	// New cert should be ~2 years out
	assert.Greater(t, result.DaysRemaining, 700.0)

	// Verify it was stored
	cert, err := cs.GetActiveCert(ctx)
	require.NoError(t, err)
	assert.Equal(t, testEntityID, cert.Subject.CommonName)
}

func TestCheckCertRotation_FreshCert(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig()

	// Store a cert expiring in 365 days (well outside 30-day window)
	cert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(365*24*time.Hour))
	err := cs.StoreActiveCert(ctx, cert)
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "no_action", result.Action)
	assert.InDelta(t, 365.0, result.DaysRemaining, 1.0)
}

func TestCheckCertRotation_WithinWindow_NoNext(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig() // 30-day window, 14-day promotion delay

	// Store a cert expiring in 25 days (within 30-day window, but > 16 days = promotion threshold)
	cert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(25*24*time.Hour))
	err := cs.StoreActiveCert(ctx, cert)
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "staged_next", result.Action)
	assert.InDelta(t, 25.0, result.DaysRemaining, 1.0)

	// Verify next cert was created
	nextCert, err := cs.GetNextCert(ctx)
	require.NoError(t, err)
	assert.NotNil(t, nextCert)
}

// TestCheckCertRotation_TransientReadError_DoesNotClobber is the MF-7
// regression: a transient (non-NotFound) error reading the active cert expiry
// must fail closed and leave the existing active cert untouched — it must NOT
// be misread as "no active cert" and overwritten with a fresh self-signed cert.
func TestCheckCertRotation_TransientReadError_DoesNotClobber(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultRotationConfig()

	mem := store.NewMemoryDB()
	seed := NewCertStore(mem)

	_, signer := newTestCertStore(t)

	// Seed a healthy, CA-issued active cert well outside the rotation window.
	caCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(365*24*time.Hour))
	require.NoError(t, seed.StoreActiveCertMeta(ctx, caCert, CertMeta{Source: SourceCAIssued}))
	origSerial := caCert.SerialNumber.String()

	// A CertStore whose active-cert Get fails with a transient (non-NotFound)
	// error. Everything else (including StoreActiveCert, were it wrongly called)
	// goes to the same underlying MemoryDB, so a clobber WOULD be observable.
	transient := errors.New("dynamodb: ProvisionedThroughputExceededException")
	faulty := NewCertStore(&errInjectDB{TableAPI: mem, failGetSK: certActiveSK, err: transient})

	result, err := CheckCertRotation(ctx, faulty, signer, testEntityID, cfg)
	require.Error(t, err, "a transient read error must surface, not be swallowed")
	assert.ErrorIs(t, err, transient)
	assert.Empty(t, result.Action, "no rotation action must be taken on a transient error")

	// The active cert must be exactly the seeded CA-issued one — untouched.
	rec, err := seed.GetActiveCertRecord(ctx)
	require.NoError(t, err)
	assert.Equal(t, origSerial, rec.Certificate.SerialNumber.String(),
		"active cert serial changed — it was clobbered by a self-signed cert")
	assert.Equal(t, SourceCAIssued, rec.Source,
		"active cert Source flipped to self-signed — the CA-issued cert was overwritten")
}

// TestCheckCertRotation_TransientNextReadError_DoesNotStage is the
// lower-blast-radius half of MF-7: within the rotation window, a transient
// error reading the staged "next" cert must fail closed rather than be misread
// as "not staged" and trigger a redundant generate/store.
func TestCheckCertRotation_TransientNextReadError_DoesNotStage(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultRotationConfig()

	mem := store.NewMemoryDB()
	seed := NewCertStore(mem)
	_, signer := newTestCertStore(t)

	// Active cert inside the rotation window (25 days) so the state machine
	// reaches the "check next cert" branch; self-signed so the CA guard is skipped.
	active := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(25*24*time.Hour))
	require.NoError(t, seed.StoreActiveCert(ctx, active))

	transient := errors.New("dynamodb: ThrottlingException")
	faulty := NewCertStore(&errInjectDB{TableAPI: mem, failGetSK: certNextSK, err: transient})

	result, err := CheckCertRotation(ctx, faulty, signer, testEntityID, cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, transient)
	assert.Empty(t, result.Action)

	// No next cert must have been staged as a side effect of the failed read.
	_, err = seed.GetNextCert(ctx)
	assert.ErrorIs(t, err, store.ErrNotFound, "no next cert should have been staged on a transient error")
}

func TestCheckCertRotation_WithinWindow_NextExists(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig() // 30-day window, 14-day promotion delay

	// Store a cert expiring in 25 days (within window but above promotion threshold of 16)
	activeCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(25*24*time.Hour))
	err := cs.StoreActiveCert(ctx, activeCert)
	require.NoError(t, err)

	// Pre-stage a next cert
	nextCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(2*365*24*time.Hour))
	err = cs.StoreNextCert(ctx, nextCert)
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "waiting_for_promotion", result.Action)
	assert.InDelta(t, 25.0, result.DaysRemaining, 1.0)

	// Active cert should be unchanged
	got, err := cs.GetActiveCert(ctx)
	require.NoError(t, err)
	assert.Equal(t, activeCert.SerialNumber, got.SerialNumber)
}

func TestCheckCertRotation_PromotionReady(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig() // 30-day window, 14-day delay -> promote at <= 16 days

	// Store a cert expiring in 10 days (below promotion threshold of 16)
	oldCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(10*24*time.Hour))
	err := cs.StoreActiveCert(ctx, oldCert)
	require.NoError(t, err)

	// Stage a next cert expiring in 2 years
	nextCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(2*365*24*time.Hour))
	err = cs.StoreNextCert(ctx, nextCert)
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "promoted", result.Action)
	// Days remaining should now reflect the promoted cert (~2 years)
	assert.Greater(t, result.DaysRemaining, 700.0)

	// Active cert should now be the old next cert
	got, err := cs.GetActiveCert(ctx)
	require.NoError(t, err)
	assert.Equal(t, nextCert.SerialNumber, got.SerialNumber)

	// Next slot should be empty
	_, err = cs.GetNextCert(ctx)
	assert.Error(t, err)
}

func TestCheckCertRotation_ExactBoundary(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig() // threshold = 30 - 14 = 16

	// Cert expiring in exactly 16 days -- should promote (<=)
	activeCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(16*24*time.Hour))
	err := cs.StoreActiveCert(ctx, activeCert)
	require.NoError(t, err)

	nextCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(2*365*24*time.Hour))
	err = cs.StoreNextCert(ctx, nextCert)
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "promoted", result.Action)
}

func TestCheckCertRotation_CustomConfig(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()

	// Custom config: 60-day window, 30-day delay -> promote at <= 30 days
	cfg := CertRotationConfig{
		RotationWindowDays: 60,
		PromotionDelayDays: 30,
	}

	// Cert expiring in 45 days: within 60-day window, above 30-day promotion threshold
	cert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(45*24*time.Hour))
	err := cs.StoreActiveCert(ctx, cert)
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "staged_next", result.Action)
}

func TestCheckCertRotation_FullLifecycle(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig()

	// Phase 1: No cert -> generate initial
	r1, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)
	assert.Equal(t, "generated_initial", r1.Action)

	// Phase 2: Fresh cert -> no action
	r2, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)
	assert.Equal(t, "no_action", r2.Action)

	// Phase 3: Simulate approaching expiry by replacing with a 25-day cert
	expiringCert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(25*24*time.Hour))
	err = cs.StoreActiveCert(ctx, expiringCert)
	require.NoError(t, err)

	r3, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)
	assert.Equal(t, "staged_next", r3.Action)

	// Phase 4: Next exists, still above promotion threshold -> waiting
	r4, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)
	assert.Equal(t, "waiting_for_promotion", r4.Action)

	// Phase 5: Simulate time passing by replacing active with 10-day cert
	almostExpired := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(10*24*time.Hour))
	err = cs.StoreActiveCert(ctx, almostExpired)
	require.NoError(t, err)

	r5, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)
	assert.Equal(t, "promoted", r5.Action)
	assert.Greater(t, r5.DaysRemaining, 700.0)
}

func TestDefaultRotationConfig(t *testing.T) {
	cfg := DefaultRotationConfig()
	assert.Equal(t, 30, cfg.RotationWindowDays)
	assert.Equal(t, 14, cfg.PromotionDelayDays)
}

func TestCheckCertRotation_CAIssuedActive_ImportRequired(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig()

	// Active cert is CA-issued and within the rotation window (25 days).
	cert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(25*24*time.Hour))
	err := cs.StoreActiveCertMeta(ctx, cert, CertMeta{Source: SourceCAIssued})
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)

	assert.Equal(t, "import_required", result.Action)

	// No self-signed next cert should have been staged.
	_, err = cs.GetNextCert(ctx)
	assert.Error(t, err)
}

func TestCheckCertRotation_CAIssuedActive_OutsideWindow_NoAction(t *testing.T) {
	cs, signer := newTestCertStore(t)
	ctx := context.Background()
	cfg := DefaultRotationConfig()

	// CA-issued but far from expiry -> normal no_action path.
	cert := generateCertWithExpiry(t, signer, testEntityID, time.Now().Add(200*24*time.Hour))
	err := cs.StoreActiveCertMeta(ctx, cert, CertMeta{Source: SourceCAIssued})
	require.NoError(t, err)

	result, err := CheckCertRotation(ctx, cs, signer, testEntityID, cfg)
	require.NoError(t, err)
	assert.Equal(t, "no_action", result.Action)
}
