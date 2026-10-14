package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

// TestNewSignedCookie_NilKey_DisablesSigningFailClosed is the MF-9 regression:
// constructing a SignedCookie with a nil key must yield a disabled instance
// whose Encode and Decode always return ErrCookieSigningDisabled. On the
// oidc-token and oidc-discovery Lambdas we pass nil (not a zero-byte
// placeholder) so any mis-routed login request fails closed immediately.
func TestNewSignedCookie_NilKey_DisablesSigningFailClosed(t *testing.T) {
	sc, err := NewSignedCookie(nil, CookiePurposeSAML)
	require.NoError(t, err, "nil key must not return an error — it creates a disabled instance")
	require.NotNil(t, sc)

	_, encErr := sc.Encode([]byte("test payload"))
	assert.ErrorIs(t, encErr, ErrCookieSigningDisabled,
		"Encode on a nil-key SignedCookie must return ErrCookieSigningDisabled")

	_, decErr := sc.Decode("00000000.dGVzdA.deadbeef")
	assert.ErrorIs(t, decErr, ErrCookieSigningDisabled,
		"Decode on a nil-key SignedCookie must return ErrCookieSigningDisabled")
}

// TestNewSignedCookie_ShortKey_Errors validates that a non-nil key shorter
// than 32 bytes is rejected at construction time (CWE-326). The old code
// silently accepted short keys (no HMAC, no AES). A short non-nil key is
// almost certainly a programming error, not an intentional "no signing"
// signal — use nil for that.
func TestNewSignedCookie_ShortKey_Errors(t *testing.T) {
	for _, l := range []int{1, 8, 16, 31} {
		key := make([]byte, l)
		_, err := rand.Read(key)
		require.NoError(t, err)

		_, scErr := NewSignedCookie(key, CookiePurposeSAML)
		assert.ErrorIs(t, scErr, ErrCookieKeyTooShort,
			"key of length %d must be rejected with ErrCookieKeyTooShort", l)
	}
}

// TestNewSignedCookie_EmptyPurpose_Errors is the I-8 guard: the purpose label
// is mandatory (even in disabled mode) so no call site can accidentally mint
// cookies that are interchangeable between SAML and OIDC.
func TestNewSignedCookie_EmptyPurpose_Errors(t *testing.T) {
	_, err := NewSignedCookie(randomKey(t), "")
	assert.ErrorIs(t, err, ErrCookiePurposeRequired)

	_, err = NewSignedCookie(nil, "")
	assert.ErrorIs(t, err, ErrCookiePurposeRequired)
}

// TestNewSignedCookie_32ByteKey_EnablesSigningAndEncryption verifies the happy
// path: a 32-byte key produces a fully functional SignedCookie whose
// Encode/Decode round-trip preserves the plaintext and emits the three-part
// kid.payload.signature wire format.
func TestNewSignedCookie_32ByteKey_EnablesSigningAndEncryption(t *testing.T) {
	sc, err := NewSignedCookie(randomKey(t), CookiePurposeOIDC)
	require.NoError(t, err)
	require.NotNil(t, sc)

	plaintext := []byte(`{"authRequestID":"test","verifier":"v","tenantSlug":"acme"}`)

	encoded, err := sc.Encode(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)
	parts := strings.Split(encoded, ".")
	require.Len(t, parts, 3, "encoded cookie must be kid.payload.signature")
	assert.Len(t, parts[0], 8, "kid must be 4 bytes hex-encoded")
	assert.Equal(t, sc.kid, parts[0])

	decoded, err := sc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decoded)
}

// TestNewSignedCookie_TamperedPayload_Rejected checks that a tampered
// ciphertext fails HMAC verification.
func TestNewSignedCookie_TamperedPayload_Rejected(t *testing.T) {
	sc, err := NewSignedCookie(randomKey(t), CookiePurposeSAML)
	require.NoError(t, err)

	encoded, err := sc.Encode([]byte("sensitive data"))
	require.NoError(t, err)

	// Flip the first byte of the payload (after the kid) to simulate
	// tampering. Use a character guaranteed to differ from the original to
	// avoid a no-op substitution.
	parts := strings.Split(encoded, ".")
	require.Len(t, parts, 3)
	sub := byte('X')
	if parts[1][0] == sub {
		sub = 'Y'
	}
	parts[1] = string(sub) + parts[1][1:]
	tampered := strings.Join(parts, ".")

	_, decErr := sc.Decode(tampered)
	assert.Error(t, decErr, "tampered cookie must be rejected")
	assert.False(t, errors.Is(decErr, ErrCookieSigningDisabled),
		"error must be a signature failure, not a disabled-key error")
	assert.False(t, errors.Is(decErr, ErrCookieUnknownKeyID),
		"kid is untouched, so the error must not be a key-id mismatch")
}

// TestSignedCookie_CrossPurposeDecodeFails is the I-8 regression: a cookie
// minted for the SAML surface must not be accepted by the OIDC surface even
// though both share the same root key (and therefore the same kid).
func TestSignedCookie_CrossPurposeDecodeFails(t *testing.T) {
	key := randomKey(t)
	samlSC, err := NewSignedCookie(key, CookiePurposeSAML)
	require.NoError(t, err)
	oidcSC, err := NewSignedCookie(key, CookiePurposeOIDC)
	require.NoError(t, err)

	encoded, err := samlSC.Encode([]byte("saml session"))
	require.NoError(t, err)

	_, decErr := oidcSC.Decode(encoded)
	require.Error(t, decErr, "OIDC instance must reject a SAML-purpose cookie")
	assert.False(t, errors.Is(decErr, ErrCookieUnknownKeyID),
		"same root key means same kid — failure must come from the purpose-bound subkeys")

	// Sanity: the originating purpose still decodes.
	plain, err := samlSC.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, []byte("saml session"), plain)
}

// TestNewSignedCookie_DoesNotMutateCallerKey is the I-7 regression: the old
// implementation derived the AES key with append(hmacKey, label...), which
// writes into the caller's backing array when the slice has spare capacity.
func TestNewSignedCookie_DoesNotMutateCallerKey(t *testing.T) {
	key := make([]byte, 32, 64)
	_, err := rand.Read(key)
	require.NoError(t, err)

	// Snapshot the whole backing array, including the spare capacity.
	before := make([]byte, 64)
	copy(before, key[:64])

	_, err = NewSignedCookie(key, CookiePurposeSAML)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(before, key[:64]),
		"NewSignedCookie must not write into the caller's key slice or its spare capacity")
}

// TestSignedCookie_WrongKey_UnknownKeyID verifies that a cookie minted under a
// different root key is rejected with ErrCookieUnknownKeyID — the precise
// diagnostic for a Lambda deployed with the wrong shared secret or for a
// cookie that outlived a key rotation.
func TestSignedCookie_WrongKey_UnknownKeyID(t *testing.T) {
	scA, err := NewSignedCookie(randomKey(t), CookiePurposeSAML)
	require.NoError(t, err)
	scB, err := NewSignedCookie(randomKey(t), CookiePurposeSAML)
	require.NoError(t, err)

	encoded, err := scA.Encode([]byte("payload"))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(encoded, scA.kid+"."), "cookie must carry the minting key id")

	_, decErr := scB.Decode(encoded)
	assert.ErrorIs(t, decErr, ErrCookieUnknownKeyID)
}

// TestSignedCookie_LegacyTwoPartRejected ensures that the pre-kid wire format
// (payload.signature) is rejected as malformed rather than falling through to
// signature verification. Cookies from before the shared-key rollout are
// invalid anyway because the key changed.
func TestSignedCookie_LegacyTwoPartRejected(t *testing.T) {
	sc, err := NewSignedCookie(randomKey(t), CookiePurposeSAML)
	require.NoError(t, err)

	for _, raw := range []string{
		"dGVzdA.deadbeef",       // legacy two-part
		"dGVzdA",                // single segment
		"",                      // empty
		"a.b.c.d",               // too many parts
		"." + sc.kid + ".sig",   // empty kid
		sc.kid + "..sig",        // empty payload
		sc.kid + ".payload.",    // empty signature
	} {
		_, decErr := sc.Decode(raw)
		require.Error(t, decErr, "raw=%q", raw)
		assert.False(t, errors.Is(decErr, ErrCookieSigningDisabled), "raw=%q", raw)
		assert.False(t, errors.Is(decErr, ErrCookieUnknownKeyID), "raw=%q must be malformed, not kid mismatch", raw)
	}
}
