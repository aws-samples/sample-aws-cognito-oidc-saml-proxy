package crypto

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSignedCookie_NilKey_DisablesSigningFailClosed is the MF-9 regression:
// constructing a SignedCookie with a nil key must yield a disabled instance
// whose Encode and Decode always return ErrCookieSigningDisabled. On the
// oidc-token and oidc-discovery Lambdas we pass nil (not a zero-byte
// placeholder) so any mis-routed login request fails closed immediately.
func TestNewSignedCookie_NilKey_DisablesSigningFailClosed(t *testing.T) {
	sc, err := NewSignedCookie(nil)
	require.NoError(t, err, "nil key must not return an error — it creates a disabled instance")
	require.NotNil(t, sc)

	_, encErr := sc.Encode([]byte("test payload"))
	assert.ErrorIs(t, encErr, ErrCookieSigningDisabled,
		"Encode on a nil-key SignedCookie must return ErrCookieSigningDisabled")

	_, decErr := sc.Decode("dGVzdA.deadbeef")
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

		_, scErr := NewSignedCookie(key)
		assert.ErrorIs(t, scErr, ErrCookieKeyTooShort,
			"key of length %d must be rejected with ErrCookieKeyTooShort", l)
	}
}

// TestNewSignedCookie_32ByteKey_EnablesSigningAndEncryption verifies the happy
// path: a 32-byte key produces a fully functional SignedCookie whose
// Encode/Decode round-trip preserves the plaintext.
func TestNewSignedCookie_32ByteKey_EnablesSigningAndEncryption(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	sc, err := NewSignedCookie(key)
	require.NoError(t, err)
	require.NotNil(t, sc)

	plaintext := []byte(`{"authRequestID":"test","verifier":"v","tenantSlug":"acme"}`)

	encoded, err := sc.Encode(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)
	assert.Contains(t, encoded, ".", "encoded cookie must contain a dot separator")

	decoded, err := sc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decoded)
}

// TestNewSignedCookie_TamperedPayload_Rejected checks that a tampered
// ciphertext fails HMAC verification.
func TestNewSignedCookie_TamperedPayload_Rejected(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	sc, err := NewSignedCookie(key)
	require.NoError(t, err)

	encoded, err := sc.Encode([]byte("sensitive data"))
	require.NoError(t, err)

	// Flip a byte in the payload (before the last dot) to simulate tampering.
	// Use a character guaranteed to differ from the original to avoid a no-op
	// substitution when encoded[0] is already that character.
	sub := byte('X')
	if encoded[0] == sub {
		sub = 'Y'
	}
	tampered := string(sub) + encoded[1:]

	_, decErr := sc.Decode(tampered)
	assert.Error(t, decErr, "tampered cookie must be rejected")
	assert.False(t, errors.Is(decErr, ErrCookieSigningDisabled),
		"error must be a signature failure, not a disabled-key error")
}
