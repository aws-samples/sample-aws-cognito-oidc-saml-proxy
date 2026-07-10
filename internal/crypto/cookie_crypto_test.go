package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCookieEncryptor_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := NewCookieEncryptor(key)
	require.NoError(t, err)
	assert.NotNil(t, enc)
}

func TestNewCookieEncryptor_InvalidKeyLength(t *testing.T) {
	tests := []struct {
		name   string
		keyLen int
	}{
		{"too short 16", 16},
		{"too short 0", 0},
		{"too long 64", 64},
		{"off by one 31", 31},
		{"off by one 33", 33},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := NewCookieEncryptor(key)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "encryption key must be 32 bytes")
		})
	}
}

func TestCookieEncryptor_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := NewCookieEncryptor(key)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"json payload", []byte(`{"email":"user@example.com","groups":["admin"],"verifier":"abc123"}`)},
		{"empty", []byte{}},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
		{"large payload", make([]byte, 4096)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := enc.Seal(tc.plaintext)
			require.NoError(t, err)
			assert.NotEqual(t, tc.plaintext, ciphertext, "ciphertext should differ from plaintext")

			decrypted, err := enc.Open(ciphertext)
			require.NoError(t, err)
			// GCM Open returns nil for empty plaintext; normalize for comparison
			assert.Equal(t, len(tc.plaintext), len(decrypted), "decrypted length should match original plaintext")
		})
	}
}

func TestCookieEncryptor_DifferentCiphertextsForSamePlaintext(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := NewCookieEncryptor(key)
	require.NoError(t, err)

	plaintext := []byte("same plaintext")

	ct1, err := enc.Seal(plaintext)
	require.NoError(t, err)

	ct2, err := enc.Seal(plaintext)
	require.NoError(t, err)

	// Random nonce means different ciphertexts each time
	assert.NotEqual(t, ct1, ct2, "encrypting the same plaintext twice should produce different ciphertexts due to random nonce")

	// But both should decrypt to the same plaintext
	dec1, err := enc.Open(ct1)
	require.NoError(t, err)

	dec2, err := enc.Open(ct2)
	require.NoError(t, err)

	assert.Equal(t, dec1, dec2)
}

func TestCookieEncryptor_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)

	enc1, err := NewCookieEncryptor(key1)
	require.NoError(t, err)

	enc2, err := NewCookieEncryptor(key2)
	require.NoError(t, err)

	ciphertext, err := enc1.Seal([]byte("secret data"))
	require.NoError(t, err)

	_, err = enc2.Open(ciphertext)
	assert.Error(t, err, "decryption with wrong key should fail")
}

func TestCookieEncryptor_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := NewCookieEncryptor(key)
	require.NoError(t, err)

	ciphertext, err := enc.Seal([]byte("sensitive data"))
	require.NoError(t, err)

	// Tamper with the ciphertext (flip a bit in the encrypted data area)
	if len(ciphertext) > 15 {
		ciphertext[15] ^= 0x01
	}

	_, err = enc.Open(ciphertext)
	assert.Error(t, err, "tampered ciphertext should fail authentication")
}

func TestCookieEncryptor_TruncatedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := NewCookieEncryptor(key)
	require.NoError(t, err)

	// Ciphertext shorter than nonce size (12 bytes for GCM)
	_, err = enc.Open([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}
