package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// CookieEncryptor provides AES-256-GCM encryption for cookie payloads.
// Encryption is applied before HMAC signing to ensure cookie contents
// (PKCE verifiers, user PII) are not readable even if the cookie is intercepted.
type CookieEncryptor struct {
	encryptionKey []byte // Must be exactly 32 bytes for AES-256
}

// NewCookieEncryptor creates a new CookieEncryptor with the given 32-byte key.
func NewCookieEncryptor(key []byte) (*CookieEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	return &CookieEncryptor{encryptionKey: key}, nil
}

// Seal encrypts plaintext using AES-256-GCM with a random nonce.
// The returned ciphertext is: nonce || encrypted_data || tag
func (e *CookieEncryptor) Seal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends the encrypted+authenticated data after the nonce
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Open decrypts ciphertext produced by Seal.
// Expects format: nonce || encrypted_data || tag
func (e *CookieEncryptor) Open(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
