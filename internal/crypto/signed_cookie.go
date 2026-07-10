package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrCookieSigningDisabled is returned by SignedCookie.Encode and Decode when
// the SignedCookie was constructed without an HMAC key (key is nil). This
// occurs on Lambdas that skip the login/callback flow — passing nil explicitly
// is the correct choice on those Lambdas; if a login request somehow reaches
// them anyway, every attempt to sign or verify a cookie fails closed rather than
// silently proceeding with a known-weak key.
var ErrCookieSigningDisabled = errors.New("signed cookie: HMAC signing is disabled (no key configured)")

// ErrCookieKeyTooShort is returned by NewSignedCookie when a non-nil key
// shorter than 32 bytes is supplied. A key that short provides less than
// 256 bits of HMAC entropy (CWE-326) and is likely a programming error.
var ErrCookieKeyTooShort = errors.New("signed cookie: HMAC key must be exactly 32 bytes (or nil to disable signing)")

// SignedCookie provides signed and encrypted cookie encoding and decoding.
// The encoding pattern is: JSON -> encrypt -> base64url -> HMAC sign -> "payload.signature"
// The decoding pattern is: verify HMAC -> base64url decode -> decrypt -> JSON unmarshal
type SignedCookie struct {
	hmacKey   []byte
	encryptor *CookieEncryptor
}

// NewSignedCookie creates a new SignedCookie with the given HMAC key.
//
// Key handling:
//   - nil: signing is DISABLED. Encode and Decode always return
//     ErrCookieSigningDisabled. Use this on Lambdas that do not handle
//     login/callback requests rather than passing a placeholder key — the
//     fail-closed error is a defence-in-depth backstop if a request is
//     mis-routed to the Lambda.
//   - 32 bytes: HMAC-SHA256 signing is enabled. AES-256-GCM encryption is also
//     enabled using a separate key derived via SHA-256 with label
//     "aes-encryption" so the same key is never reused for both operations.
//   - any other non-nil length: returns ErrCookieKeyTooShort. A short key
//     provides less than 256 bits of HMAC entropy and is almost certainly a
//     programming error. The caller must panic or propagate the error — never
//     proceed with a weak key.
func NewSignedCookie(hmacKey []byte) (*SignedCookie, error) {
	if hmacKey != nil && len(hmacKey) != 32 {
		return nil, ErrCookieKeyTooShort
	}
	sc := &SignedCookie{hmacKey: hmacKey}
	if len(hmacKey) == 32 {
		aesKey := sha256.Sum256(append(hmacKey, []byte("aes-encryption")...))
		enc, err := NewCookieEncryptor(aesKey[:])
		if err == nil {
			sc.encryptor = enc
		}
	}
	return sc, nil
}

// Encode encrypts, encodes, and signs the given data.
// Returns a string in the format "base64url_payload.hex_signature".
// Returns ErrCookieSigningDisabled when the SignedCookie was constructed
// without a key (nil hmacKey — disabled mode).
func (sc *SignedCookie) Encode(data []byte) (string, error) {
	if sc.hmacKey == nil {
		return "", ErrCookieSigningDisabled
	}
	// Encrypt before encoding if encryptor is available
	if sc.encryptor != nil {
		var err error
		data, err = sc.encryptor.Seal(data)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt cookie: %w", err)
		}
	}

	payload := base64.RawURLEncoding.EncodeToString(data)
	sig := sc.hmacSign([]byte(payload))
	return payload + "." + sig, nil
}

// Decode verifies the signature, decodes, and decrypts the given signed cookie.
// Returns the plaintext data or an error if verification or decryption fails.
// Returns ErrCookieSigningDisabled when the SignedCookie was constructed
// without a key (nil hmacKey — disabled mode).
func (sc *SignedCookie) Decode(raw string) ([]byte, error) {
	if sc.hmacKey == nil {
		return nil, ErrCookieSigningDisabled
	}
	// Split into payload.signature
	var payload, sig string
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] == '.' {
			payload = raw[:i]
			sig = raw[i+1:]
			break
		}
	}
	if payload == "" || sig == "" {
		return nil, fmt.Errorf("malformed signed cookie")
	}

	expected := sc.hmacSign([]byte(payload))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, fmt.Errorf("invalid cookie signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}

	// Decrypt after decoding if encryptor is available
	if sc.encryptor != nil {
		data, err = sc.encryptor.Open(data)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt cookie: %w", err)
		}
	}

	return data, nil
}

func (sc *SignedCookie) hmacSign(data []byte) string {
	mac := hmac.New(sha256.New, sc.hmacKey)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
