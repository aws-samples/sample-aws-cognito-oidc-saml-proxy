package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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

// ErrCookiePurposeRequired is returned by NewSignedCookie when the purpose
// label is empty. The purpose is mixed into both subkeys so a cookie minted
// for one protocol (SAML) can never be replayed into another (OIDC) even when
// both share the same root key (I-8).
var ErrCookiePurposeRequired = errors.New("signed cookie: purpose label is required")

// ErrCookieUnknownKeyID is returned by SignedCookie.Decode when the cookie's
// key-id prefix does not match the key this instance was constructed with.
// This is the expected failure after a key rotation (old cookies die) and the
// diagnostic for a Lambda that was deployed with a different shared secret.
var ErrCookieUnknownKeyID = errors.New("signed cookie: unknown key id")

// Cookie purposes. Every SignedCookie must be constructed with exactly one of
// these so that the HMAC and AES subkeys differ per protocol surface.
const (
	CookiePurposeSAML = "saml"
	CookiePurposeOIDC = "oidc"
)

// SignedCookie provides signed and encrypted cookie encoding and decoding.
// The encoding pattern is: JSON -> encrypt -> base64url -> HMAC sign -> "kid.payload.signature"
// The decoding pattern is: check kid -> verify HMAC -> base64url decode -> decrypt -> JSON unmarshal
type SignedCookie struct {
	hmacKey   []byte
	kid       string
	encryptor *CookieEncryptor
}

// NewSignedCookie creates a new SignedCookie from a 32-byte root key and a
// purpose label.
//
// Key handling:
//   - nil: signing is DISABLED. Encode and Decode always return
//     ErrCookieSigningDisabled. Use this on Lambdas that do not handle
//     login/callback requests rather than passing a placeholder key — the
//     fail-closed error is a defence-in-depth backstop if a request is
//     mis-routed to the Lambda.
//   - 32 bytes: HMAC-SHA256 signing and AES-256-GCM encryption are enabled.
//     Both subkeys are derived from the root key with SHA-256 over
//     key || "hmac:" || purpose and key || "aes:" || purpose, into freshly
//     allocated buffers, so the root key is never used directly, the two
//     operations never share a key, and the caller's slice is never written
//     to (I-7).
//   - any other non-nil length: returns ErrCookieKeyTooShort. A short key
//     provides less than 256 bits of HMAC entropy and is almost certainly a
//     programming error. The caller must panic or propagate the error — never
//     proceed with a weak key.
//
// The purpose label (CookiePurposeSAML or CookiePurposeOIDC) is required even
// in disabled mode so call sites cannot forget it.
//
// Every encoded cookie carries a key id — hex(SHA-256(key)[:4]) — as its first
// segment. Decode rejects cookies whose kid does not match before touching the
// signature, which turns "wrong shared secret on this Lambda" into a precise
// error instead of a generic signature failure.
func NewSignedCookie(key []byte, purpose string) (*SignedCookie, error) {
	if purpose == "" {
		return nil, ErrCookiePurposeRequired
	}
	if key != nil && len(key) != 32 {
		return nil, ErrCookieKeyTooShort
	}
	sc := &SignedCookie{}
	if key == nil {
		return sc, nil
	}

	hmacKey := deriveSubkey(key, "hmac:", purpose)
	aesKey := deriveSubkey(key, "aes:", purpose)
	enc, err := NewCookieEncryptor(aesKey)
	if err != nil {
		return nil, fmt.Errorf("signed cookie: failed to initialise encryptor: %w", err)
	}

	kidSum := sha256.Sum256(key)
	sc.hmacKey = hmacKey
	sc.kid = hex.EncodeToString(kidSum[:4])
	sc.encryptor = enc
	return sc, nil
}

// deriveSubkey returns SHA-256(key || label || purpose) computed over a fresh
// buffer. It never appends onto the caller's slice, so a key with spare
// capacity is not mutated behind the caller's back.
func deriveSubkey(key []byte, label, purpose string) []byte {
	buf := make([]byte, 0, len(key)+len(label)+len(purpose))
	buf = append(buf, key...)
	buf = append(buf, label...)
	buf = append(buf, purpose...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

// Encode encrypts, encodes, and signs the given data.
// Returns a string in the format "kid.base64url_payload.hex_signature" where
// the signature covers "kid.base64url_payload".
// Returns ErrCookieSigningDisabled when the SignedCookie was constructed
// without a key (nil key — disabled mode).
func (sc *SignedCookie) Encode(data []byte) (string, error) {
	if sc.hmacKey == nil {
		return "", ErrCookieSigningDisabled
	}
	sealed, err := sc.encryptor.Seal(data)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt cookie: %w", err)
	}

	signed := sc.kid + "." + base64.RawURLEncoding.EncodeToString(sealed)
	sig := sc.hmacSign([]byte(signed))
	return signed + "." + sig, nil
}

// Decode verifies the key id and signature, then decodes and decrypts the
// given signed cookie. Returns the plaintext data or an error if any step
// fails. Returns ErrCookieSigningDisabled when the SignedCookie was constructed
// without a key (nil key — disabled mode) and ErrCookieUnknownKeyID when the
// cookie was minted under a different root key. Legacy two-part cookies
// (payload.signature) are rejected as malformed.
func (sc *SignedCookie) Decode(raw string) ([]byte, error) {
	if sc.hmacKey == nil {
		return nil, ErrCookieSigningDisabled
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("malformed signed cookie")
	}
	kid, payload, sig := parts[0], parts[1], parts[2]
	if kid != sc.kid {
		return nil, ErrCookieUnknownKeyID
	}

	expected := sc.hmacSign([]byte(kid + "." + payload))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, fmt.Errorf("invalid cookie signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}

	data, err = sc.encryptor.Open(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt cookie: %w", err)
	}

	return data, nil
}

func (sc *SignedCookie) hmacSign(data []byte) string {
	mac := hmac.New(sha256.New, sc.hmacKey)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
