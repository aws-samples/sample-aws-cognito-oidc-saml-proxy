package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

// PairwiseID generates a privacy-preserving pairwise subject identifier
// per the SAML2Int specification. It computes HMAC-SHA256 of "sub|entityID"
// with the provided secret, returns the first 16 bytes encoded as lowercase
// base32 without padding, followed by "@scope".
func PairwiseID(cognitoSub, spEntityID, secret, scope string) string {
	// Create HMAC with the secret
	h := hmac.New(sha256.New, []byte(secret))

	// Write the input: sub|entityID
	input := fmt.Sprintf("%s|%s", cognitoSub, spEntityID)
	h.Write([]byte(input))

	// Get the HMAC digest
	digest := h.Sum(nil)

	// Take first 16 bytes
	truncated := digest[:16]

	// Encode as base32, convert to lowercase, remove padding
	encoded := base32.StdEncoding.EncodeToString(truncated)
	encoded = strings.ToLower(encoded)
	encoded = strings.TrimRight(encoded, "=")

	// Append @scope
	return encoded + "@" + scope
}
