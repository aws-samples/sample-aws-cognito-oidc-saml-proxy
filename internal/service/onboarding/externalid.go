// Package onboarding implements the SaaS wizard state machine.
package onboarding

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
)

// externalIDBytes is the random-byte width. 32 bytes base32-encoded produces
// 52 chars (56 with padding, but we use raw encoding). Well inside AWS's
// ExternalId length bounds (2–1224 chars).
const externalIDBytes = 32

// GenerateExternalID returns a base32-encoded random string suitable for an
// AWS IAM trust-policy ExternalId condition. Per AWS confused-deputy guidance,
// the SaaS (us) generates the ExternalId — not the customer — and embeds it in
// both the trust policy (via the IaC we hand the customer) and the AssumeRole
// call.
//
// The returned value contains only [A-Z2-7], which is a strict subset of the
// characters AWS accepts in an ExternalId. It is non-guessable and unique per
// call with ~160 bits of entropy.
func GenerateExternalID() (string, error) {
	buf := make([]byte, externalIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("onboarding: generate ExternalID: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}
