// Package crypto — shared cookie-key provisioning.
//
// The SAML and OIDC login flows carry state across requests in signed and
// encrypted cookies (saml_flow, saml_session, oidc_flow, the __Host- login
// binding cookies). Before M-3 each Lambda instance asked KMS for a fresh
// random data key at cold start, so a cookie minted by one instance was
// unreadable by every other instance — the flow only worked when the same
// container happened to serve both halves of a login.
//
// FetchCookieKey retrieves a single 32-byte key from AWS Secrets Manager so
// every instance of saml-sso and oidc-authorize (and a deployed cmd/proxy
// monolith) shares the same root key. SignedCookie derives per-purpose HMAC
// and AES subkeys from it. Rotation: taint the Terraform random_bytes resource
// and apply; all existing cookies are invalidated and users re-authenticate.
package crypto

import "context"

// FetchCookieKey fetches the shared cookie root key from Secrets Manager.
// The secret must contain exactly 32 bytes as SecretBinary. If the secret is
// absent, too short, or too long, an error is returned and the Lambda aborts
// at boot — fail closed rather than operating with an unpredictable key.
//
// secretARN may be a full ARN or a secret name; Secrets Manager resolves both.
// Unlike FetchEdgeSecret, an empty ARN is not a local-dev shortcut: callers
// decide whether a per-process random key is acceptable for their environment.
func FetchCookieKey(ctx context.Context, client OIDCCryptoKeyClient, secretARN string) ([]byte, error) {
	return fetchSecretKey32(ctx, client, secretARN, "cookie key")
}
