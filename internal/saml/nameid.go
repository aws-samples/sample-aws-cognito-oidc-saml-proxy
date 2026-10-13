package saml

import (
	"strings"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// NameID fallback reasons reported by resolveNameID. They are logged so an
// operator can see why an SP received a persistent `sub` instead of the
// configured email NameID.
const (
	// nameIDReasonEmailUnverified: the app asked for an email NameID but Cognito
	// did not assert email_verified=true (or the token carried no email), so the
	// gateway issued a persistent NameID = Cognito sub instead (finding M-6).
	nameIDReasonEmailUnverified = "email_unverified"
	// nameIDReasonNoSubject: the token carried no `sub`; no NameID can be issued
	// and the caller must fail closed.
	nameIDReasonNoSubject = "no_subject"
)

// resolveNameID chooses the SAML Subject NameID for a session from the app's
// stored NameIDFormat/NameIDSource and the verified Cognito claims.
//
// The email address is usable as an identifier ONLY when the token carries a
// non-empty `email` AND Cognito asserts `email_verified=true`. An unverified
// email is attacker-chosen at sign-up and must never become the subject an SP
// keys its accounts on (finding M-6). Whenever email is requested but not
// usable, the gateway falls back to a persistent NameID equal to the raw
// Cognito `sub`, which is stable for the user and cannot be chosen by them.
//
// Rules, in order:
//   - no sub                       -> ("", "", no_subject); caller fails closed
//   - format email OR source email -> email if usable, else (sub, persistent, email_unverified)
//   - format transient             -> (sessionID, transient)
//   - format persistent            -> (sub, persistent)
//   - unspecified / custom format  -> value from source (email only if usable,
//     otherwise sub), format left as configured
//
// cfg may be nil (legacy single-tenant path); it is treated as unspecified
// format with source sub.
func resolveNameID(claims *cognito.UserClaims, cfg *tenant.SAMLConfig, sessionID string) (value, format, reason string) {
	if claims == nil || claims.Sub == "" {
		return "", "", nameIDReasonNoSubject
	}

	var requestedFormat, source string
	if cfg != nil {
		requestedFormat = cfg.NameIDFormat
		source = cfg.NameIDSource
	}
	format = tenant.CanonicalNameIDFormat(requestedFormat)
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = "sub"
	}

	emailUsable := claims.Email != "" && claims.EmailVerified

	switch {
	case format == tenant.NameIDFormatEmail || source == "email":
		if emailUsable {
			return claims.Email, tenant.NameIDFormatEmail, ""
		}
		return claims.Sub, tenant.NameIDFormatPersistent, nameIDReasonEmailUnverified
	case format == tenant.NameIDFormatTransient:
		return sessionID, tenant.NameIDFormatTransient, ""
	case format == tenant.NameIDFormatPersistent:
		return claims.Sub, tenant.NameIDFormatPersistent, ""
	default:
		// Unspecified or a custom format with a non-email source (the email
		// source was handled above): the only other identifier the gateway
		// vouches for is the Cognito sub. The format is left as configured.
		return claims.Sub, format, ""
	}
}
