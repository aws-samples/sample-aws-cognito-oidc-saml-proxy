package tenant

import (
	"net/url"
	"strings"
	"time"
)

// Tenant represents a customer organization in the multi-tenant system.
type Tenant struct {
	Slug             string    `dynamo:"slug" json:"slug"`
	DisplayName      string    `dynamo:"displayName" json:"displayName"`
	Plan             string    `dynamo:"plan" json:"plan"`
	Domain           string    `dynamo:"domain,omitempty" json:"domain,omitempty"`
	Status           string    `dynamo:"status" json:"status"`
	MaxApps          int       `dynamo:"maxApps" json:"maxApps"`
	MaxAuthsPerMonth int       `dynamo:"maxAuthsPerMonth" json:"maxAuthsPerMonth"`
	KMSKeyID         string    `dynamo:"kmsKeyId,omitempty" json:"kmsKeyId,omitempty"`
	KMSKeyArn        string    `dynamo:"kmsKeyArn,omitempty" json:"kmsKeyArn,omitempty"`
	CreatedAt        time.Time `dynamo:"createdAt" json:"createdAt"`
	UpdatedAt        time.Time `dynamo:"updatedAt" json:"updatedAt"`

	// SAML defaults (applied when creating apps that don't override)
	DefaultSessionDurationSec int    `dynamo:"defaultSessionDurationSec" json:"defaultSessionDurationSec"`
	DefaultSignResponse       bool   `dynamo:"defaultSignResponse" json:"defaultSignResponse"`
	DefaultSignAssertion      bool   `dynamo:"defaultSignAssertion" json:"defaultSignAssertion"`
	DefaultNameIDFormat       string `dynamo:"defaultNameIdFormat" json:"defaultNameIdFormat"`

	// OIDC defaults
	DefaultIDTokenLifetimeSec     int      `dynamo:"defaultIdTokenLifetimeSec" json:"defaultIdTokenLifetimeSec"`
	DefaultAccessTokenLifetimeSec int      `dynamo:"defaultAccessTokenLifetimeSec" json:"defaultAccessTokenLifetimeSec"`
	DefaultScopes                 []string `dynamo:"defaultScopes" json:"defaultScopes"`

	// Onboarding (populated by the SaaS onboarding wizard; legacy tenants have zero values)
	OnboardingState string          `dynamo:"onboardingState,omitempty" json:"onboardingState,omitempty"`
	CapabilityMap   map[string]bool `dynamo:"capabilityMap,omitempty" json:"capabilityMap,omitempty"`
}

// IdentitySource represents an AWS Cognito User Pool configured as an identity provider.
type IdentitySource struct {
	ID          string    `dynamo:"id" json:"id"`
	TenantSlug  string    `dynamo:"tenantSlug" json:"-"`
	DisplayName string    `dynamo:"displayName" json:"displayName"`
	Type        string    `dynamo:"type" json:"type"`
	PoolID      string    `dynamo:"poolId" json:"poolId"`
	Region      string    `dynamo:"region" json:"region"`
	Domain      string    `dynamo:"domain" json:"domain"`
	ClientID    string    `dynamo:"clientId" json:"clientId"`
	Status      string    `dynamo:"status" json:"status"`
	CreatedAt   time.Time `dynamo:"createdAt" json:"createdAt"`
	UpdatedAt   time.Time `dynamo:"updatedAt" json:"updatedAt"`

	// Cross-account access (populated by the onboarding wizard; legacy sources have zero values
	// and use the public-client PKCE path).
	RoleArn    string `dynamo:"roleArn,omitempty" json:"roleArn,omitempty"`
	ExternalID string `dynamo:"externalId,omitempty" json:"-"`
	SecretArn  string `dynamo:"secretArn,omitempty" json:"secretArn,omitempty"`
}

// Application represents a SAML or OIDC application that users authenticate to.
type Application struct {
	ID          string    `dynamo:"id" json:"id"`
	TenantSlug  string    `dynamo:"tenantSlug" json:"-"`
	DisplayName string    `dynamo:"displayName" json:"displayName"`
	Protocol    string    `dynamo:"protocol" json:"protocol"`
	SourceID    string    `dynamo:"sourceId" json:"sourceId"`
	Status      string    `dynamo:"status" json:"status"`
	CreatedAt   time.Time `dynamo:"createdAt" json:"createdAt"`
	UpdatedAt   time.Time `dynamo:"updatedAt" json:"updatedAt"`

	// CustomLoginURL, when set, REPLACES the Cognito Hosted UI for interactive
	// login: an unauthenticated user is redirected here instead of to Cognito.
	// The custom page authenticates the user and hands a Cognito ID token back
	// to the gateway's session-establish endpoint to resume the SSO flow.
	CustomLoginURL string `dynamo:"customLoginUrl,omitempty" json:"customLoginUrl,omitempty"`
	// TrustedLoginRedirectURIs is the allowlist of permitted login-page URLs.
	// CustomLoginURL must be covered by this list. Entries must be https URLs.
	TrustedLoginRedirectURIs []string `dynamo:"trustedLoginRedirectUris,omitempty" json:"trustedLoginRedirectUris,omitempty"`
}

// HasCustomLogin reports whether a custom login page is configured for this app.
func (a *Application) HasCustomLogin() bool {
	return strings.TrimSpace(a.CustomLoginURL) != ""
}

// IsTrustedLoginRedirect reports whether candidate is an allowed login-page
// redirect target. Matching is done on parsed URL COMPONENTS, never on a raw
// string prefix. A candidate is trusted only when, for some allow-list
// entry, the scheme (https), host, and port match exactly and the candidate's
// path is either equal to the entry's path or extends it at a "/" boundary.
//
// String-prefix matching is unsafe: with
// "https://app.example.com" allow-listed, both "https://app.example.com.evil.com"
// and "https://app.example.com@evil.com" pass strings.HasPrefix and redirect the
// user to an attacker-controlled host. Any candidate (or allow-list entry)
// carrying userinfo ("user@host") is rejected outright. An empty allow-list
// trusts nothing.
func (a *Application) IsTrustedLoginRedirect(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	cu, err := url.Parse(candidate)
	if err != nil || !strings.EqualFold(cu.Scheme, "https") {
		return false
	}
	// Reject userinfo — "https://trusted.example.com@evil.com" has Host=evil.com
	// but is a classic open-redirect disguise. A legitimate redirect target never
	// carries credentials.
	if cu.User != nil {
		return false
	}
	if cu.Host == "" {
		return false
	}

	for _, allowed := range a.TrustedLoginRedirectURIs {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		au, err := url.Parse(allowed)
		if err != nil || au.User != nil || au.Host == "" {
			continue
		}
		if !strings.EqualFold(au.Scheme, "https") {
			continue
		}
		// Exact scheme + host (host includes port) match, case-insensitive on host.
		if !strings.EqualFold(cu.Host, au.Host) {
			continue
		}
		if pathWithinBoundary(cu.EscapedPath(), au.EscapedPath()) {
			return true
		}
	}
	return false
}

// pathWithinBoundary reports whether candidate path p is equal to the allowed
// path a, or extends it at a "/" segment boundary. This prevents
// "/appfoo" from matching an allow-listed "/app" while still allowing
// "/app" and "/app/anything". An empty or "/" allowed path matches any path
// under the (already exactly-matched) host.
func pathWithinBoundary(p, a string) bool {
	if a == "" || a == "/" {
		return true
	}
	// Normalize away a single trailing slash on the allow-list entry so that
	// "/app" and "/app/" are treated the same as a base.
	base := strings.TrimSuffix(a, "/")
	if p == base {
		return true
	}
	return strings.HasPrefix(p, base+"/")
}

// SAMLConfig contains SAML-specific configuration for an application.
type SAMLConfig struct {
	EntityID                string   `dynamo:"entityId" json:"entityId"`
	AcsURL                  string   `dynamo:"acsUrl" json:"acsUrl"`
	AcsURLs                 []string `dynamo:"acsUrls" json:"acsUrls"`
	MetadataURL             string   `dynamo:"metadataUrl,omitempty" json:"metadataUrl,omitempty"`
	SigningCertPem          string   `dynamo:"signingCertPem,omitempty" json:"-"`
	EncryptionCertPem       string   `dynamo:"encryptionCertPem,omitempty" json:"-"`
	NameIDFormat            string   `dynamo:"nameIdFormat" json:"nameIdFormat"`
	NameIDSource            string   `dynamo:"nameIdSource" json:"nameIdSource"`
	SignResponse            bool     `dynamo:"signResponse" json:"signResponse"`
	SignAssertion           bool     `dynamo:"signAssertion" json:"signAssertion"`
	EncryptAssertion        bool     `dynamo:"encryptAssertion" json:"encryptAssertion"`
	WantAuthnRequestsSigned bool     `dynamo:"wantAuthnRequestsSigned" json:"wantAuthnRequestsSigned"`
	// AllowIDPInitiated permits unsolicited (IdP-initiated) SSO into this SP via
	// the gateway's /saml/idp-initiate endpoint. Disabled by default — it is an
	// opt-in because IdP-initiated SSO is a known abuse/phishing vector.
	AllowIDPInitiated  bool   `dynamo:"allowIdpInitiated" json:"allowIdpInitiated"`
	SloURL             string `dynamo:"sloUrl,omitempty" json:"sloUrl,omitempty"`
	SessionDurationSec int    `dynamo:"sessionDurationSec" json:"sessionDurationSec"`
	ClockSkewSec       int    `dynamo:"clockSkewSec" json:"clockSkewSec"`
	// AllowInsecureSHA1 opts this SP into accepting SHA-1 redirect-binding
	// signature algorithms (rsa-sha1 / ecdsa-sha1). SHA-1 is collision-feasible
	// and disabled by default; enable only for a legacy SP that cannot sign with
	// SHA-256+, and treat it as a deprecation path. Its use is logged.
	//
	// Authorization: this field is intentionally excluded from SAMLConfigInput
	// (internal/api/app_types.go) so it cannot be set via the tenant-admin
	// create/update API. It can only be written by a GlobalOperatorGroup caller
	// via a direct DynamoDB management operation or a future operator-only
	// management endpoint. Do NOT add it to SAMLConfigInput.
	AllowInsecureSHA1 bool `dynamo:"allowInsecureSha1,omitempty" json:"allowInsecureSha1,omitempty"`
}

// ClaimMapping defines how to transform Cognito JWT claims to SAML attributes.
type ClaimMapping struct {
	Name            string `dynamo:"name" json:"name"`
	SourceType      string `dynamo:"sourceType" json:"sourceType"`
	SourceAttribute string `dynamo:"sourceAttribute" json:"sourceAttribute"`
	TargetAttribute string `dynamo:"targetAttribute" json:"targetAttribute"`
	Required        bool   `dynamo:"required" json:"required"`
	DefaultValue    string `dynamo:"defaultValue,omitempty" json:"defaultValue,omitempty"`
}

// RoleMapping defines how Cognito groups map to SAML role attributes.
type RoleMapping struct {
	CognitoGroup string `dynamo:"cognitoGroup" json:"cognitoGroup"`
	MappedValue  string `dynamo:"mappedValue" json:"mappedValue"`
}

// OIDCConfig contains OIDC-specific configuration for an application.
type OIDCConfig struct {
	ClientSecret            string   `dynamo:"clientSecret" json:"-"`
	RedirectURIs            []string `dynamo:"redirectURIs" json:"redirectURIs"`
	PostLogoutRedirectURIs  []string `dynamo:"postLogoutRedirectURIs" json:"postLogoutRedirectURIs"`
	GrantTypes              []string `dynamo:"grantTypes" json:"grantTypes"`
	ResponseTypes           []string `dynamo:"responseTypes" json:"responseTypes"`
	Scopes                  []string `dynamo:"scopes" json:"scopes"`
	TokenEndpointAuthMethod string   `dynamo:"tokenEndpointAuthMethod" json:"tokenEndpointAuthMethod"`
	IDTokenLifetimeSec      int      `dynamo:"idTokenLifetimeSec" json:"idTokenLifetimeSec"`
	AccessTokenLifetimeSec  int      `dynamo:"accessTokenLifetimeSec" json:"accessTokenLifetimeSec"`
	// RefreshTokenLifetimeSec bounds how long a refresh token remains valid.
	// Only relevant when GrantTypes includes "refresh_token" and the client
	// requests the "offline_access" scope. Zero falls back to the gateway
	// default (see internal/oidc).
	RefreshTokenLifetimeSec int `dynamo:"refreshTokenLifetimeSec" json:"refreshTokenLifetimeSec"`
}
