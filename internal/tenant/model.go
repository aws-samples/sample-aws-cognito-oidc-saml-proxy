package tenant

import (
	"net/url"
	"strings"
	"time"
)

// Tenant represents a customer organization in the multi-tenant system.
type Tenant struct {
	Slug             string `dynamo:"slug" json:"slug"`
	DisplayName      string `dynamo:"displayName" json:"displayName"`
	Plan             string `dynamo:"plan" json:"plan"`
	Domain           string `dynamo:"domain,omitempty" json:"domain,omitempty"`
	Status           string `dynamo:"status" json:"status"`
	MaxApps          int    `dynamo:"maxApps" json:"maxApps"`
	MaxAuthsPerMonth int    `dynamo:"maxAuthsPerMonth" json:"maxAuthsPerMonth"`
	// KMSKeyID and KMSKeyArn are legacy fields from a never-shipped per-tenant
	// signing-key feature. Nothing reads them: every tenant signs with the
	// single gateway KMS key (plus the optional backup key during rotation), and
	// the management API refuses a request that sets either (422).
	KMSKeyID  string    `dynamo:"kmsKeyId,omitempty" json:"kmsKeyId,omitempty"`
	KMSKeyArn string    `dynamo:"kmsKeyArn,omitempty" json:"kmsKeyArn,omitempty"`
	CreatedAt time.Time `dynamo:"createdAt" json:"createdAt"`
	UpdatedAt time.Time `dynamo:"updatedAt" json:"updatedAt"`

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

// IsTrustedBrowserOrigin reports whether origin — the value of a browser's
// Origin header, "scheme://host[:port]" — is one of the origins this app's
// custom login page or trusted login redirect targets are served from. It is
// the anti-CSRF gate for browser form posts to the IdP-initiated SSO endpoint
// (finding M-4): a cross-site page can make a user's browser POST an id_token,
// but it cannot forge the Origin header, so only the pages an admin has
// explicitly allow-listed may launch IdP-initiated SSO from a form.
//
// Matching is an exact scheme + host + port comparison (case-insensitive on
// scheme and host) against the origin component of CustomLoginURL and every
// TrustedLoginRedirectURIs entry; paths are ignored because Origin never
// carries one. Anything that is not an https origin, that has a path, query,
// fragment or userinfo, or that has no host, is rejected. An empty origin or
// an app with no login-page URLs trusts nothing.
func (a *Application) IsTrustedBrowserOrigin(origin string) bool {
	oScheme, oHost, ok := parseOrigin(strings.TrimSpace(origin))
	if !ok {
		return false
	}
	candidates := make([]string, 0, len(a.TrustedLoginRedirectURIs)+1)
	if u := strings.TrimSpace(a.CustomLoginURL); u != "" {
		candidates = append(candidates, u)
	}
	candidates = append(candidates, a.TrustedLoginRedirectURIs...)
	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		au, err := url.Parse(raw)
		if err != nil || au.User != nil || au.Host == "" || !strings.EqualFold(au.Scheme, "https") {
			continue
		}
		if strings.EqualFold(au.Scheme, oScheme) && strings.EqualFold(au.Host, oHost) {
			return true
		}
	}
	return false
}

// parseOrigin splits a serialised origin into its scheme and host[:port]. It
// accepts only the exact "https://host[:port]" shape — no path (a bare "/" is
// tolerated because some clients serialise it), query, fragment or userinfo.
func parseOrigin(origin string) (scheme, host string, ok bool) {
	if origin == "" {
		return "", "", false
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Host == "" || u.Opaque != "" {
		return "", "", false
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", "", false
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	return u.Scheme, u.Host, true
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

// Bounds for the timing fields on SAMLConfig and OIDCConfig. The management
// API refuses values outside these ranges with 422 (0 means "use the default");
// the protocol paths clamp anyway so a record written by an older API or
// imported directly can never yield a zero-length or multi-day session/token
// (appsec finding M-8).
const (
	// SessionDurationMinSec / SessionDurationMaxSec bound SAMLConfig.SessionDurationSec.
	SessionDurationMinSec = 300
	SessionDurationMaxSec = 86400
	// ClockSkewMinSec / ClockSkewMaxSec bound SAMLConfig.ClockSkewSec.
	ClockSkewMinSec = 0
	ClockSkewMaxSec = 600
	// TokenLifetimeMinSec / TokenLifetimeMaxSec bound OIDCConfig.IDTokenLifetimeSec
	// and OIDCConfig.AccessTokenLifetimeSec.
	TokenLifetimeMinSec = 60
	TokenLifetimeMaxSec = 86400
)

// SAMLConfig contains SAML-specific configuration for an application.
type SAMLConfig struct {
	EntityID          string   `dynamo:"entityId" json:"entityId"`
	AcsURL            string   `dynamo:"acsUrl" json:"acsUrl"`
	AcsURLs           []string `dynamo:"acsUrls" json:"acsUrls"`
	MetadataURL       string   `dynamo:"metadataUrl,omitempty" json:"metadataUrl,omitempty"`
	SigningCertPem    string   `dynamo:"signingCertPem,omitempty" json:"-"`
	EncryptionCertPem string   `dynamo:"encryptionCertPem,omitempty" json:"-"`
	NameIDFormat      string   `dynamo:"nameIdFormat" json:"nameIdFormat"`
	NameIDSource      string   `dynamo:"nameIdSource" json:"nameIdSource"`
	// SignResponse and SignAssertion are always true: the gateway signs both the
	// SAML response and the assertion (RSA-SHA256 via KMS) and the API refuses
	// an attempt to set either to false. They remain as fields so the stored
	// record states the behaviour explicitly.
	SignResponse  bool `dynamo:"signResponse" json:"signResponse"`
	SignAssertion bool `dynamo:"signAssertion" json:"signAssertion"`
	// EncryptAssertion controls whether the SP's encryption certificate
	// (EncryptionCertPem, imported from its metadata) is advertised to the IdP
	// engine, which encrypts the assertion whenever one is present. The API
	// refuses true without a stored certificate; false means the stored
	// certificate is ignored and the assertion is sent signed but in clear.
	EncryptAssertion bool `dynamo:"encryptAssertion" json:"encryptAssertion"`
	// WantAuthnRequestsSigned is stored for import fidelity only. It is not
	// settable via the API and NOT honoured — AuthnRequest signature
	// verification is not implemented — so the SSO path refuses an SP with it
	// set (SPProvider fails closed) rather than pretend requests are verified.
	WantAuthnRequestsSigned bool `dynamo:"wantAuthnRequestsSigned" json:"wantAuthnRequestsSigned"`
	// AllowIDPInitiated permits unsolicited (IdP-initiated) SSO into this SP via
	// the gateway's /saml/idp-initiate endpoint. Disabled by default — it is an
	// opt-in because IdP-initiated SSO is a known abuse/phishing vector.
	AllowIDPInitiated bool   `dynamo:"allowIdpInitiated" json:"allowIdpInitiated"`
	SloURL            string `dynamo:"sloUrl,omitempty" json:"sloUrl,omitempty"`
	// SessionDurationSec is the SAML session lifetime (saml_session cookie and
	// the assertion's SessionNotOnOrAfter), bounded by SessionDurationMinSec /
	// SessionDurationMaxSec; 0 means the gateway default (8h).
	SessionDurationSec int `dynamo:"sessionDurationSec" json:"sessionDurationSec"`
	// ClockSkewSec is the allowance subtracted from the assertion's
	// Conditions.NotBefore, bounded by ClockSkewMinSec / ClockSkewMaxSec; 0
	// means the gateway default (180s).
	ClockSkewSec int `dynamo:"clockSkewSec" json:"clockSkewSec"`
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

// IsCognitoSource reports whether a ClaimMapping.SourceType selects a value
// from the user's Cognito claims. "cognito" is the canonical value; "attribute"
// is the alias the registration wizard writes (see api.toClaimMappings) and
// must resolve identically, otherwise wizard-created mappings silently release
// nothing. Both the SAML assertion maker and the mapping preview use this.
func IsCognitoSource(sourceType string) bool {
	switch sourceType {
	case "cognito", "attribute":
		return true
	}
	return false
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
	// IDTokenLifetimeSec and AccessTokenLifetimeSec are bounded by
	// TokenLifetimeMinSec / TokenLifetimeMaxSec; 0 means the gateway default (1h).
	IDTokenLifetimeSec     int `dynamo:"idTokenLifetimeSec" json:"idTokenLifetimeSec"`
	AccessTokenLifetimeSec int `dynamo:"accessTokenLifetimeSec" json:"accessTokenLifetimeSec"`
	// RefreshTokenLifetimeSec bounds how long a refresh token remains valid.
	// Only relevant when GrantTypes includes "refresh_token" and the client
	// requests the "offline_access" scope. Zero falls back to the gateway
	// default (see internal/oidc).
	RefreshTokenLifetimeSec int `dynamo:"refreshTokenLifetimeSec" json:"refreshTokenLifetimeSec"`
}
