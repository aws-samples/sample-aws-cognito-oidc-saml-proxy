package oidc

import (
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// defaultTokenLifetime applies to ID and access tokens whose configured
// lifetime is 0 (unset). The bounds live in the tenant package
// (tenant.TokenLifetimeMinSec / MaxSec): the management API refuses values
// outside them with 422 (finding M-8), and the token path clamps anyway so a
// record written by an older API can never mint a near-immortal token.
const defaultTokenLifetime = 1 * time.Hour

// boundedTokenLifetime converts a configured lifetime in seconds to a Duration
// clamped to [tenant.TokenLifetimeMinSec, tenant.TokenLifetimeMaxSec]; 0 means
// "default".
func boundedTokenLifetime(sec int) time.Duration {
	switch {
	case sec == 0:
		return defaultTokenLifetime
	case sec < tenant.TokenLifetimeMinSec:
		sec = tenant.TokenLifetimeMinSec
	case sec > tenant.TokenLifetimeMaxSec:
		sec = tenant.TokenLifetimeMaxSec
	}
	return time.Duration(sec) * time.Second
}

// Client implements op.Client by wrapping a tenant Application and its OIDCConfig.
type Client struct {
	app     *tenant.Application
	oidcCfg *tenant.OIDCConfig
}

// NewClient creates a Client from a tenant Application and OIDCConfig.
func NewClient(app *tenant.Application, oidcCfg *tenant.OIDCConfig) *Client {
	return &Client{app: app, oidcCfg: oidcCfg}
}

func (c *Client) GetID() string { return c.app.ID }

func (c *Client) RedirectURIs() []string {
	if c.oidcCfg == nil {
		return nil
	}
	return c.oidcCfg.RedirectURIs
}

func (c *Client) PostLogoutRedirectURIs() []string {
	if c.oidcCfg == nil {
		return nil
	}
	return c.oidcCfg.PostLogoutRedirectURIs
}

func (c *Client) ApplicationType() op.ApplicationType {
	return op.ApplicationTypeWeb
}

func (c *Client) AuthMethod() oidc.AuthMethod {
	if c.oidcCfg == nil {
		return oidc.AuthMethodBasic
	}
	switch c.oidcCfg.TokenEndpointAuthMethod {
	case "client_secret_post":
		return oidc.AuthMethodPost
	case "none":
		return oidc.AuthMethodNone
	default:
		return oidc.AuthMethodBasic
	}
}

func (c *Client) ResponseTypes() []oidc.ResponseType {
	if c.oidcCfg == nil {
		return []oidc.ResponseType{oidc.ResponseTypeCode}
	}
	types := make([]oidc.ResponseType, 0, len(c.oidcCfg.ResponseTypes))
	for _, rt := range c.oidcCfg.ResponseTypes {
		types = append(types, oidc.ResponseType(rt))
	}
	if len(types) == 0 {
		return []oidc.ResponseType{oidc.ResponseTypeCode}
	}
	return types
}

func (c *Client) GrantTypes() []oidc.GrantType {
	if c.oidcCfg == nil {
		return []oidc.GrantType{oidc.GrantTypeCode}
	}
	types := make([]oidc.GrantType, 0, len(c.oidcCfg.GrantTypes))
	for _, gt := range c.oidcCfg.GrantTypes {
		types = append(types, oidc.GrantType(gt))
	}
	if len(types) == 0 {
		return []oidc.GrantType{oidc.GrantTypeCode}
	}
	return types
}

func (c *Client) LoginURL(authRequestID string) string {
	// The login URL redirects to Cognito hosted UI for authentication.
	// In a full implementation, this would point to the gateway's login page
	// which then redirects to the configured Cognito identity source.
	return "/login?authRequestID=" + authRequestID
}

func (c *Client) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}


// IDTokenLifetime returns the client's IDTokenLifetimeSec bounded to the shared
// token-lifetime range, or the 1h default when unset.
func (c *Client) IDTokenLifetime() time.Duration {
	if c.oidcCfg == nil {
		return defaultTokenLifetime
	}
	return boundedTokenLifetime(c.oidcCfg.IDTokenLifetimeSec)
}

func (c *Client) DevMode() bool {
	return false
}

func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) IsScopeAllowed(scope string) bool {
	if c.oidcCfg == nil {
		// Default allowed scopes
		switch scope {
		case "openid", "profile", "email":
			return true
		}
		return false
	}
	for _, s := range c.oidcCfg.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (c *Client) IDTokenUserinfoClaimsAssertion() bool {
	// Return true to include userinfo claims (email, name, etc.) directly in the ID token.
	// When false, zitadel/oidc strips the email/profile scopes before calling
	// SetUserinfoFromScopes, resulting in an ID token with only sub/aud/iss.
	return true
}

func (c *Client) ClockSkew() time.Duration {
	return 0
}
