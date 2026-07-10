package oidc

import (
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func newTestClient(app *tenant.Application, cfg *tenant.OIDCConfig) *Client {
	return NewClient(app, cfg)
}

func TestClient_GetID(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-123"}, nil)
	assert.Equal(t, "app-123", c.GetID())
}

func TestClient_RedirectURIs_NilConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Nil(t, c.RedirectURIs())
}

func TestClient_RedirectURIs_WithConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	assert.Equal(t, []string{"https://app.example.com/callback"}, c.RedirectURIs())
}

func TestClient_PostLogoutRedirectURIs_NilConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Nil(t, c.PostLogoutRedirectURIs())
}

func TestClient_PostLogoutRedirectURIs_WithConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		PostLogoutRedirectURIs: []string{"https://app.example.com/logout"},
	})
	assert.Equal(t, []string{"https://app.example.com/logout"}, c.PostLogoutRedirectURIs())
}

func TestClient_ApplicationType(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, op.ApplicationTypeWeb, c.ApplicationType())
}

func TestClient_AuthMethod_NilConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, oidc.AuthMethodBasic, c.AuthMethod())
}

func TestClient_AuthMethod_Post(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		TokenEndpointAuthMethod: "client_secret_post",
	})
	assert.Equal(t, oidc.AuthMethodPost, c.AuthMethod())
}

func TestClient_AuthMethod_None(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		TokenEndpointAuthMethod: "none",
	})
	assert.Equal(t, oidc.AuthMethodNone, c.AuthMethod())
}

func TestClient_AuthMethod_Default(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	assert.Equal(t, oidc.AuthMethodBasic, c.AuthMethod())
}

func TestClient_ResponseTypes_NilConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, []oidc.ResponseType{oidc.ResponseTypeCode}, c.ResponseTypes())
}

func TestClient_ResponseTypes_WithConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		ResponseTypes: []string{"code", "id_token"},
	})
	types := c.ResponseTypes()
	assert.Len(t, types, 2)
	assert.Equal(t, oidc.ResponseType("code"), types[0])
}

func TestClient_ResponseTypes_EmptyConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		ResponseTypes: []string{},
	})
	assert.Equal(t, []oidc.ResponseType{oidc.ResponseTypeCode}, c.ResponseTypes())
}

func TestClient_GrantTypes_NilConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, []oidc.GrantType{oidc.GrantTypeCode}, c.GrantTypes())
}

func TestClient_GrantTypes_WithConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		GrantTypes: []string{"authorization_code", "refresh_token"},
	})
	types := c.GrantTypes()
	assert.Len(t, types, 2)
}

func TestClient_GrantTypes_EmptyConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		GrantTypes: []string{},
	})
	assert.Equal(t, []oidc.GrantType{oidc.GrantTypeCode}, c.GrantTypes())
}

func TestClient_LoginURL(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, "/login?authRequestID=req-abc", c.LoginURL("req-abc"))
}

func TestClient_AccessTokenType(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, op.AccessTokenTypeBearer, c.AccessTokenType())
}

func TestClient_IDTokenLifetime_Default(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, 1*time.Hour, c.IDTokenLifetime())
}

func TestClient_IDTokenLifetime_Custom(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		IDTokenLifetimeSec: 1800,
	})
	assert.Equal(t, 30*time.Minute, c.IDTokenLifetime())
}

func TestClient_DevMode(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.False(t, c.DevMode())
}

func TestClient_RestrictAdditionalIdTokenScopes(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	fn := c.RestrictAdditionalIdTokenScopes()
	scopes := []string{"openid", "profile"}
	assert.Equal(t, scopes, fn(scopes))
}

func TestClient_RestrictAdditionalAccessTokenScopes(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	fn := c.RestrictAdditionalAccessTokenScopes()
	scopes := []string{"openid", "email"}
	assert.Equal(t, scopes, fn(scopes))
}

func TestClient_IsScopeAllowed_NilConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.True(t, c.IsScopeAllowed("openid"))
	assert.True(t, c.IsScopeAllowed("profile"))
	assert.True(t, c.IsScopeAllowed("email"))
	assert.False(t, c.IsScopeAllowed("custom"))
}

func TestClient_IsScopeAllowed_WithConfig(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, &tenant.OIDCConfig{
		Scopes: []string{"openid", "custom:scope"},
	})
	assert.True(t, c.IsScopeAllowed("openid"))
	assert.True(t, c.IsScopeAllowed("custom:scope"))
	assert.False(t, c.IsScopeAllowed("profile"))
}

func TestClient_IDTokenUserinfoClaimsAssertion(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.True(t, c.IDTokenUserinfoClaimsAssertion())
}

func TestClient_ClockSkew(t *testing.T) {
	c := newTestClient(&tenant.Application{ID: "app-1"}, nil)
	assert.Equal(t, time.Duration(0), c.ClockSkew())
}
