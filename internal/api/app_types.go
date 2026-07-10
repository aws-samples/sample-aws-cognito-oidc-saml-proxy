package api

import "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"

// SAMLConfigInput is the nested SAML configuration block accepted on
// create/update. Mirrors the nested `saml` object returned by AppOutput.
type SAMLConfigInput struct {
	EntityID           string   `json:"entityId,omitempty" format:"uri" doc:"SAML Entity ID"`
	AcsURL             string   `json:"acsUrl,omitempty" format:"uri" doc:"Primary ACS URL"`
	AcsURLs            []string `json:"acsUrls,omitempty" doc:"Additional ACS URLs"`
	MetadataURL        string   `json:"metadataUrl,omitempty" format:"uri" doc:"SP metadata URL"`
	NameIDFormat       string   `json:"nameIdFormat,omitempty" doc:"NameID format (short code like 'email'/'persistent' or a full SAML NameID-Format URN)"`
	NameIDSource       string   `json:"nameIdSource,omitempty" doc:"Cognito attribute for NameID"`
	SignResponse       *bool    `json:"signResponse,omitempty"`
	SignAssertion      *bool    `json:"signAssertion,omitempty"`
	EncryptAssertion   *bool    `json:"encryptAssertion,omitempty"`
	AllowIDPInitiated  *bool    `json:"allowIdpInitiated,omitempty" doc:"Allow IdP-initiated SSO into this SP (default false)"`
	SloURL             string   `json:"sloUrl,omitempty" format:"uri" doc:"Single Logout URL"`
	SessionDurationSec int      `json:"sessionDurationSec,omitempty" doc:"Session duration in seconds"`
	ClockSkewSec       int      `json:"clockSkewSec,omitempty" doc:"Clock skew tolerance in seconds"`
}

// OIDCConfigInput is the nested OIDC configuration block accepted on
// create/update. Mirrors the nested `oidc` object returned by AppOutput.
type OIDCConfigInput struct {
	RedirectURIs            []string `json:"redirectURIs,omitempty" doc:"OAuth 2.0 redirect URIs"`
	PostLogoutRedirectURIs  []string `json:"postLogoutRedirectURIs,omitempty" doc:"Post-logout redirect URIs"`
	GrantTypes              []string `json:"grantTypes,omitempty" doc:"Allowed OAuth 2.0 grant types"`
	ResponseTypes           []string `json:"responseTypes,omitempty" doc:"Allowed OAuth 2.0 response types"`
	Scopes                  []string `json:"scopes,omitempty" doc:"Allowed OAuth 2.0 scopes"`
	TokenEndpointAuthMethod string   `json:"tokenEndpointAuthMethod,omitempty" doc:"Token endpoint authentication method"`
	IDTokenLifetimeSec      int      `json:"idTokenLifetimeSec,omitempty" doc:"ID token lifetime in seconds"`
	AccessTokenLifetimeSec  int      `json:"accessTokenLifetimeSec,omitempty" doc:"Access token lifetime in seconds"`
	RefreshTokenLifetimeSec int      `json:"refreshTokenLifetimeSec,omitempty" doc:"Refresh token lifetime in seconds (requires the refresh_token grant and offline_access scope; 0 uses the gateway default of 30 days)"`
}

// ClaimMappingInput is the simplified claim mapping shape used by the
// application wizard (source attribute -> target attribute).
type ClaimMappingInput struct {
	Source string `json:"source" doc:"Source Cognito claim/attribute"`
	Target string `json:"target" doc:"Target attribute name"`
}

// RoleMappingInput is the simplified role mapping shape used by the application
// wizard (Cognito group -> mapped role value).
type RoleMappingInput struct {
	Group string `json:"group" doc:"Cognito group"`
	Value string `json:"value" doc:"Mapped role value"`
}

// CreateAppInput defines the request schema for creating an application.
type CreateAppInput struct {
	Body struct {
		DisplayName   string              `json:"displayName" minLength:"1" maxLength:"255" doc:"Human-readable application name"`
		Protocol      string              `json:"protocol,omitempty" enum:"saml,oidc" default:"saml" doc:"Application protocol"`
		SourceID      string              `json:"sourceId,omitempty" doc:"Identity source ID"`
		SAML          *SAMLConfigInput    `json:"saml,omitempty" doc:"SAML configuration (required when protocol=saml)"`
		OIDC          *OIDCConfigInput    `json:"oidc,omitempty" doc:"OIDC configuration (required when protocol=oidc)"`
		ClaimMappings []ClaimMappingInput `json:"claimMappings,omitempty" doc:"Claim mappings"`
		RoleMappings  []RoleMappingInput  `json:"roleMappings,omitempty" doc:"Role mappings"`

		CustomLoginURL           string   `json:"customLoginUrl,omitempty" doc:"Custom login page URL. When set, REPLACES the Cognito Hosted UI: unauthenticated users are redirected here instead. Must be https and covered by trustedLoginRedirectUris."`
		TrustedLoginRedirectURIs []string `json:"trustedLoginRedirectUris,omitempty" doc:"Allowlist of permitted login-page redirect URLs (https). customLoginUrl must be covered by this list."`
	}
}

// AppOutput wraps an Application and optional SAMLConfig/OIDCConfig for API responses.
type AppOutput struct {
	Body struct {
		tenant.Application
		SAML *tenant.SAMLConfig `json:"saml,omitempty"`
		OIDC *tenant.OIDCConfig `json:"oidc,omitempty"`
		// ClientSecret is the plaintext OIDC client secret. It is returned ONCE,
		// only when a confidential client's secret is first generated (on create
		// or when switching a client to a confidential auth method). It is never
		// returned on read. Store it securely; it cannot be retrieved again.
		ClientSecret string `json:"clientSecret,omitempty" doc:"Newly generated OIDC client secret, shown once. Empty unless a confidential client secret was just created."`
	}
}

// ListAppsOutput is the response for listing applications.
type ListAppsOutput struct {
	Body []tenant.Application
}

// GetAppInput defines the path parameter for application endpoints.
type GetAppInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// UpdateAppInput defines the request schema for updating an application.
type UpdateAppInput struct {
	ID   string `path:"id" doc:"Application ID"`
	Body struct {
		DisplayName   string              `json:"displayName" minLength:"1" maxLength:"255" doc:"Human-readable application name"`
		Protocol      string              `json:"protocol,omitempty" enum:"saml,oidc" doc:"Application protocol"`
		SourceID      string              `json:"sourceId,omitempty" doc:"Identity source ID"`
		SAML          *SAMLConfigInput    `json:"saml,omitempty" doc:"SAML configuration (when protocol=saml)"`
		OIDC          *OIDCConfigInput    `json:"oidc,omitempty" doc:"OIDC configuration (when protocol=oidc)"`
		ClaimMappings []ClaimMappingInput `json:"claimMappings,omitempty" doc:"Claim mappings"`
		RoleMappings  []RoleMappingInput  `json:"roleMappings,omitempty" doc:"Role mappings"`

		CustomLoginURL           *string   `json:"customLoginUrl,omitempty" doc:"Custom login page URL. When set, REPLACES the Cognito Hosted UI: unauthenticated users are redirected here instead. Must be https and covered by trustedLoginRedirectUris. Omit to leave unchanged."`
		TrustedLoginRedirectURIs *[]string `json:"trustedLoginRedirectUris,omitempty" doc:"Allowlist of permitted login-page redirect URLs (https). customLoginUrl must be covered by this list. Omit to leave unchanged."`
	}
}

// DeleteAppInput defines the path parameter for deleting an application.
type DeleteAppInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// EnableAppInput defines the path parameter for enabling an application.
type EnableAppInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// DisableAppInput defines the path parameter for disabling an application.
type DisableAppInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// PreviewInput defines the request schema for claim mapping preview.
type PreviewInput struct {
	ID   string `path:"id" doc:"Application ID"`
	Body struct {
		Sub    string   `json:"sub" doc:"Test user subject"`
		Email  string   `json:"email" doc:"Test user email"`
		Groups []string `json:"groups,omitempty" doc:"Test user groups"`
	}
}

// PreviewOutput defines the response schema for claim mapping preview.
type PreviewOutput struct {
	Body struct {
		Protocol string `json:"protocol" doc:"saml or oidc"`
		Preview  string `json:"preview" doc:"Assertion XML or token claims JSON"`
	}
}

// ImportAppInput defines the request schema for importing an application from SP metadata.
type ImportAppInput struct {
	Body struct {
		MetadataURL string `json:"metadataUrl" format:"uri" doc:"URL to the SP SAML metadata XML"`
		SourceID    string `json:"sourceId,omitempty" doc:"Identity source ID"`
		DisplayName string `json:"displayName,omitempty" doc:"Human-readable name (defaults to entityId)"`
	}
}

// ValidateAppInput defines the path parameter for validating an application.
type ValidateAppInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// ValidateAppOutput is the response for application validation.
type ValidateAppOutput struct {
	Body struct {
		Valid    bool     `json:"valid" doc:"Whether the application configuration is valid"`
		Errors   []string `json:"errors" doc:"Validation errors"`
		Warnings []string `json:"warnings" doc:"Validation warnings"`
	}
}

// RotateSecretInput defines the path parameter for rotating OIDC client secrets.
type RotateSecretInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// RotateSecretOutput is the response for client secret rotation.
type RotateSecretOutput struct {
	Body struct {
		ClientSecret string `json:"clientSecret" doc:"New client secret (shown once)"`
	}
}
