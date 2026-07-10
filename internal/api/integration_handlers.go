package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
)

// IntegrationInfoInput defines the path parameter for the integration endpoint.
type IntegrationInfoInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// IntegrationInfoOutput contains all connection details for configuring an SP/RP.
type IntegrationInfoOutput struct {
	Body struct {
		Application struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Protocol    string `json:"protocol"`
		} `json:"application"`

		// SAML-specific (only if protocol == "saml")
		SAML *SAMLIntegration `json:"saml,omitempty"`

		// OIDC-specific (only if protocol == "oidc", future)
		OIDC *OIDCIntegration `json:"oidc,omitempty"`

		// Framework quick-start snippets
		QuickStart map[string]string `json:"quickStart"`
	}
}

// SAMLIntegration contains SAML IdP connection details.
type SAMLIntegration struct {
	MetadataURL            string `json:"metadataUrl"`
	AppMetadataURL         string `json:"appMetadataUrl"`
	EntityID               string `json:"entityId"`
	SSOURL                 string `json:"ssoUrl"`
	SLOURL                 string `json:"sloUrl"`
	CertificateFingerprint string `json:"certificateFingerprint"`
	NameIDFormat           string `json:"nameIdFormat"`
}

// OIDCIntegration contains OIDC provider connection details (future).
type OIDCIntegration struct {
	DiscoveryURL     string   `json:"discoveryUrl"`
	ClientID         string   `json:"clientId"`
	AuthorizationURL string   `json:"authorizationUrl"`
	TokenURL         string   `json:"tokenUrl"`
	JWKSURL          string   `json:"jwksUrl"`
	UserInfoURL      string   `json:"userinfoUrl"`
	Scopes           []string `json:"scopes"`
}

// RegisterIntegrationRoutes registers the integration endpoint.
func RegisterIntegrationRoutes(api huma.API, apps domain.AppReader, baseURL string, certSvc *service.CertificateService) {
	huma.Register(api, huma.Operation{
		OperationID: "get-integration-info",
		Method:      http.MethodGet,
		Path:        "/api/v1/applications/{id}/integration",
		Summary:     "Get integration information",
		Description: "Returns all connection details needed to configure a Service Provider",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *IntegrationInfoInput) (*IntegrationInfoOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Load application
		app, err := apps.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		out := &IntegrationInfoOutput{}
		out.Body.Application.ID = app.ID
		out.Body.Application.DisplayName = app.DisplayName
		out.Body.Application.Protocol = app.Protocol

		// Build tenant-scoped URLs
		tenantBase := fmt.Sprintf("%s/t/%s", strings.TrimSuffix(baseURL, "/"), slug)

		// Protocol-specific integration info
		if strings.EqualFold(app.Protocol, "saml") {
			samlCfg, err := apps.GetSAMLConfig(ctx, slug, input.ID)
			if err != nil {
				return nil, huma.Error500InternalServerError("failed to get SAML config", err)
			}

			// Get certificate fingerprint from service
			certInfo, err := certSvc.GetInfo()
			if err != nil {
				return nil, huma.Error500InternalServerError("failed to get certificate info", err)
			}

			out.Body.SAML = &SAMLIntegration{
				MetadataURL:            fmt.Sprintf("%s/saml/metadata", tenantBase),
				AppMetadataURL:         fmt.Sprintf("%s/saml/metadata/%s", tenantBase, input.ID),
				EntityID:               fmt.Sprintf("%s/saml/metadata", tenantBase),
				SSOURL:                 fmt.Sprintf("%s/saml/sso", tenantBase),
				SLOURL:                 fmt.Sprintf("%s/saml/slo", tenantBase),
				CertificateFingerprint: certInfo.Fingerprint,
				NameIDFormat:           samlCfg.NameIDFormat,
			}

			out.Body.QuickStart = generateSAMLQuickStart(tenantBase, certInfo.Fingerprint, samlCfg.NameIDFormat)
		} else if strings.EqualFold(app.Protocol, "oidc") {
			// Future: OIDC integration info
			out.Body.OIDC = &OIDCIntegration{
				DiscoveryURL:     fmt.Sprintf("%s/oidc/.well-known/openid-configuration", tenantBase),
				ClientID:         app.ID,
				AuthorizationURL: fmt.Sprintf("%s/oidc/authorize", tenantBase),
				TokenURL:         fmt.Sprintf("%s/oidc/token", tenantBase),
				JWKSURL:          fmt.Sprintf("%s/oidc/.well-known/jwks.json", tenantBase),
				UserInfoURL:      fmt.Sprintf("%s/oidc/userinfo", tenantBase),
				Scopes:           []string{"openid", "profile", "email"},
			}

			out.Body.QuickStart = generateOIDCQuickStart(tenantBase, app.ID)
		}

		return out, nil
	})
}

// generateSAMLQuickStart generates framework-specific SAML configuration snippets.
func generateSAMLQuickStart(tenantBase, fingerprint, nameIDFormat string) map[string]string {
	metadataURL := fmt.Sprintf("%s/saml/metadata", tenantBase)
	ssoURL := fmt.Sprintf("%s/saml/sso", tenantBase)

	return map[string]string{
		"spring-boot": fmt.Sprintf(`# Spring Boot application.yml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          federation-gateway:
            assertingparty:
              metadata-uri: %s
              entity-id: %s/saml/metadata
              single-sign-on:
                url: %s
                binding: POST
              verification:
                credentials:
                  - certificate-location: classpath:saml-cert.pem
            entity-id: your-entity-id
            acs:
              location: "{baseUrl}/saml2/authenticate/federation-gateway"
              binding: POST`, metadataURL, tenantBase, ssoURL),

		"nextauth": fmt.Sprintf(`// NextAuth.js v5 - SAML Provider (future OIDC)
import NextAuth from "next-auth"
import { SamlProvider } from "@auth/saml-provider"

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    SamlProvider({
      id: "federation-gateway",
      name: "Federation Gateway",
      issuer: "%s/saml/metadata",
      clientId: "your-entity-id",
      clientSecret: process.env.SAML_CERT,
      metadata: "%s",
    })
  ]
})`, tenantBase, metadataURL),

		"aws-cli": fmt.Sprintf(`# AWS CLI SAML Profile Configuration
# Add to ~/.aws/config

[profile federation-gateway]
region = eu-north-1
output = json
credential_process = saml2aws login --idp-provider=generic --mfa=Auto --url=%s --skip-prompt --quiet`, ssoURL),

		"python-saml": fmt.Sprintf(`# python3-saml settings
SAML_SETTINGS = {
    'strict': True,
    'debug': False,
    'sp': {
        'entityId': 'your-entity-id',
        'assertionConsumerService': {
            'url': 'https://yourapp.example.com/saml/acs',
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        },
        'NameIDFormat': '%s',
    },
    'idp': {
        'entityId': '%s/saml/metadata',
        'singleSignOnService': {
            'url': '%s',
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        },
        'x509cert': 'your-idp-certificate',
    }
}`, nameIDFormat, tenantBase, ssoURL),

		"onelogin-saml": fmt.Sprintf(`# Ruby/Rails - OneLogin SAML Gem
# config/initializers/saml.rb

SAML_SETTINGS = {
  assertion_consumer_service_url: "https://yourapp.example.com/saml/acs",
  issuer: "your-entity-id",
  idp_sso_target_url: "%s",
  idp_cert_fingerprint: "%s",
  name_identifier_format: "%s",
  idp_entity_id: "%s/saml/metadata"
}`, ssoURL, fingerprint, nameIDFormat, tenantBase),
	}
}

// generateOIDCQuickStart generates framework-specific OIDC configuration snippets.
func generateOIDCQuickStart(tenantBase, clientID string) map[string]string {
	discoveryURL := fmt.Sprintf("%s/oidc/.well-known/openid-configuration", tenantBase)

	return map[string]string{
		"nextauth": fmt.Sprintf(`// NextAuth.js v5 - OIDC Provider
import NextAuth from "next-auth"

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    {
      id: "federation-gateway",
      name: "Federation Gateway",
      type: "oidc",
      issuer: "%s",
      clientId: "%s",
      clientSecret: process.env.AUTH_CLIENT_SECRET,
      wellKnown: "%s",
    }
  ]
})`, tenantBase+"/oidc", clientID, discoveryURL),

		"spring-boot": fmt.Sprintf(`# Spring Boot application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          federation-gateway:
            provider: federation-gateway
            client-id: %s
            client-secret: ${CLIENT_SECRET}
            scope: openid,profile,email
            redirect-uri: "{baseUrl}/login/oauth2/code/federation-gateway"
        provider:
          federation-gateway:
            issuer-uri: %s/oidc
            authorization-uri: %s/oidc/authorize
            token-uri: %s/oidc/token
            user-info-uri: %s/oidc/userinfo
            jwk-set-uri: %s/oidc/.well-known/jwks.json`, clientID, tenantBase, tenantBase, tenantBase, tenantBase, tenantBase),

		"express-passport": fmt.Sprintf(`// Express.js + Passport OIDC
const passport = require('passport');
const { Strategy } = require('openid-client');

const issuer = await Issuer.discover('%s/oidc');
const client = new issuer.Client({
  client_id: '%s',
  client_secret: process.env.CLIENT_SECRET,
  redirect_uris: ['http://localhost:3000/callback'],
  response_types: ['code'],
});

passport.use('oidc', new Strategy({ client }, (tokenSet, done) => {
  return done(null, tokenSet.claims());
}));`, tenantBase, clientID),

		"python-authlib": fmt.Sprintf(`# Python Authlib OIDC Configuration
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    name='federation_gateway',
    client_id='%s',
    client_secret=os.getenv('CLIENT_SECRET'),
    server_metadata_url='%s',
    client_kwargs={
        'scope': 'openid profile email'
    }
)`, clientID, discoveryURL),
	}
}
