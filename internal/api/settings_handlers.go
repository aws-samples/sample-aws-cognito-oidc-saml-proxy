package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// GatewayInfo contains gateway-level configuration and metadata.
type GatewayInfo struct {
	EntityID         string `json:"entityId" doc:"SAML Entity ID for the IdP"`
	BaseURL          string `json:"baseUrl" doc:"Base URL for the gateway"`
	KMSKeyID         string `json:"kmsKeyId,omitempty" doc:"KMS key ID for SAML signing"`
	KMSKeyIDBackup   string `json:"kmsKeyIdBackup,omitempty" doc:"KMS key ID for the backup signing certificate"`
	SAMLMetadataURL  string `json:"samlMetadataUrl" doc:"URL to tenant SAML IdP metadata"`
	OIDCDiscoveryURL string `json:"oidcDiscoveryUrl" doc:"URL to tenant OIDC discovery document"`
}

// SettingsOutput combines tenant configuration with gateway information.
type SettingsOutput struct {
	Body struct {
		Tenant  tenant.Tenant `json:"tenant" doc:"Tenant configuration"`
		Gateway GatewayInfo   `json:"gateway" doc:"Gateway configuration and metadata"`
	}
}

// RegisterSettingsRoutes registers the settings endpoint.
func RegisterSettingsRoutes(api huma.API, settingsSvc *service.SettingsService) {
	huma.Register(api, huma.Operation{
		OperationID: "get-settings",
		Method:      http.MethodGet,
		Path:        "/api/v1/settings",
		Summary:     "Get gateway settings",
		Description: "Returns tenant configuration and gateway information",
		Tags:        []string{"Settings"},
	}, func(ctx context.Context, input *struct{}) (*SettingsOutput, error) {
		// Get tenant slug from context (set by tenant middleware)
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Delegate to service
		settings, err := settingsSvc.GetSettings(ctx, slug)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to load settings", err)
		}

		out := &SettingsOutput{}
		out.Body.Tenant = settings.Tenant
		out.Body.Gateway = GatewayInfo{
			EntityID:         settings.Gateway.EntityID,
			BaseURL:          settings.Gateway.BaseURL,
			KMSKeyID:         settings.Gateway.KMSKeyID,
			KMSKeyIDBackup:   settings.Gateway.KMSKeyIDBackup,
			SAMLMetadataURL:  settings.Gateway.SAMLMetadataURL,
			OIDCDiscoveryURL: settings.Gateway.OIDCDiscoveryURL,
		}
		return out, nil
	})
}
