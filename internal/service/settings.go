package service

import (
	"context"
	"fmt"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// GatewayInfo contains gateway-level configuration and metadata.
type GatewayInfo struct {
	EntityID         string
	BaseURL          string
	KMSKeyID         string
	KMSKeyIDBackup   string
	SAMLMetadataURL  string
	OIDCDiscoveryURL string
}

// Settings combines tenant configuration with gateway information.
type Settings struct {
	Tenant  tenant.Tenant
	Gateway GatewayInfo
}

// SettingsService provides gateway and tenant configuration.
type SettingsService struct {
	tenants        domain.TenantReader
	entityID       string
	baseURL        string
	kmsKeyID       string
	kmsKeyIDBackup string
}

// NewSettingsService creates a new settings service.
func NewSettingsService(tenants domain.TenantReader, entityID, baseURL, kmsKeyID, kmsKeyIDBackup string) *SettingsService {
	return &SettingsService{
		tenants:        tenants,
		entityID:       entityID,
		baseURL:        baseURL,
		kmsKeyID:       kmsKeyID,
		kmsKeyIDBackup: kmsKeyIDBackup,
	}
}

// GetSettings returns the tenant configuration and gateway information for the specified tenant.
func (s *SettingsService) GetSettings(ctx context.Context, tenantSlug string) (*Settings, error) {
	t, err := s.tenants.Get(ctx, tenantSlug)
	if err != nil {
		return nil, fmt.Errorf("failed to load tenant: %w", err)
	}

	return &Settings{
		Tenant: *t,
		Gateway: GatewayInfo{
			EntityID:         s.entityID,
			BaseURL:          s.baseURL,
			KMSKeyID:         s.kmsKeyID,
			KMSKeyIDBackup:   s.kmsKeyIDBackup,
			SAMLMetadataURL:  s.baseURL + "/t/" + tenantSlug + "/saml/metadata",
			OIDCDiscoveryURL: s.baseURL + "/t/" + tenantSlug + "/oidc/.well-known/openid-configuration",
		},
	}, nil
}
