package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// mockTenantReader provides test tenants.
type mockTenantReader struct {
	tenant *tenant.Tenant
	err    error
}

func (m *mockTenantReader) Get(_ context.Context, slug string) (*tenant.Tenant, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}
	return m.tenant, nil
}

func (m *mockTenantReader) List(_ context.Context) ([]*tenant.Tenant, error) {
	return nil, nil
}

func TestSettingsService_GetSettings(t *testing.T) {
	testTenant := &tenant.Tenant{
		Slug:        "acme",
		DisplayName: "Acme Corporation",
		Plan:        "enterprise",
		Status:      "active",
	}

	tenantReader := &mockTenantReader{tenant: testTenant}
	svc := NewSettingsService(
		tenantReader,
		"https://idp.example.com",
		"https://proxy.example.com",
		"arn:aws:kms:us-east-1:123456789012:key/abc-123",
		"",
	)

	settings, err := svc.GetSettings(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}

	// Verify tenant information
	if settings.Tenant.Slug != "acme" {
		t.Errorf("expected tenant slug=acme, got %s", settings.Tenant.Slug)
	}

	if settings.Tenant.DisplayName != "Acme Corporation" {
		t.Errorf("expected tenant displayName=Acme Corporation, got %s", settings.Tenant.DisplayName)
	}

	// Verify gateway information
	if settings.Gateway.EntityID != "https://idp.example.com" {
		t.Errorf("expected entityID=https://idp.example.com, got %s", settings.Gateway.EntityID)
	}

	if settings.Gateway.BaseURL != "https://proxy.example.com" {
		t.Errorf("expected baseURL=https://proxy.example.com, got %s", settings.Gateway.BaseURL)
	}

	if settings.Gateway.KMSKeyID != "arn:aws:kms:us-east-1:123456789012:key/abc-123" {
		t.Errorf("expected kmsKeyID=arn:aws:kms:us-east-1:123456789012:key/abc-123, got %s", settings.Gateway.KMSKeyID)
	}

	// Verify generated URLs
	expectedMetadataURL := "https://proxy.example.com/t/acme/saml/metadata"
	if settings.Gateway.SAMLMetadataURL != expectedMetadataURL {
		t.Errorf("expected SAMLMetadataURL=%s, got %s", expectedMetadataURL, settings.Gateway.SAMLMetadataURL)
	}

	expectedDiscoveryURL := "https://proxy.example.com/t/acme/oidc/.well-known/openid-configuration"
	if settings.Gateway.OIDCDiscoveryURL != expectedDiscoveryURL {
		t.Errorf("expected OIDCDiscoveryURL=%s, got %s", expectedDiscoveryURL, settings.Gateway.OIDCDiscoveryURL)
	}
}

func TestSettingsService_GetSettings_TenantNotFound(t *testing.T) {
	tenantReader := &mockTenantReader{err: fmt.Errorf("tenant not found")}
	svc := NewSettingsService(
		tenantReader,
		"https://idp.example.com",
		"https://proxy.example.com",
		"",
		"",
	)

	_, err := svc.GetSettings(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestSettingsService_GetSettings_MultiTenant(t *testing.T) {
	tenants := map[string]*tenant.Tenant{
		"tenant1": {
			Slug:        "tenant1",
			DisplayName: "Tenant One",
			Status:      "active",
		},
		"tenant2": {
			Slug:        "tenant2",
			DisplayName: "Tenant Two",
			Status:      "active",
		},
	}

	for slug, expectedTenant := range tenants {
		tenantReader := &mockTenantReader{tenant: expectedTenant}
		svc := NewSettingsService(
			tenantReader,
			"https://idp.example.com",
			"https://proxy.example.com",
			"",
			"",
		)

		settings, err := svc.GetSettings(context.Background(), slug)
		if err != nil {
			t.Fatalf("GetSettings failed for %s: %v", slug, err)
		}

		if settings.Tenant.Slug != slug {
			t.Errorf("expected slug=%s, got %s", slug, settings.Tenant.Slug)
		}

		// Verify metadata URL is tenant-specific
		expectedMetadataURL := "https://proxy.example.com/t/" + slug + "/saml/metadata"
		if settings.Gateway.SAMLMetadataURL != expectedMetadataURL {
			t.Errorf("expected SAMLMetadataURL=%s, got %s", expectedMetadataURL, settings.Gateway.SAMLMetadataURL)
		}
	}
}
