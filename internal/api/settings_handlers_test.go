package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSettingsAPI creates a test API for settings endpoints with tenant injection.
func newTestSettingsAPI(t *testing.T) (humatest.TestAPI, *store.TenantStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test")

	// Inject tenant middleware
	api.UseMiddleware(injectTenantMiddleware(testTenantSlug))

	// Create settings service with test gateway config
	settingsSvc := service.NewSettingsService(tenantStore,
		"https://idp.example.com",                             // entityID
		"https://gateway.example.com",                         // baseURL
		"arn:aws:kms:eu-north-1:123456789012:key/test-key-id", // kmsKeyID
		"") // kmsKeyIDBackup

	// Register settings routes
	RegisterSettingsRoutes(api, settingsSvc)

	return api, tenantStore
}

func TestGetSettings(t *testing.T) {
	api, tenantStore := newTestSettingsAPI(t)

	// Create the test tenant
	err := tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug:             testTenantSlug,
		DisplayName:      "Test Tenant",
		Plan:             "standard",
		Status:           "active",
		MaxApps:          10,
		MaxAuthsPerMonth: 10000,
	})
	require.NoError(t, err)

	// Call GET /api/v1/settings
	resp := api.Get("/api/v1/settings")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify tenant section
	tenantData, ok := result["tenant"].(map[string]interface{})
	require.True(t, ok, "expected tenant object in response")
	assert.Equal(t, testTenantSlug, tenantData["slug"])
	assert.Equal(t, "Test Tenant", tenantData["displayName"])
	assert.Equal(t, "standard", tenantData["plan"])
	assert.Equal(t, "active", tenantData["status"])

	// Verify gateway section
	gatewayData, ok := result["gateway"].(map[string]interface{})
	require.True(t, ok, "expected gateway object in response")
	assert.Equal(t, "https://idp.example.com", gatewayData["entityId"])
	assert.Equal(t, "https://gateway.example.com", gatewayData["baseUrl"])
	assert.Equal(t, "arn:aws:kms:eu-north-1:123456789012:key/test-key-id", gatewayData["kmsKeyId"])
	assert.Equal(t, "https://gateway.example.com/t/"+testTenantSlug+"/saml/metadata", gatewayData["samlMetadataUrl"])
	assert.Equal(t, "https://gateway.example.com/t/"+testTenantSlug+"/oidc/.well-known/openid-configuration", gatewayData["oidcDiscoveryUrl"])
}

func TestGetSettingsTenantNotFound(t *testing.T) {
	api, _ := newTestSettingsAPI(t)

	// Don't create the tenant, so it will not be found

	resp := api.Get("/api/v1/settings")
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	// The 5xx sanitizer must scrub the internal cause: the client body carries a
	// generic message plus a correlation id, never the underlying error text.
	detail := result["detail"].(string)
	assert.Contains(t, detail, "internal server error")
	assert.Contains(t, detail, "correlation id")
	assert.NotContains(t, detail, "failed to load settings")
	assert.NotContains(t, detail, "not found")
}
