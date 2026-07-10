package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAnalyticsAPI(t *testing.T) humatest.TestAPI {
	t.Helper()
	t.Setenv("PROXY_ENVIRONMENT", "local")
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	appStore := store.NewAppStore(configDB, "test")
	auditStore := store.NewAuditStore(sessionDB, "test")
	tenantStore := store.NewTenantStore(configDB, "test")

	// Create tenant and middleware context
	ctx := context.Background()
	_ = tenantStore.Create(ctx, &tenant.Tenant{
		Slug: testTenantSlug, DisplayName: "Test", Plan: "free", Status: "active",
	})

	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	RegisterAnalyticsRoutes(api, appStore, auditStore)
	return api
}

func TestAnalyticsOverview(t *testing.T) {
	api := newTestAnalyticsAPI(t)

	resp := api.Get("/api/v1/analytics/overview")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	// Without tenant context in humatest, counts will be 0
	assert.NotNil(t, result["totalSPs"])
	assert.NotNil(t, result["totalAuths"])
}

func TestAppMetrics(t *testing.T) {
	api := newTestAnalyticsAPI(t)

	resp := api.Get("/api/v1/analytics/applications/app-123")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "app-123", result["appId"])
	assert.Equal(t, float64(0), result["authCount"])
	assert.Equal(t, float64(0), result["avgLatency"])
}
