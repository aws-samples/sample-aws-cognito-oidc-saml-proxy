package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTenantAPIWithApps builds a tenant API whose delete guard is wired to a
// real app store, so tests can exercise the "tenant still owns apps" path. It
// injects a global operator context so the CRUD-mechanics tests can act on
// arbitrary slugs; the cross-tenant guard is exercised by the authorization
// tests below.
func newTestTenantAPIWithApps(t *testing.T) (humatest.TestAPI, *store.TenantStore, *store.AppStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test")
	appStore := store.NewAppStore(memStore, "test")
	api.UseMiddleware(injectOnboardingTenant("gateway-ops", []string{middleware.GlobalOperatorGroup}))
	RegisterTenantRoutes(api, tenantStore, appStore, testKMSKeyPolicy())
	return api, tenantStore, appStore
}

// newTestTenantAPIAs builds a tenant API wired with a caller context of the
// given tenant slug and groups, so the cross-tenant IDOR guard (MF-1) can be
// exercised for callers other than a global operator.
func newTestTenantAPIAs(t *testing.T, callerSlug string, groups []string) (humatest.TestAPI, *store.TenantStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test")
	appStore := store.NewAppStore(memStore, "test")
	api.UseMiddleware(injectOnboardingTenant(callerSlug, groups))
	RegisterTenantRoutes(api, tenantStore, appStore, testKMSKeyPolicy())
	return api, tenantStore
}

// testKMSKeyPolicy returns a KMS key policy pinned to a fixed test account and
// region, mirroring a deployed (Strict) gateway so tests exercise the same
// validation path production uses.
func testKMSKeyPolicy() KMSKeyPolicy {
	return KMSKeyPolicy{AccountID: "111122223333", Region: "eu-north-1", Strict: true}
}

func TestDeleteTenant_Success(t *testing.T) {
	api, tenantStore, _ := newTestTenantAPIWithApps(t)
	require.NoError(t, tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug: "acme", DisplayName: "Acme", Status: "active", Plan: "standard",
	}))

	resp := api.Delete("/api/v1/tenants/acme")
	assert.Equal(t, http.StatusNoContent, resp.Code)

	_, err := tenantStore.Get(context.Background(), "acme")
	assert.Error(t, err, "tenant should be deleted")
}

func TestDeleteTenant_DefaultBlocked(t *testing.T) {
	api, tenantStore, _ := newTestTenantAPIWithApps(t)
	require.NoError(t, tenantStore.Create(context.Background(), tenant.NewDefaultTenant()))

	resp := api.Delete("/api/v1/tenants/" + tenant.DefaultSlug)
	assert.Equal(t, http.StatusBadRequest, resp.Code)

	_, err := tenantStore.Get(context.Background(), tenant.DefaultSlug)
	assert.NoError(t, err, "default tenant must not be deleted")
}

func TestDeleteTenant_NotFound(t *testing.T) {
	api, _, _ := newTestTenantAPIWithApps(t)
	resp := api.Delete("/api/v1/tenants/nonexistent")
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestDeleteTenant_WithAppsConflict(t *testing.T) {
	api, tenantStore, appStore := newTestTenantAPIWithApps(t)
	ctx := context.Background()
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug: "acme", DisplayName: "Acme", Status: "active", Plan: "standard",
	}))
	_, err := appStore.Create(ctx, "acme", &tenant.Application{
		DisplayName: "App", Protocol: "oidc", Status: "active",
	}, nil)
	require.NoError(t, err)

	resp := api.Delete("/api/v1/tenants/acme")
	assert.Equal(t, http.StatusConflict, resp.Code)

	_, err = tenantStore.Get(ctx, "acme")
	assert.NoError(t, err, "tenant with apps must not be deleted")
}

func TestCreateTenantWithDefaults(t *testing.T) {
	api, tenantStore := newTestTenantAPI(t)

	// Create tenant without specifying protocol defaults
	resp := api.Post("/api/v1/tenants", strings.NewReader(`{
		"slug": "test-org",
		"displayName": "Test Organization"
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify the tenant was created with correct defaults
	assert.Equal(t, "test-org", result["slug"])
	assert.Equal(t, "Test Organization", result["displayName"])
	assert.Equal(t, "standard", result["plan"])
	assert.Equal(t, "active", result["status"])

	// Verify SAML defaults
	assert.Equal(t, float64(3600), result["defaultSessionDurationSec"])
	assert.Equal(t, true, result["defaultSignResponse"])
	assert.Equal(t, true, result["defaultSignAssertion"])
	assert.Equal(t, "email", result["defaultNameIdFormat"])

	// Verify OIDC defaults
	assert.Equal(t, float64(3600), result["defaultIdTokenLifetimeSec"])
	assert.Equal(t, float64(3600), result["defaultAccessTokenLifetimeSec"])
	scopes, ok := result["defaultScopes"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, 3, len(scopes))
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "email")
	assert.Contains(t, scopes, "profile")

	// Verify we can retrieve the tenant with GET
	getResp := api.Get("/api/v1/tenants/test-org")
	assert.Equal(t, http.StatusOK, getResp.Code)

	var getTenant map[string]interface{}
	err = json.Unmarshal(getResp.Body.Bytes(), &getTenant)
	require.NoError(t, err)

	assert.Equal(t, float64(3600), getTenant["defaultSessionDurationSec"])
	assert.Equal(t, true, getTenant["defaultSignResponse"])
	assert.Equal(t, true, getTenant["defaultSignAssertion"])
	assert.Equal(t, "email", getTenant["defaultNameIdFormat"])

	_ = tenantStore // silence unused warning
}

func TestCreateTenantWithCustomDefaults(t *testing.T) {
	api, _ := newTestTenantAPI(t)

	// Create tenant with custom protocol defaults
	resp := api.Post("/api/v1/tenants", strings.NewReader(`{
		"slug": "custom-org",
		"displayName": "Custom Organization",
		"defaultSessionDurationSec": 7200,
		"defaultSignResponse": false,
		"defaultSignAssertion": false,
		"defaultNameIdFormat": "persistent",
		"defaultIdTokenLifetimeSec": 1800,
		"defaultAccessTokenLifetimeSec": 1800,
		"defaultScopes": ["openid", "email"]
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify custom defaults were applied
	assert.Equal(t, float64(7200), result["defaultSessionDurationSec"])
	assert.Equal(t, false, result["defaultSignResponse"])
	assert.Equal(t, false, result["defaultSignAssertion"])
	assert.Equal(t, "persistent", result["defaultNameIdFormat"])
	assert.Equal(t, float64(1800), result["defaultIdTokenLifetimeSec"])
	assert.Equal(t, float64(1800), result["defaultAccessTokenLifetimeSec"])
	scopes, ok := result["defaultScopes"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, 2, len(scopes))
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "email")
}

func TestUpdateTenantProtocolDefaults(t *testing.T) {
	api, _ := newTestTenantAPI(t)

	// Create tenant first
	resp := api.Post("/api/v1/tenants", strings.NewReader(`{
		"slug": "update-test",
		"displayName": "Update Test Org"
	}`))
	require.Equal(t, http.StatusOK, resp.Code)

	// Update protocol defaults
	updateResp := api.Put("/api/v1/tenants/update-test", strings.NewReader(`{
		"defaultSessionDurationSec": 5400,
		"defaultSignResponse": false,
		"defaultNameIdFormat": "transient",
		"defaultIdTokenLifetimeSec": 2700,
		"defaultScopes": ["openid"]
	}`))

	assert.Equal(t, http.StatusOK, updateResp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(updateResp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify updated values
	assert.Equal(t, float64(5400), result["defaultSessionDurationSec"])
	assert.Equal(t, false, result["defaultSignResponse"])
	assert.Equal(t, "transient", result["defaultNameIdFormat"])
	assert.Equal(t, float64(2700), result["defaultIdTokenLifetimeSec"])
	// DefaultSignAssertion should remain true (not updated)
	assert.Equal(t, true, result["defaultSignAssertion"])

	scopes, ok := result["defaultScopes"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, len(scopes))
	assert.Contains(t, scopes, "openid")

	// Verify we can retrieve the updated tenant with GET
	getResp := api.Get("/api/v1/tenants/update-test")
	assert.Equal(t, http.StatusOK, getResp.Code)

	var getTenant map[string]interface{}
	err = json.Unmarshal(getResp.Body.Bytes(), &getTenant)
	require.NoError(t, err)

	assert.Equal(t, float64(5400), getTenant["defaultSessionDurationSec"])
	assert.Equal(t, false, getTenant["defaultSignResponse"])
	assert.Equal(t, true, getTenant["defaultSignAssertion"])
	assert.Equal(t, "transient", getTenant["defaultNameIdFormat"])
}

func TestUpdateTenantPartialProtocolDefaults(t *testing.T) {
	api, _ := newTestTenantAPI(t)

	// Create tenant with default values
	resp := api.Post("/api/v1/tenants", strings.NewReader(`{
		"slug": "partial-update",
		"displayName": "Partial Update Org"
	}`))
	require.Equal(t, http.StatusOK, resp.Code)

	// Update only some protocol defaults
	updateResp := api.Put("/api/v1/tenants/partial-update", strings.NewReader(`{
		"displayName": "Updated Name",
		"defaultSessionDurationSec": 7200
	}`))

	assert.Equal(t, http.StatusOK, updateResp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(updateResp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify updated values
	assert.Equal(t, "Updated Name", result["displayName"])
	assert.Equal(t, float64(7200), result["defaultSessionDurationSec"])

	// Verify other defaults remain unchanged
	assert.Equal(t, true, result["defaultSignResponse"])
	assert.Equal(t, true, result["defaultSignAssertion"])
	assert.Equal(t, "email", result["defaultNameIdFormat"])
	assert.Equal(t, float64(3600), result["defaultIdTokenLifetimeSec"])
	assert.Equal(t, float64(3600), result["defaultAccessTokenLifetimeSec"])
}

// --- MF-1: cross-tenant IDOR / BOLA guard on the tenant-management CRUD plane ---
//
// v2-MF-1 was fixed for the onboarding handlers (requireOnboardingTenant) but the
// identical unguarded pattern was left on the tenant-CRUD handlers: any
// authenticated per-tenant admin could read, overwrite, or delete any other
// tenant and enumerate every tenant's KMS signing-key ARNs. These tests assert a
// non-operator caller is confined to its own tenant, mirroring
// TestOnboarding_CrossTenantRejected.

// seedTenant writes a tenant row directly into the store, bypassing the API, so
// the authorization tests start from a known cross-tenant fixture.
func seedTenant(t *testing.T, store *store.TenantStore, slug string) {
	t.Helper()
	require.NoError(t, store.Create(context.Background(), &tenant.Tenant{
		Slug: slug, DisplayName: slug, Status: "active", Plan: "standard",
	}))
}

func TestGetTenant_CrossTenantRejected(t *testing.T) {
	// Caller is a per-tenant admin for "attacker", targets "victim".
	api, store := newTestTenantAPIAs(t, "attacker", []string{"Admins"})
	seedTenant(t, store, "victim")

	resp := api.Get("/api/v1/tenants/victim")
	assert.Equal(t, http.StatusForbidden, resp.Code, "cross-tenant read must be rejected; body=%s", resp.Body.String())
	assert.NotContains(t, resp.Body.String(), "victim", "target tenant config must not leak on a rejected read")
}

func TestGetTenant_SameTenantAllowed(t *testing.T) {
	api, store := newTestTenantAPIAs(t, "acme", []string{"Admins"})
	seedTenant(t, store, "acme")

	resp := api.Get("/api/v1/tenants/acme")
	require.Equal(t, http.StatusOK, resp.Code, "same-tenant read must be allowed; body=%s", resp.Body.String())
}

func TestGetTenant_GlobalOperatorAllowedCrossTenant(t *testing.T) {
	api, store := newTestTenantAPIAs(t, "gateway-ops", []string{middleware.GlobalOperatorGroup})
	seedTenant(t, store, "victim")

	resp := api.Get("/api/v1/tenants/victim")
	require.Equal(t, http.StatusOK, resp.Code, "global operator must read any tenant; body=%s", resp.Body.String())
}

func TestUpdateTenant_CrossTenantRejected(t *testing.T) {
	api, store := newTestTenantAPIAs(t, "attacker", []string{"Admins"})
	seedTenant(t, store, "victim")

	resp := api.Put("/api/v1/tenants/victim", strings.NewReader(`{"displayName":"pwned"}`))
	assert.Equal(t, http.StatusForbidden, resp.Code, "cross-tenant update must be rejected; body=%s", resp.Body.String())

	// The victim's config must be untouched.
	v, err := store.Get(context.Background(), "victim")
	require.NoError(t, err)
	assert.Equal(t, "victim", v.DisplayName, "rejected update must not mutate the target tenant")
}

func TestDeleteTenant_CrossTenantRejected(t *testing.T) {
	api, store := newTestTenantAPIAs(t, "attacker", []string{"Admins"})
	seedTenant(t, store, "victim")

	resp := api.Delete("/api/v1/tenants/victim")
	assert.Equal(t, http.StatusForbidden, resp.Code, "cross-tenant delete must be rejected; body=%s", resp.Body.String())

	_, err := store.Get(context.Background(), "victim")
	assert.NoError(t, err, "rejected delete must leave the target tenant intact")
}

func TestListTenants_ScopedToCallerTenant(t *testing.T) {
	// A per-tenant admin sees only its own tenant, never the full roster.
	api, store := newTestTenantAPIAs(t, "acme", []string{"Admins"})
	seedTenant(t, store, "acme")
	seedTenant(t, store, "victim")
	seedTenant(t, store, "other")

	resp := api.Get("/api/v1/tenants")
	require.Equal(t, http.StatusOK, resp.Code, "body=%s", resp.Body.String())

	var listed []tenant.Tenant
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &listed))
	require.Len(t, listed, 1, "per-tenant admin must see only its own tenant")
	assert.Equal(t, "acme", listed[0].Slug)
}

func TestListTenants_GlobalOperatorSeesAll(t *testing.T) {
	api, store := newTestTenantAPIAs(t, "gateway-ops", []string{middleware.GlobalOperatorGroup})
	seedTenant(t, store, "acme")
	seedTenant(t, store, "victim")
	seedTenant(t, store, "other")

	resp := api.Get("/api/v1/tenants")
	require.Equal(t, http.StatusOK, resp.Code, "body=%s", resp.Body.String())

	var listed []tenant.Tenant
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &listed))
	assert.Len(t, listed, 3, "global operator must see every tenant")
}

func TestTenantCRUD_NoContextFailsClosed(t *testing.T) {
	// No tenant middleware wired at all — every handler must fail closed with 403.
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test")
	appStore := store.NewAppStore(memStore, "test")
	RegisterTenantRoutes(api, tenantStore, appStore, testKMSKeyPolicy())
	seedTenant(t, tenantStore, "acme")

	assert.Equal(t, http.StatusForbidden, api.Get("/api/v1/tenants").Code, "list must fail closed")
	assert.Equal(t, http.StatusForbidden, api.Get("/api/v1/tenants/acme").Code, "get must fail closed")
	assert.Equal(t, http.StatusForbidden, api.Put("/api/v1/tenants/acme", strings.NewReader(`{"displayName":"x"}`)).Code, "update must fail closed")
	assert.Equal(t, http.StatusForbidden, api.Delete("/api/v1/tenants/acme").Code, "delete must fail closed")
}
