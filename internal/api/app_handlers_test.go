package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTenantSlug = "test-tenant"

// injectTenantMiddleware returns a Huma middleware that injects a test tenant
// into the request context.
func injectTenantMiddleware(slug string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		t := &tenant.Tenant{
			Slug:        slug,
			DisplayName: "Test Tenant",
			Plan:        "standard",
			Status:      "active",
		}
		newGoCtx := tenant.WithContext(ctx.Context(), t)
		next(huma.WithContext(ctx, newGoCtx))
	}
}

// newTestAPIWithMiddleware creates a humatest API with a Huma-level middleware
// that injects a test tenant into every request context.
func newTestAPIWithMiddleware(t *testing.T) (humatest.TestAPI, *store.AppStore, *store.ClaimStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	memStore := store.NewMemoryStore()
	appStore := store.NewAppStore(memStore, "test")
	claimStore := store.NewClaimStore(memStore, "test")

	// Create services
	importSvc := service.NewMetadataImportService(appStore, &service.HTTPMetadataFetcher{})
	previewSvc := service.NewPreviewService(appStore, claimStore)

	api.UseMiddleware(injectTenantMiddleware(testTenantSlug))

	RegisterAppRoutes(api, appStore, claimStore, importSvc, previewSvc)
	RegisterMappingRoutes(api, appStore, claimStore)

	return api, appStore, claimStore
}

// newTestTenantAPI creates a test API for tenant endpoints. It injects a global
// operator context so the CRUD-mechanics tests can operate on arbitrary slugs;
// the per-handler cross-tenant guard (MF-1) is exercised separately by the
// authorization tests in tenant_handlers_test.go.
func newTestTenantAPI(t *testing.T) (humatest.TestAPI, *store.TenantStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test")
	appStore := store.NewAppStore(memStore, "test")

	api.UseMiddleware(injectOnboardingTenant("gateway-ops", []string{middleware.GlobalOperatorGroup}))
	RegisterTenantRoutes(api, tenantStore, appStore, testKMSKeyPolicy())
	return api, tenantStore
}

// newTestSourceAPI creates a test API for source endpoints with tenant injection.
func newTestSourceAPI(t *testing.T) (humatest.TestAPI, *store.SourceStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	memStore := store.NewMemoryStore()
	sourceStore := store.NewSourceStore(memStore, "test")

	api.UseMiddleware(injectTenantMiddleware(testTenantSlug))

	// Inject a permissive connectivity probe so tests can point the "test
	// source" endpoint at loopback httptest servers. Production uses the
	// SSRF-hardened probe (the default); this double is test-only.
	RegisterSourceRoutes(api, sourceStore, WithConnectivityProbe(func(ctx context.Context, testURL string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			return nil, err
		}
		return (&http.Client{Timeout: 5 * time.Second}).Do(req)
	}))
	return api, sourceStore
}

// --- Application handler tests ---

func TestCreateApplication(t *testing.T) {
	api, _, _ := newTestAPIWithMiddleware(t)

	resp := api.Post("/api/v1/applications", strings.NewReader(`{
		"displayName": "Test App",
		"protocol": "saml",
		"saml": {
			"entityId": "https://test.example.com",
			"acsUrl": "https://test.example.com/acs"
		}
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.NotEmpty(t, result["id"])
	assert.Equal(t, "Test App", result["displayName"])
	assert.Equal(t, "active", result["status"])
}

func TestCreateOIDCApplication(t *testing.T) {
	api, _, _ := newTestAPIWithMiddleware(t)

	resp := api.Post("/api/v1/applications", strings.NewReader(`{
		"displayName": "Test OIDC App",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://app.example.com/callback"],
			"scopes": ["openid", "profile", "email"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "client_secret_basic",
			"idTokenLifetimeSec": 3600,
			"accessTokenLifetimeSec": 7200
		}
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.NotEmpty(t, result["id"])
	assert.Equal(t, "Test OIDC App", result["displayName"])
	assert.Equal(t, "oidc", result["protocol"])
	assert.Equal(t, "active", result["status"])

	// Verify OIDC config is present in response
	oidcCfg, ok := result["oidc"].(map[string]interface{})
	require.True(t, ok, "OIDC config should be present in response")
	assert.NotNil(t, oidcCfg["redirectURIs"])
	assert.NotNil(t, oidcCfg["scopes"])

	// Test GET to verify OIDC config persists
	appID := result["id"].(string)
	getResp := api.Get("/api/v1/applications/" + appID)
	assert.Equal(t, http.StatusOK, getResp.Code)

	var getResult map[string]interface{}
	err = json.Unmarshal(getResp.Body.Bytes(), &getResult)
	require.NoError(t, err)
	assert.Equal(t, "oidc", getResult["protocol"])

	getOidcCfg, ok := getResult["oidc"].(map[string]interface{})
	require.True(t, ok, "OIDC config should be present in GET response")
	assert.Equal(t, "client_secret_basic", getOidcCfg["tokenEndpointAuthMethod"])
	assert.Equal(t, float64(3600), getOidcCfg["idTokenLifetimeSec"])
	assert.Equal(t, float64(7200), getOidcCfg["accessTokenLifetimeSec"])
}

func TestListApplications(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create two apps directly in the store
	app1 := &tenant.Application{
		DisplayName: "App 1",
		Protocol:    "saml",
		Status:      "active",
	}
	app2 := &tenant.Application{
		DisplayName: "App 2",
		Protocol:    "saml",
		Status:      "active",
	}

	_, err := appStore.Create(context.Background(), testTenantSlug, app1, nil)
	require.NoError(t, err)
	_, err = appStore.Create(context.Background(), testTenantSlug, app2, nil)
	require.NoError(t, err)

	resp := api.Get("/api/v1/applications")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result []map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestGetApplicationByID(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:     "https://test.example.com",
		AcsURL:       "https://test.example.com/acs",
		NameIDFormat: "persistent",
		NameIDSource: "sub",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, samlCfg)
	require.NoError(t, err)

	resp := api.Get("/api/v1/applications/" + id)
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, id, result["id"])
	assert.Equal(t, "Test App", result["displayName"])
	// SAML config should be present
	assert.NotNil(t, result["saml"])
}

func TestGetApplicationNotFound(t *testing.T) {
	api, _, _ := newTestAPIWithMiddleware(t)

	resp := api.Get("/api/v1/applications/nonexistent")
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestEnableDisableApplication(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create an active app
	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		Status:      "active",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	// Disable it
	resp := api.Post("/api/v1/applications/" + id + "/disable")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "disabled", result["status"])

	// Enable it
	resp = api.Post("/api/v1/applications/" + id + "/enable")
	assert.Equal(t, http.StatusOK, resp.Code)

	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "active", result["status"])
}

func TestDeleteApplication(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		Status:      "active",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	// Delete it (hard delete removes the record)
	resp := api.Delete("/api/v1/applications/" + id)
	assert.Equal(t, http.StatusNoContent, resp.Code)

	// Verify it's actually gone from the store.
	_, err = appStore.Get(context.Background(), testTenantSlug, id)
	assert.Error(t, err)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestUpdateApplication(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		Status:      "active",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	resp := api.Put("/api/v1/applications/"+id, strings.NewReader(`{
		"displayName": "Updated App",
		"protocol": "saml"
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "Updated App", result["displayName"])
}

func TestUpdateOIDCApplication(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create OIDC app
	app := &tenant.Application{
		DisplayName: "Test OIDC App",
		Protocol:    "oidc",
		Status:      "active",
	}
	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		Scopes:                  []string{"openid", "profile"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		IDTokenLifetimeSec:      3600,
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)
	err = appStore.UpdateOIDCConfig(context.Background(), testTenantSlug, id, oidcCfg)
	require.NoError(t, err)

	// Update the OIDC config
	resp := api.Put("/api/v1/applications/"+id, strings.NewReader(`{
		"displayName": "Updated OIDC App",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://new.example.com/callback", "https://app.example.com/callback"],
			"scopes": ["openid", "profile", "email"],
			"grantTypes": ["authorization_code", "refresh_token"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "client_secret_post",
			"idTokenLifetimeSec": 7200,
			"accessTokenLifetimeSec": 3600
		}
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "Updated OIDC App", result["displayName"])

	// Verify OIDC config was updated
	oidcResult, ok := result["oidc"].(map[string]interface{})
	require.True(t, ok, "OIDC config should be present")
	assert.Equal(t, "client_secret_post", oidcResult["tokenEndpointAuthMethod"])
	assert.Equal(t, float64(7200), oidcResult["idTokenLifetimeSec"])
	assert.Equal(t, float64(3600), oidcResult["accessTokenLifetimeSec"])

	redirects := oidcResult["redirectURIs"].([]interface{})
	assert.Len(t, redirects, 2)
}

// --- Claim mapping tests ---

func TestClaimMappings(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		Status:      "active",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	// Put claim mappings
	resp := api.Put("/api/v1/applications/"+id+"/claim-mappings", strings.NewReader(`{
		"mappings": [
			{
				"name": "email",
				"sourceType": "cognito",
				"sourceAttribute": "email",
				"targetAttribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
				"required": true
			}
		]
	}`))
	assert.Equal(t, http.StatusOK, resp.Code)

	var putResult map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &putResult)
	require.NoError(t, err)
	assert.Equal(t, float64(1), putResult["updated"])

	// Get claim mappings
	resp = api.Get("/api/v1/applications/" + id + "/claim-mappings")
	assert.Equal(t, http.StatusOK, resp.Code)

	var mappings []map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &mappings)
	require.NoError(t, err)
	assert.Len(t, mappings, 1)
	assert.Equal(t, "email", mappings[0]["name"])
}

func TestRoleMappings(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		Status:      "active",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	// Put role mappings
	resp := api.Put("/api/v1/applications/"+id+"/role-mappings", strings.NewReader(`{
		"mappings": [
			{
				"cognitoGroup": "admins",
				"mappedValue": "urn:example:role:admin"
			}
		]
	}`))
	assert.Equal(t, http.StatusOK, resp.Code)

	// Get role mappings
	resp = api.Get("/api/v1/applications/" + id + "/role-mappings")
	assert.Equal(t, http.StatusOK, resp.Code)

	var mappings []map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &mappings)
	require.NoError(t, err)
	assert.Len(t, mappings, 1)
	assert.Equal(t, "admins", mappings[0]["cognitoGroup"])
}

func TestClaimMappingsPreview_SAML(t *testing.T) {
	api, appStore, claimStore := newTestAPIWithMiddleware(t)

	// Create SAML application
	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		Status:      "active",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	// Set up claim mappings
	claimMappings := []tenant.ClaimMapping{
		{
			Name:            "email",
			SourceType:      "cognito",
			SourceAttribute: "email",
			TargetAttribute: "urn:oid:0.9.2342.19200300.100.1.3",
			Required:        true,
		},
		{
			Name:            "department",
			SourceType:      "static",
			TargetAttribute: "urn:oid:2.5.4.11",
			DefaultValue:    "Engineering",
		},
	}
	err = claimStore.PutClaimMappings(context.Background(), testTenantSlug, id, claimMappings)
	require.NoError(t, err)

	// Set up role mappings
	roleMappings := []tenant.RoleMapping{
		{
			CognitoGroup: "admins",
			MappedValue:  "urn:example:role:admin",
		},
		{
			CognitoGroup: "users",
			MappedValue:  "urn:example:role:user",
		},
	}
	err = claimStore.PutRoleMappings(context.Background(), testTenantSlug, id, roleMappings)
	require.NoError(t, err)

	// Add a group mapping claim
	groupClaim := tenant.ClaimMapping{
		Name:            "roles",
		SourceType:      "groupMapping",
		TargetAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
	}
	err = claimStore.PutClaimMappings(context.Background(), testTenantSlug, id, append(claimMappings, groupClaim))
	require.NoError(t, err)

	// Post preview request
	resp := api.Post("/api/v1/applications/"+id+"/claim-mappings/preview", strings.NewReader(`{
		"sub": "user123",
		"email": "test@example.com",
		"groups": ["admins", "users"]
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "saml", result["protocol"])
	preview, ok := result["preview"].(string)
	require.True(t, ok, "preview should be a string")

	// Verify SAML XML contains expected attributes
	assert.Contains(t, preview, `<saml:Assertion`)
	assert.Contains(t, preview, `<saml:AttributeStatement>`)
	assert.Contains(t, preview, `urn:oid:0.9.2342.19200300.100.1.3`)
	assert.Contains(t, preview, `test@example.com`)
	assert.Contains(t, preview, `urn:oid:2.5.4.11`)
	assert.Contains(t, preview, `Engineering`)
	assert.Contains(t, preview, `urn:oid:1.3.6.1.4.1.5923.1.1.1.7`)
	assert.Contains(t, preview, `urn:example:role:admin`)
	assert.Contains(t, preview, `urn:example:role:user`)
}

func TestClaimMappingsPreview_OIDC(t *testing.T) {
	api, appStore, claimStore := newTestAPIWithMiddleware(t)

	// Create OIDC application
	app := &tenant.Application{
		DisplayName: "Test OIDC App",
		Protocol:    "oidc",
		Status:      "active",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	// Set up claim mappings for OIDC
	claimMappings := []tenant.ClaimMapping{
		{
			Name:            "email",
			SourceType:      "cognito",
			SourceAttribute: "email",
			TargetAttribute: "email",
			Required:        true,
		},
		{
			Name:            "name",
			SourceType:      "static",
			TargetAttribute: "name",
			DefaultValue:    "Test User",
		},
		{
			Name:            "roles",
			SourceType:      "groupMapping",
			TargetAttribute: "roles",
		},
	}
	err = claimStore.PutClaimMappings(context.Background(), testTenantSlug, id, claimMappings)
	require.NoError(t, err)

	// Set up role mappings
	roleMappings := []tenant.RoleMapping{
		{
			CognitoGroup: "developers",
			MappedValue:  "developer",
		},
	}
	err = claimStore.PutRoleMappings(context.Background(), testTenantSlug, id, roleMappings)
	require.NoError(t, err)

	// Post preview request
	resp := api.Post("/api/v1/applications/"+id+"/claim-mappings/preview", strings.NewReader(`{
		"sub": "user456",
		"email": "oidc@example.com",
		"groups": ["developers"]
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "oidc", result["protocol"])
	preview, ok := result["preview"].(string)
	require.True(t, ok, "preview should be a string")

	// Verify JSON structure
	var claims map[string]interface{}
	err = json.Unmarshal([]byte(preview), &claims)
	require.NoError(t, err)

	assert.Equal(t, "oidc@example.com", claims["email"])
	assert.Equal(t, "Test User", claims["name"])
	roles, ok := claims["roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, roles, 1)
	assert.Equal(t, "developer", roles[0])
}

// --- Tenant handler tests ---

func TestCreateTenant(t *testing.T) {
	api, _ := newTestTenantAPI(t)

	resp := api.Post("/api/v1/tenants", strings.NewReader(`{
		"slug": "acme",
		"displayName": "Acme Corp"
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "acme", result["slug"])
	assert.Equal(t, "Acme Corp", result["displayName"])
	assert.Equal(t, "standard", result["plan"])
	assert.Equal(t, "active", result["status"])
	assert.Equal(t, float64(10), result["maxApps"])
	assert.Equal(t, float64(10000), result["maxAuthsPerMonth"])
}

func TestListTenants(t *testing.T) {
	api, tenantStore := newTestTenantAPI(t)

	// Create tenants directly
	err := tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug:        "acme",
		DisplayName: "Acme Corp",
		Plan:        "standard",
		Status:      "active",
	})
	require.NoError(t, err)
	err = tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug:        "globex",
		DisplayName: "Globex Corp",
		Plan:        "standard",
		Status:      "active",
	})
	require.NoError(t, err)

	resp := api.Get("/api/v1/tenants")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result []map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestGetTenantBySlug(t *testing.T) {
	api, tenantStore := newTestTenantAPI(t)

	err := tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug:        "acme",
		DisplayName: "Acme Corp",
		Plan:        "standard",
		Status:      "active",
	})
	require.NoError(t, err)

	resp := api.Get("/api/v1/tenants/acme")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "acme", result["slug"])
}

func TestGetTenantNotFound(t *testing.T) {
	api, _ := newTestTenantAPI(t)

	resp := api.Get("/api/v1/tenants/nonexistent")
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

// --- Source handler tests ---

func TestCreateSource(t *testing.T) {
	api, _ := newTestSourceAPI(t)

	resp := api.Post("/api/v1/identity-sources", strings.NewReader(`{
		"displayName": "My Pool",
		"type": "cognito",
		"poolId": "eu-north-1_abc123",
		"region": "eu-north-1",
		"domain": "mypool.auth.eu-north-1.amazoncognito.com",
		"clientId": "abcdef123456"
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.NotEmpty(t, result["id"])
	assert.Equal(t, "My Pool", result["displayName"])
	assert.Equal(t, "cognito", result["type"])
	assert.Equal(t, "active", result["status"])
}

func TestListSources(t *testing.T) {
	api, sourceStore := newTestSourceAPI(t)

	_, err := sourceStore.Create(context.Background(), testTenantSlug, &tenant.IdentitySource{
		DisplayName: "Pool 1",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	resp := api.Get("/api/v1/identity-sources")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result []map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestDeleteSource(t *testing.T) {
	api, sourceStore := newTestSourceAPI(t)

	id, err := sourceStore.Create(context.Background(), testTenantSlug, &tenant.IdentitySource{
		DisplayName: "Pool 1",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	resp := api.Delete("/api/v1/identity-sources/" + id)
	assert.Equal(t, http.StatusNoContent, resp.Code)
}

// --- Mock fetcher for import tests ---

type mockFetcher struct {
	data []byte
	err  error
}

func (m *mockFetcher) Fetch(_ context.Context, _ string) ([]byte, error) {
	return m.data, m.err
}

// newTestImportAPI creates a test API with import and validate routes using a mock fetcher.
func newTestImportAPI(t *testing.T, fetcher MetadataFetcher) (humatest.TestAPI, *store.AppStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	memStore := store.NewMemoryStore()
	appStore := store.NewAppStore(memStore, "test")

	// Create services with test fetcher
	importSvc := service.NewMetadataImportService(appStore, fetcher)

	api.UseMiddleware(injectTenantMiddleware(testTenantSlug))

	registerImportAppRoute(api, importSvc)
	registerValidateAppRoute(api, appStore)

	return api, appStore
}

// --- Import handler tests ---

func TestImportApplication_ValidMetadata(t *testing.T) {
	validMetadataXML := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
		<SPSSODescriptor>
			<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
		</SPSSODescriptor>
	</EntityDescriptor>`

	fetcher := &mockFetcher{data: []byte(validMetadataXML)}
	api, _ := newTestImportAPI(t, fetcher)

	resp := api.Post("/api/v1/applications/import", strings.NewReader(`{
		"metadataUrl": "https://sp.example.com/metadata",
		"displayName": "My SP"
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "My SP", result["displayName"])
	assert.Equal(t, "saml", result["protocol"])
	assert.Equal(t, "active", result["status"])

	// SAML config should be present with entity ID
	samlCfg, ok := result["saml"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "https://sp.example.com", samlCfg["entityId"])
	assert.Equal(t, "https://sp.example.com/acs", samlCfg["acsUrl"])
}

func TestImportApplication_FetchError(t *testing.T) {
	fetcher := &mockFetcher{err: errors.New("connection refused")}
	api, _ := newTestImportAPI(t, fetcher)

	resp := api.Post("/api/v1/applications/import", strings.NewReader(`{
		"metadataUrl": "https://invalid.example.com/metadata"
	}`))

	assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result["detail"].(string), "failed to fetch metadata")
}

func TestImportApplication_NonXMLResponse(t *testing.T) {
	fetcher := &mockFetcher{data: []byte("this is not XML at all")}
	api, _ := newTestImportAPI(t, fetcher)

	resp := api.Post("/api/v1/applications/import", strings.NewReader(`{
		"metadataUrl": "https://sp.example.com/not-metadata"
	}`))

	assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result["detail"].(string), "metadata")
}

// --- Validate handler tests ---

func TestValidateApplication_Valid(t *testing.T) {
	api, appStore := newTestImportAPI(t, &mockFetcher{})

	app := &tenant.Application{
		DisplayName: "Valid App",
		Protocol:    "saml",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:           "https://sp.example.com",
		AcsURL:             "https://sp.example.com/acs",
		NameIDFormat:       "persistent",
		NameIDSource:       "sub",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       180,
	}

	id, err := appStore.Create(context.Background(), testTenantSlug, app, samlCfg)
	require.NoError(t, err)

	resp := api.Post("/api/v1/applications/" + id + "/validate")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, true, result["valid"])
	assert.Empty(t, result["errors"])
}

func TestValidateApplication_MissingEntityID(t *testing.T) {
	api, appStore := newTestImportAPI(t, &mockFetcher{})

	app := &tenant.Application{
		DisplayName: "Incomplete App",
		Protocol:    "saml",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:           "", // missing
		AcsURL:             "https://sp.example.com/acs",
		NameIDFormat:       "persistent",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
	}

	id, err := appStore.Create(context.Background(), testTenantSlug, app, samlCfg)
	require.NoError(t, err)

	resp := api.Post("/api/v1/applications/" + id + "/validate")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, false, result["valid"])

	errs, ok := result["errors"].([]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, errs)

	found := false
	for _, e := range errs {
		if strings.Contains(e.(string), "entityId") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected validation error mentioning entityId")
}

// --- Rotate client secret tests ---

func TestRotateClientSecret(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create an OIDC app with client_secret_basic auth
	app := &tenant.Application{
		DisplayName: "Test OIDC App",
		Protocol:    "oidc",
		Status:      "active",
	}
	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		Scopes:                  []string{"openid", "profile"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		IDTokenLifetimeSec:      3600,
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)
	err = appStore.UpdateOIDCConfig(context.Background(), testTenantSlug, id, oidcCfg)
	require.NoError(t, err)

	// Rotate the secret
	resp := api.Post("/api/v1/applications/"+id+"/rotate-secret", strings.NewReader(""))
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify clientSecret is present and is 64 hex chars
	clientSecret, ok := result["clientSecret"].(string)
	require.True(t, ok, "clientSecret should be present in response")
	assert.Len(t, clientSecret, 64, "clientSecret should be 64 hex characters")

	// Verify it's valid hex
	_, err = hex.DecodeString(clientSecret)
	assert.NoError(t, err, "clientSecret should be valid hex")

	// GET the app and verify clientSecret is NOT in the response (json:"-" tag)
	getResp := api.Get("/api/v1/applications/" + id)
	assert.Equal(t, http.StatusOK, getResp.Code)

	var getResult map[string]interface{}
	err = json.Unmarshal(getResp.Body.Bytes(), &getResult)
	require.NoError(t, err)

	oidcResult, ok := getResult["oidc"].(map[string]interface{})
	require.True(t, ok, "OIDC config should be present")

	// clientSecret should NOT be in the GET response
	_, hasSecret := oidcResult["clientSecret"]
	assert.False(t, hasSecret, "clientSecret should not be exposed in GET response")
}

func TestRotateClientSecret_PublicClient(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create an OIDC app with tokenEndpointAuthMethod=none (public client)
	app := &tenant.Application{
		DisplayName: "Public OIDC App",
		Protocol:    "oidc",
		Status:      "active",
	}
	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		Scopes:                  []string{"openid", "profile"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		IDTokenLifetimeSec:      3600,
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)
	err = appStore.UpdateOIDCConfig(context.Background(), testTenantSlug, id, oidcCfg)
	require.NoError(t, err)

	// Try to rotate secret - should fail with 400
	resp := api.Post("/api/v1/applications/"+id+"/rotate-secret", strings.NewReader(""))
	assert.Equal(t, http.StatusBadRequest, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result["detail"].(string), "public clients do not use secrets")
}

func TestRotateClientSecret_SAMLApp(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create a SAML app
	app := &tenant.Application{
		DisplayName: "SAML App",
		Protocol:    "saml",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:     "https://sp.example.com",
		AcsURL:       "https://sp.example.com/acs",
		NameIDFormat: "persistent",
	}
	id, err := appStore.Create(context.Background(), testTenantSlug, app, samlCfg)
	require.NoError(t, err)

	// Try to rotate secret - should fail with 400
	resp := api.Post("/api/v1/applications/"+id+"/rotate-secret", strings.NewReader(""))
	assert.Equal(t, http.StatusBadRequest, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result["detail"].(string), "OIDC applications")
}

// --- Confidential client secret lifecycle (create/update) tests ---

// storedOIDCSecret is a helper that reads the persisted client secret straight
// from the store (the API never returns it on read, so tests assert on storage).
func storedOIDCSecret(t *testing.T, appStore *store.AppStore, id string) string {
	t.Helper()
	cfg, err := appStore.GetOIDCConfig(context.Background(), testTenantSlug, id)
	require.NoError(t, err)
	return cfg.ClientSecret
}

// TestCreateOIDCApplication_ConfidentialGeneratesSecret verifies that creating
// an OIDC app with a client-secret auth method mints a secret, returns it once
// in the response, and persists it.
func TestCreateOIDCApplication_ConfidentialGeneratesSecret(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	resp := api.Post("/api/v1/applications", strings.NewReader(`{
		"displayName": "Cognito RP",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://pool.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"],
			"scopes": ["openid", "email"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "client_secret_basic"
		}
	}`))
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))

	// One-time secret returned at the top level.
	secret, ok := result["clientSecret"].(string)
	require.True(t, ok, "clientSecret should be returned once on create")
	assert.Len(t, secret, 64, "client secret should be 64 hex chars")
	_, err := hex.DecodeString(secret)
	assert.NoError(t, err, "client secret should be valid hex")

	// The embedded OIDC config must NOT leak the secret.
	oidcCfg, ok := result["oidc"].(map[string]interface{})
	require.True(t, ok)
	_, leaked := oidcCfg["clientSecret"]
	assert.False(t, leaked, "client secret must not appear inside the oidc object")

	// The returned secret must match what was persisted.
	id := result["id"].(string)
	assert.Equal(t, secret, storedOIDCSecret(t, appStore, id))
}

// TestCreateOIDCApplication_PublicClientNoSecret verifies that a public client
// (tokenEndpointAuthMethod=none) gets no secret.
func TestCreateOIDCApplication_PublicClientNoSecret(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	resp := api.Post("/api/v1/applications", strings.NewReader(`{
		"displayName": "Public SPA",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://spa.example.com/callback"],
			"scopes": ["openid"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "none"
		}
	}`))
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))

	// omitempty: no secret returned for a public client.
	_, hasSecret := result["clientSecret"]
	assert.False(t, hasSecret, "public client must not receive a client secret")

	id := result["id"].(string)
	assert.Empty(t, storedOIDCSecret(t, appStore, id), "public client must have no stored secret")
}

// TestUpdateOIDCApplication_PreservesClientSecret is the regression guard for
// the data-loss bug: editing an OIDC app must NOT wipe an existing secret, and
// must not regenerate (no secret returned).
func TestUpdateOIDCApplication_PreservesClientSecret(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create a confidential client (mints secret S1).
	createResp := api.Post("/api/v1/applications", strings.NewReader(`{
		"displayName": "Confidential App",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://app.example.com/cb"],
			"scopes": ["openid"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "client_secret_basic"
		}
	}`))
	require.Equal(t, http.StatusOK, createResp.Code)
	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(createResp.Body.Bytes(), &created))
	id := created["id"].(string)
	s1 := created["clientSecret"].(string)
	require.NotEmpty(t, s1)

	// Update an unrelated field while keeping a confidential auth method.
	updateResp := api.Put("/api/v1/applications/"+id, strings.NewReader(`{
		"displayName": "Confidential App Renamed",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://app.example.com/cb", "https://app.example.com/cb2"],
			"scopes": ["openid", "email"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "client_secret_basic"
		}
	}`))
	require.Equal(t, http.StatusOK, updateResp.Code)
	var updated map[string]interface{}
	require.NoError(t, json.Unmarshal(updateResp.Body.Bytes(), &updated))

	// No new secret returned (it was preserved, not regenerated).
	_, regenerated := updated["clientSecret"]
	assert.False(t, regenerated, "update must not regenerate an existing secret")

	// The stored secret is unchanged.
	assert.Equal(t, s1, storedOIDCSecret(t, appStore, id), "existing client secret must survive an update")
}

// TestUpdateOIDCApplication_SwitchToConfidentialGeneratesSecret verifies that
// promoting a public client to a confidential auth method mints a secret and
// returns it once.
func TestUpdateOIDCApplication_SwitchToConfidentialGeneratesSecret(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create as a public client (no secret).
	createResp := api.Post("/api/v1/applications", strings.NewReader(`{
		"displayName": "Was Public",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://app.example.com/cb"],
			"scopes": ["openid"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "none"
		}
	}`))
	require.Equal(t, http.StatusOK, createResp.Code)
	id := mustID(t, createResp)
	require.Empty(t, storedOIDCSecret(t, appStore, id))

	// Switch to client_secret_post.
	updateResp := api.Put("/api/v1/applications/"+id, strings.NewReader(`{
		"displayName": "Now Confidential",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://app.example.com/cb"],
			"scopes": ["openid"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "client_secret_post"
		}
	}`))
	require.Equal(t, http.StatusOK, updateResp.Code)
	var updated map[string]interface{}
	require.NoError(t, json.Unmarshal(updateResp.Body.Bytes(), &updated))

	secret, ok := updated["clientSecret"].(string)
	require.True(t, ok, "switching to a confidential method should return a one-time secret")
	assert.Len(t, secret, 64)
	assert.Equal(t, secret, storedOIDCSecret(t, appStore, id))
}

// TestUpdateOIDCApplication_SwitchToPublicClearsSecret verifies that demoting a
// confidential client to a public one clears the stored secret.
func TestUpdateOIDCApplication_SwitchToPublicClearsSecret(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	// Create a confidential client.
	createResp := api.Post("/api/v1/applications", strings.NewReader(`{
		"displayName": "Confidential",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://app.example.com/cb"],
			"scopes": ["openid"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "client_secret_basic"
		}
	}`))
	require.Equal(t, http.StatusOK, createResp.Code)
	id := mustID(t, createResp)
	require.NotEmpty(t, storedOIDCSecret(t, appStore, id))

	// Demote to public.
	updateResp := api.Put("/api/v1/applications/"+id, strings.NewReader(`{
		"displayName": "Now Public",
		"protocol": "oidc",
		"oidc": {
			"redirectURIs": ["https://app.example.com/cb"],
			"scopes": ["openid"],
			"grantTypes": ["authorization_code"],
			"responseTypes": ["code"],
			"tokenEndpointAuthMethod": "none"
		}
	}`))
	require.Equal(t, http.StatusOK, updateResp.Code)

	assert.Empty(t, storedOIDCSecret(t, appStore, id), "demoting to a public client must clear the secret")
}

// mustID parses the application id out of a create/update response body.
func mustID(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	id, ok := result["id"].(string)
	require.True(t, ok, "response should contain an id")
	return id
}
