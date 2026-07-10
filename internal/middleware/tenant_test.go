package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantFromPath_Success(t *testing.T) {
	// Setup
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")

	testTenant := &tenant.Tenant{
		Slug:        "acme-corp",
		DisplayName: "Acme Corp",
		Status:      "active",
		Plan:        "enterprise",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, tenantStore.Create(context.Background(), testTenant))

	// Create handler that checks tenant context
	handler := TenantFromPath(tenantStore)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenant.FromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "acme-corp", tenant.Slug)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/t/acme-corp/saml/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestTenantFromPath_NotFound(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")

	handler := TenantFromPath(tenantStore)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/t/nonexistent/saml/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "tenant not found")
}

func TestTenantFromPath_Suspended(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")

	suspendedTenant := &tenant.Tenant{
		Slug:        "suspended-tenant",
		DisplayName: "Suspended Tenant",
		Status:      "suspended",
		Plan:        "free",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, tenantStore.Create(context.Background(), suspendedTenant))

	handler := TenantFromPath(tenantStore)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/t/suspended-tenant/saml/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "tenant suspended")
}

func TestTenantFromPath_InvalidPath(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")

	handler := TenantFromPath(tenantStore)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "tenant not found")
}

func TestTenantFromJWT_Success(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")

	testTenant := &tenant.Tenant{
		Slug:        "acme-corp",
		DisplayName: "Acme Corp",
		Status:      "active",
		Plan:        "enterprise",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, tenantStore.Create(context.Background(), testTenant))

	// Create handler that checks tenant context
	handler := TenantFromJWT(tenantStore)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenant.FromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "acme-corp", tenant.Slug)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	// Set tenant slug in context (normally done by RequireAuth middleware)
	ctx := SetTenantSlug(req.Context(), "acme-corp")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestTenantFromJWT_MissingSlugInContext(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")

	handler := TenantFromJWT(tenantStore)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "forbidden")
}

func TestTenantFromJWT_TenantNotFound(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")

	handler := TenantFromJWT(tenantStore)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	ctx := SetTenantSlug(req.Context(), "nonexistent")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "forbidden")
}

func TestSetTenantSlug_GetTenantSlug(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	ctx := SetTenantSlug(req.Context(), "test-tenant")
	slug, ok := GetTenantSlug(ctx)
	assert.True(t, ok)
	assert.Equal(t, "test-tenant", slug)
}

func TestGetTenantSlug_NotSet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	slug, ok := GetTenantSlug(req.Context())
	assert.False(t, ok)
	assert.Empty(t, slug)
}

// tenantCapture returns a handler that records the resolved tenant slug.
func tenantCapture(got *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t, ok := tenant.FromContext(r.Context()); ok {
			*got = t.Slug
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestTenantFromJWTForAPI_DefaultFallback(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")
	require.NoError(t, tenantStore.Create(context.Background(), tenant.NewDefaultTenant()))

	var got string
	handler := TenantFromJWTForAPI(tenantStore)(tenantCapture(&got))

	// No tenant in context and no override header → default tenant.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, tenant.DefaultSlug, got)
}

func TestTenantFromJWTForAPI_HeaderOverride_GlobalOperator(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")
	require.NoError(t, tenantStore.Create(context.Background(), tenant.NewDefaultTenant()))
	require.NoError(t, tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug: "acme-corp", DisplayName: "Acme", Status: "active", Plan: "standard",
	}))

	var got string
	handler := TenantFromJWTForAPI(tenantStore)(tenantCapture(&got))

	// A global operator's override header wins over the JWT-derived tenant.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	ctx := SetTenantSlug(req.Context(), tenant.DefaultSlug)
	ctx = SetGroups(ctx, []string{GlobalOperatorGroup})
	req = req.WithContext(ctx)
	req.Header.Set(TenantHeaderOverride, "acme-corp")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "acme-corp", got)
}

// TestTenantFromJWTForAPI_HeaderOverride_NonOperatorRejected verifies that a
// per-tenant caller (Admins, but NOT a global operator) that
// sends X-Tenant-Id targeting another tenant must be rejected with 403 and must
// NOT be resolved to either the target or its own claimed tenant.
func TestTenantFromJWTForAPI_HeaderOverride_NonOperatorRejected(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")
	require.NoError(t, tenantStore.Create(context.Background(), tenant.NewDefaultTenant()))
	require.NoError(t, tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug: "acme-corp", DisplayName: "Acme", Status: "active", Plan: "standard",
	}))

	var got string
	handler := TenantFromJWTForAPI(tenantStore)(tenantCapture(&got))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	ctx := SetTenantSlug(req.Context(), tenant.DefaultSlug)
	ctx = SetGroups(ctx, []string{"Admins"}) // per-tenant admin, not a global operator
	req = req.WithContext(ctx)
	req.Header.Set(TenantHeaderOverride, "acme-corp")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "tenant override not permitted")
	// The downstream handler must not have run, so no tenant was resolved.
	assert.Empty(t, got)
}

// TestTenantFromJWTForAPI_HeaderOverride_NoGroupsRejected verifies the fail-
// closed default: absent any groups on the context, the override is refused.
func TestTenantFromJWTForAPI_HeaderOverride_NoGroupsRejected(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")
	require.NoError(t, tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug: "acme-corp", DisplayName: "Acme", Status: "active", Plan: "standard",
	}))

	var got string
	handler := TenantFromJWTForAPI(tenantStore)(tenantCapture(&got))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req = req.WithContext(SetTenantSlug(req.Context(), tenant.DefaultSlug))
	req.Header.Set(TenantHeaderOverride, "acme-corp")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Empty(t, got)
}

func TestTenantFromJWTForAPI_ClaimUsedWhenNoOverride(t *testing.T) {
	memStore := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(memStore, "test-table")
	require.NoError(t, tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug: "acme-corp", DisplayName: "Acme", Status: "active", Plan: "standard",
	}))

	var got string
	handler := TenantFromJWTForAPI(tenantStore)(tenantCapture(&got))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req = req.WithContext(SetTenantSlug(req.Context(), "acme-corp"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "acme-corp", got)
}
