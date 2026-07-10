package oidc

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRouterWithDeps creates a chi router with OIDC routes registered,
// including the login/callback handler dependencies.
func newTestRouterWithDeps(t *testing.T) (chi.Router, *Storage, *store.AppStore, *store.SourceStore) {
	t.Helper()

	storage, appStore, _, sourceStore := newTestStorage(t)

	// Bootstrap a tenant and identity source for tests.
	ctx := context.Background()
	tenantStore := store.NewTenantStore(storage.db, "test")
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "test-tenant",
		DisplayName: "Test Tenant",
		Plan:        "free",
		Status:      "active",
	}))

	sourceID, err := sourceStore.Create(ctx, "test-tenant", &tenant.IdentitySource{
		DisplayName: "Test Cognito",
		Type:        "cognito",
		Domain:      "test.auth.eu-north-1.amazoncognito.com",
		PoolID:      "eu-north-1_TEST",
		ClientID:    "test-cognito-client",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	_, err = appStore.Create(ctx, "test-tenant", &tenant.Application{
		DisplayName: "Test OIDC App",
		Protocol:    "oidc",
		SourceID:    sourceID,
		Status:      "active",
	}, nil)
	require.NoError(t, err)

	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)

	// MF-5: test uses a random per-test crypto key (no SM needed in unit tests)
	var cryptoKey [32]byte
	_, err = rand.Read(cryptoKey[:])
	require.NoError(t, err)

	r := chi.NewRouter()
	err = RegisterOIDCRoutes(r, storage, "http://localhost", appStore, sourceStore, nil, cryptoKey, hmacKey, nil, false)
	require.NoError(t, err)

	return r, storage, appStore, sourceStore
}

func TestOIDCRouteRegistration(t *testing.T) {
	r, _, _, _ := newTestRouterWithDeps(t)

	testServer := httptest.NewServer(r)
	defer testServer.Close()

	// Test that the OIDC path is recognized
	resp, err := http.Get(testServer.URL + "/t/test-tenant/oidc/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Should not return 404, indicating route is registered
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "OIDC routes should be registered")
}

func TestOIDCDiscoveryEndpoint(t *testing.T) {
	r, _, _, _ := newTestRouterWithDeps(t)

	testServer := httptest.NewServer(r)
	defer testServer.Close()

	// Fetch discovery document
	resp, err := http.Get(testServer.URL + "/t/test-tenant/oidc/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Should return success
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Should return JSON
	contentType := resp.Header.Get("Content-Type")
	assert.True(t, strings.Contains(contentType, "application/json"), "Response should be JSON")
}

func TestIssuerFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		path       string
		tenantSlug string
		expected   string
	}{
		{
			name:       "tenant slug from header",
			baseURL:    "http://localhost",
			path:       "/authorize",
			tenantSlug: "acme",
			expected:   "http://localhost/t/acme/oidc",
		},
		{
			name:       "baseURL with trailing slash",
			baseURL:    "http://localhost/",
			path:       "/.well-known/openid-configuration",
			tenantSlug: "tenant1",
			expected:   "http://localhost/t/tenant1/oidc",
		},
		{
			name:       "HTTPS URL",
			baseURL:    "https://auth.example.com",
			path:       "/token",
			tenantSlug: "tenant2",
			expected:   "https://auth.example.com/t/tenant2/oidc",
		},
		{
			name:       "missing header falls back to default",
			baseURL:    "http://localhost",
			path:       "/keys",
			tenantSlug: "",
			expected:   "http://localhost/t/default/oidc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.tenantSlug != "" {
				req.Header.Set("X-Tenant-Slug", tt.tenantSlug)
			}
			issuer := issuerFromRequest(req, tt.baseURL)
			assert.Equal(t, tt.expected, issuer)
		})
	}
}

func TestStorageInterfaceImplementation(t *testing.T) {
	// This test verifies that Storage implements all required interfaces
	storage, _, _, _ := newTestStorage(t)

	// Verify basic storage operations work
	ctx := context.Background()

	// Test Health
	err := storage.Health(ctx)
	assert.NoError(t, err)

	// Test SigningKey
	key, err := storage.SigningKey(ctx)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, "test-key-id", key.ID())

	// Test KeySet
	keys, err := storage.KeySet(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	// Test SignatureAlgorithms
	algs, err := storage.SignatureAlgorithms(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, algs)
}
