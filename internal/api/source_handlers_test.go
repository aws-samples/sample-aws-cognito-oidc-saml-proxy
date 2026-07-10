package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiscoverPool_NoTenantContextRejected covers the
// discover-cognito-pool endpoint: it uses the gateway's own IAM credentials to
// DescribeUserPool on a caller-supplied pool id, so it must fail closed with 403
// when no verified tenant is present in context — before any AWS call is made.
func TestDiscoverPool_NoTenantContextRejected(t *testing.T) {
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	memStore := store.NewMemoryStore()
	sourceStore := store.NewSourceStore(memStore, "test")
	// Deliberately NO tenant-injection middleware.
	RegisterSourceRoutes(api, sourceStore)

	resp := api.Post("/api/v1/identity-sources/discover", strings.NewReader(`{
		"poolId": "eu-north-1_victimpool",
		"region": "eu-north-1"
	}`))

	assert.Equal(t, http.StatusForbidden, resp.Code, "discover must fail closed without tenant context; body=%s", resp.Body.String())
}

func TestSourceConnectionReachable(t *testing.T) {
	api, sourceStore := newTestSourceAPI(t)

	// Start a mock HTTP server that responds to OIDC configuration
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer": "https://test.example.com",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Create an identity source with the mock server's full URL (for testing only)
	src := &tenant.IdentitySource{
		DisplayName: "Test Source",
		Type:        "cognito",
		PoolID:      "eu-north-1_test123",
		Region:      "eu-north-1",
		Domain:      mockServer.URL, // Full URL with http:// scheme for testing
		ClientID:    "test-client-id",
		Status:      "active",
	}

	// Store the identity source
	ctx := tenant.WithContext(context.Background(), &tenant.Tenant{
		Slug:        testTenantSlug,
		DisplayName: "Test Tenant",
		Plan:        "standard",
		Status:      "active",
	})
	sourceID, err := sourceStore.Create(ctx, testTenantSlug, src)
	require.NoError(t, err)

	// Test the connectivity endpoint
	resp := api.Post("/api/v1/identity-sources/"+sourceID+"/test", strings.NewReader(""))
	require.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify the response
	assert.True(t, result["reachable"].(bool), "Source should be reachable")
	assert.GreaterOrEqual(t, result["latencyMs"].(float64), float64(0), "Latency should be non-negative")
	assert.Empty(t, result["error"], "Error should be empty for reachable source")
}

func TestSourceConnectionUnreachable(t *testing.T) {
	api, sourceStore := newTestSourceAPI(t)

	// Create an identity source with an unreachable domain
	src := &tenant.IdentitySource{
		DisplayName: "Unreachable Source",
		Type:        "cognito",
		PoolID:      "eu-north-1_test456",
		Region:      "eu-north-1",
		Domain:      "unreachable.invalid.local", // Invalid domain
		ClientID:    "test-client-id",
		Status:      "active",
	}

	// Store the identity source
	ctx := tenant.WithContext(context.Background(), &tenant.Tenant{
		Slug:        testTenantSlug,
		DisplayName: "Test Tenant",
		Plan:        "standard",
		Status:      "active",
	})
	sourceID, err := sourceStore.Create(ctx, testTenantSlug, src)
	require.NoError(t, err)

	// Test the connectivity endpoint
	resp := api.Post("/api/v1/identity-sources/"+sourceID+"/test", strings.NewReader(""))
	require.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify the response
	assert.False(t, result["reachable"].(bool), "Source should not be reachable")
	assert.GreaterOrEqual(t, result["latencyMs"].(float64), float64(0), "Latency should be non-negative")
	assert.NotEmpty(t, result["error"], "Error should be present for unreachable source")
}

func TestSourceConnectionNotFound(t *testing.T) {
	api, _ := newTestSourceAPI(t)

	// Test with a non-existent source ID
	resp := api.Post("/api/v1/identity-sources/nonexistent-id/test", strings.NewReader(""))
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestSourceConnectionServerError(t *testing.T) {
	api, sourceStore := newTestSourceAPI(t)

	// Start a mock HTTP server that returns a server error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	// Create an identity source with the mock server's full URL (for testing only)
	src := &tenant.IdentitySource{
		DisplayName: "Error Source",
		Type:        "cognito",
		PoolID:      "eu-north-1_test789",
		Region:      "eu-north-1",
		Domain:      mockServer.URL, // Full URL with http:// scheme for testing
		ClientID:    "test-client-id",
		Status:      "active",
	}

	// Store the identity source
	ctx := tenant.WithContext(context.Background(), &tenant.Tenant{
		Slug:        testTenantSlug,
		DisplayName: "Test Tenant",
		Plan:        "standard",
		Status:      "active",
	})
	sourceID, err := sourceStore.Create(ctx, testTenantSlug, src)
	require.NoError(t, err)

	// Test the connectivity endpoint
	resp := api.Post("/api/v1/identity-sources/"+sourceID+"/test", strings.NewReader(""))
	require.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify the response
	assert.False(t, result["reachable"].(bool), "Source should not be reachable with server error")
	assert.GreaterOrEqual(t, result["latencyMs"].(float64), float64(0), "Latency should be non-negative")
	assert.Contains(t, result["error"].(string), "500", "Error should mention HTTP 500")
}

func TestSourceConnectionTimeout(t *testing.T) {
	api, sourceStore := newTestSourceAPI(t)

	// Start a mock HTTP server that delays the response beyond the timeout
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(6 * time.Second) // Longer than the 5-second timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Create an identity source with the mock server's full URL (for testing only)
	src := &tenant.IdentitySource{
		DisplayName: "Timeout Source",
		Type:        "cognito",
		PoolID:      "eu-north-1_timeout",
		Region:      "eu-north-1",
		Domain:      mockServer.URL, // Full URL with http:// scheme for testing
		ClientID:    "test-client-id",
		Status:      "active",
	}

	// Store the identity source
	ctx := tenant.WithContext(context.Background(), &tenant.Tenant{
		Slug:        testTenantSlug,
		DisplayName: "Test Tenant",
		Plan:        "standard",
		Status:      "active",
	})
	sourceID, err := sourceStore.Create(ctx, testTenantSlug, src)
	require.NoError(t, err)

	// Test the connectivity endpoint
	resp := api.Post("/api/v1/identity-sources/"+sourceID+"/test", strings.NewReader(""))
	require.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify the response
	assert.False(t, result["reachable"].(bool), "Source should not be reachable due to timeout")
	assert.NotEmpty(t, result["error"], "Error should be present for timeout")
}
