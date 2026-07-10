package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// buildTestJWT creates a minimal JWT with the given payload claims for testing.
func buildTestJWT(claims map[string]interface{}) string {
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(payloadJSON) +
		".fake-signature"
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// TestRequireAuth_NoEnvBypass asserts that RequireAuth does not honor any
// environment-variable auth skip. Even with PROXY_ENVIRONMENT=local set, a
// request with no Authorization header is rejected — the middleware itself can
// never be disabled by an env var. The only local bypass is the explicit
// AllowUnauthenticatedForAPILocalDev double, selected at router-construction time.
func TestRequireAuth_NoEnvBypass(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "local")

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing Authorization header")
}

// TestAllowUnauthenticatedForAPILocalDev asserts the explicit local-dev bypass
// lets /api/v1/* through without a token, and leaves non-API paths untouched.
func TestAllowUnauthenticatedForAPILocalDev(t *testing.T) {
	handler := AllowUnauthenticatedForAPILocalDev()(okHandler())

	apiReq := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	apiRR := httptest.NewRecorder()
	handler.ServeHTTP(apiRR, apiReq)
	assert.Equal(t, http.StatusOK, apiRR.Code)

	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRR := httptest.NewRecorder()
	handler.ServeHTTP(healthRR, healthReq)
	assert.Equal(t, http.StatusOK, healthRR.Code)
}

func TestRequireAuth_MissingAuthHeader(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing Authorization header")
}

func TestRequireAuth_InvalidAuthFormat(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid Authorization header format")
}

func TestRequireAuth_EmptyBearerToken(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "empty bearer token")
}

func TestRequireAuth_InvalidJWT(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestRequireAuth_GET_AdminsAllowed(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	token := buildTestJWT(map[string]interface{}{
		"sub":            "user-1",
		"cognito:groups": []interface{}{"Admins"},
	})

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAuth_GET_OperatorsAllowed(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	token := buildTestJWT(map[string]interface{}{
		"sub":            "user-2",
		"cognito:groups": []interface{}{"Operators"},
	})

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAuth_GET_NoGroupsForbidden(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	token := buildTestJWT(map[string]interface{}{
		"sub": "user-3",
	})

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Admins or Operators group required")
}

func TestRequireAuth_POST_AdminsAllowed(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	token := buildTestJWT(map[string]interface{}{
		"sub":            "admin-user",
		"cognito:groups": []interface{}{"Admins"},
	})

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAuth_POST_OperatorsForbidden(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	token := buildTestJWT(map[string]interface{}{
		"sub":            "operator-user",
		"cognito:groups": []interface{}{"Operators"},
	})

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Admins group required for write operations")
}

func TestRequireAuth_DELETE_OperatorsForbidden(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	token := buildTestJWT(map[string]interface{}{
		"sub":            "operator-user",
		"cognito:groups": []interface{}{"Operators"},
	})

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sp/123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireAuth_PUT_AdminsAllowed(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "prod")

	token := buildTestJWT(map[string]interface{}{
		"sub":            "admin-user",
		"cognito:groups": []interface{}{"Admins"},
	})

	handler := RequireAuth(okHandler())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sp/123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestExtractGroupsFromJWT_ValidToken(t *testing.T) {
	token := buildTestJWT(map[string]interface{}{
		"sub":            "user-1",
		"cognito:groups": []interface{}{"Admins", "Operators"},
	})

	groups, claims, err := extractGroupsFromJWT(token)
	assert.NoError(t, err)
	assert.Equal(t, []string{"Admins", "Operators"}, groups)
	assert.NotNil(t, claims)
	assert.Equal(t, "user-1", claims["sub"])
}

func TestExtractGroupsFromJWT_NoGroups(t *testing.T) {
	token := buildTestJWT(map[string]interface{}{
		"sub": "user-1",
	})

	groups, claims, err := extractGroupsFromJWT(token)
	assert.NoError(t, err)
	assert.Empty(t, groups)
	assert.NotNil(t, claims)
}

func TestExtractGroupsFromJWT_InvalidFormat(t *testing.T) {
	_, _, err := extractGroupsFromJWT("not-a-jwt")
	assert.Error(t, err)
}

func TestExtractGroupsFromJWT_WithTenantID(t *testing.T) {
	token := buildTestJWT(map[string]interface{}{
		"sub":              "user-1",
		"cognito:groups":   []interface{}{"Admins"},
		"custom:tenant_id": "acme-corp",
	})

	groups, claims, err := extractGroupsFromJWT(token)
	assert.NoError(t, err)
	assert.Equal(t, []string{"Admins"}, groups)
	assert.Equal(t, "acme-corp", claims["custom:tenant_id"])
}
