package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReqWithTenant(t *testing.T, tnt *tenant.Tenant) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	return r.WithContext(tenant.WithContext(r.Context(), tnt))
}

func nextOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestRequireCapability_AllowsWhenCapabilityTrue(t *testing.T) {
	tnt := &tenant.Tenant{
		Slug:          "acme",
		CapabilityMap: map[string]bool{"user_directory": true},
	}
	r := newReqWithTenant(t, tnt)
	rr := httptest.NewRecorder()

	handler := RequireCapability("user_directory")(nextOK())
	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "ok", rr.Body.String())
}

func TestRequireCapability_Denies403WhenCapabilityFalse(t *testing.T) {
	tnt := &tenant.Tenant{
		Slug:          "acme",
		CapabilityMap: map[string]bool{"user_directory": false},
	}
	r := newReqWithTenant(t, tnt)
	rr := httptest.NewRecorder()

	handler := RequireCapability("user_directory")(nextOK())
	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	var body struct {
		Error              string `json:"error"`
		CapabilityRequired string `json:"capabilityRequired"`
		Remediation        string `json:"remediation"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "capability_not_enabled", body.Error)
	assert.Equal(t, "user_directory", body.CapabilityRequired)
	assert.Equal(t, "/onboarding", body.Remediation)
}

func TestRequireCapability_Denies403WhenCapabilityMissingFromMap(t *testing.T) {
	tnt := &tenant.Tenant{
		Slug:          "acme",
		CapabilityMap: map[string]bool{"core": true},
	}
	r := newReqWithTenant(t, tnt)
	rr := httptest.NewRecorder()

	handler := RequireCapability("user_directory")(nextOK())
	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireCapability_AllowsLegacyNilMap(t *testing.T) {
	tnt := &tenant.Tenant{
		Slug:          "legacy",
		CapabilityMap: nil,
	}
	r := newReqWithTenant(t, tnt)
	rr := httptest.NewRecorder()

	handler := RequireCapability("user_directory")(nextOK())
	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusOK, rr.Code, "legacy nil map allows any capability")
}

func TestRequireCapability_ReturnsServerErrorWhenNoTenantInContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rr := httptest.NewRecorder()

	handler := RequireCapability("user_directory")(nextOK())
	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
