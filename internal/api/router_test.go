package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAPIRoutes(t *testing.T) {
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test")
	appStore := store.NewAppStore(configDB, "test")
	claimStore := store.NewClaimStore(configDB, "test")

	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	// Create services
	importSvc := service.NewMetadataImportService(appStore, &service.HTTPMetadataFetcher{})
	previewSvc := service.NewPreviewService(appStore, claimStore)
	certSvc := service.NewCertificateService(certPEM)
	settingsSvc := service.NewSettingsService(tenantStore, "test-entity", "https://proxy.example.com", "test-kms", "")

	deps := Dependencies{
		Tenants:     tenantStore,
		Apps:        appStore,
		Sources:     store.NewSourceStore(configDB, "test"),
		Claims:      claimStore,
		Audit:       store.NewAuditStore(sessionDB, "test"),
		ImportSvc:   importSvc,
		PreviewSvc:  previewSvc,
		CertSvc:     certSvc,
		SettingsSvc: settingsSvc,
		BaseURL:     "https://proxy.example.com",
		EntityID:    "test-entity",
		KMSKeyID:    "test-kms",
	}

	// Should not panic
	RegisterAPIRoutes(api, deps)

	// Verify health endpoint works after registration
	resp := api.Get("/api/v1/health")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}

// TestNewRouter_FailsClosedWithoutVerifier asserts that in any deployed
// environment, building the router without a real JWKS verifier returns an error
// rather than silently degrading to unauthenticated or decode-only access. The
// process would exit at startup, so a deployed build can never come up with auth
// disabled.
func TestNewRouter_FailsClosedWithoutVerifier(t *testing.T) {
	configDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test")

	for _, env := range []config.Environment{config.EnvDev, config.EnvStaging, config.EnvProd} {
		t.Run(string(env), func(t *testing.T) {
			_, err := NewRouter(Dependencies{
				Tenants:     tenantStore,
				Environment: env,
				Verifier:    nil, // no verifier configured
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "requires a Cognito JWKS verifier")
		})
	}
}

// TestNewRouter_LocalAllowsNoVerifier asserts that local dev — and ONLY local
// dev — may build a router without a verifier, selecting the explicit bypass.
func TestNewRouter_LocalAllowsNoVerifier(t *testing.T) {
	configDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test")

	r, err := NewRouter(Dependencies{
		Tenants:     tenantStore,
		Environment: config.EnvLocal,
		Verifier:    nil,
	})
	require.NoError(t, err)
	require.NotNil(t, r)
}

// TestNewRouter_DeployedWithVerifier asserts that a deployed environment with a
// real verifier builds successfully (the normal production path).
func TestNewRouter_DeployedWithVerifier(t *testing.T) {
	configDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test")

	verifier, jwksErr := cognito.NewJWKSVerifier("eu-north-1_test", "eu-north-1")
	require.NoError(t, jwksErr)

	r, err := NewRouter(Dependencies{
		Tenants:          tenantStore,
		Environment:      config.EnvProd,
		Verifier:         verifier,
		VerifierClientID: "test-client-id",
	})
	require.NoError(t, err)
	require.NotNil(t, r)
}

// TestNewRouter_RejectsWrongTenantStoreType asserts NewRouter fails closed by
// returning an error when the tenant repository is not the concrete
// *store.TenantStore the tenant middleware requires.
func TestNewRouter_RejectsWrongTenantStoreType(t *testing.T) {
	_, err := NewRouter(Dependencies{
		Tenants:     nil,
		Environment: config.EnvLocal,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires *store.TenantStore")
}

// TestErrorSanitizer_5xxStripsInternalDetail asserts the global huma error
// transformer scrubs internal detail from any 5xx response body (CWE-209). A
// throwaway operation returns a 500 whose detail message and wrapped error both
// carry a secret-looking internal string; the client-facing body must contain
// neither, only a generic message plus a correlation id. installErrorSanitizer is
// invoked twice to confirm it is idempotent (single install, no double-wrapping).
func TestErrorSanitizer_5xxStripsInternalDetail(t *testing.T) {
	installErrorSanitizer()
	installErrorSanitizer() // idempotent: second call must be a no-op.

	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	const secret = "postgres://svc:S3cr3tP@ss@internal-db.eu-north-1/config: connection refused"
	huma.Register(api, huma.Operation{
		OperationID: "test-500-leak",
		Method:      http.MethodGet,
		Path:        "/api/v1/test-500-leak",
	}, func(_ context.Context, _ *struct{}) (*struct{}, error) {
		return nil, huma.Error500InternalServerError("failed to load settings: "+secret, errors.New(secret))
	})

	resp := api.Get("/api/v1/test-500-leak")
	require.Equal(t, http.StatusInternalServerError, resp.Code)

	body := resp.Body.String()
	assert.NotContains(t, body, secret, "5xx body must not leak the internal error detail")
	assert.NotContains(t, body, "postgres://", "5xx body must not leak internal connection detail")
	assert.NotContains(t, body, "S3cr3tP@ss", "5xx body must not leak internal credential detail")

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	detail, ok := result["detail"].(string)
	require.True(t, ok, "expected a string detail field in the error body")
	assert.Contains(t, detail, genericServerErrorMessage, "5xx body must carry the generic message")
	assert.Contains(t, detail, "correlation id", "5xx body must carry a correlation id for server-side triage")
	assert.Empty(t, result["errors"], "scrubbed 5xx body must not carry a wrapped errors list")
}

// TestErrorSanitizer_Preserves4xx asserts the transformer only scrubs 5xx: a 4xx
// message is intentionally client-facing and must pass through unchanged so the
// per-endpoint 400/403 messages remain visible.
func TestErrorSanitizer_Preserves4xx(t *testing.T) {
	installErrorSanitizer()

	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	const clientMsg = "tenant slug must be lowercase alphanumeric"
	huma.Register(api, huma.Operation{
		OperationID: "test-400-passthrough",
		Method:      http.MethodGet,
		Path:        "/api/v1/test-400-passthrough",
	}, func(_ context.Context, _ *struct{}) (*struct{}, error) {
		return nil, huma.Error400BadRequest(clientMsg)
	})

	resp := api.Get("/api/v1/test-400-passthrough")
	require.Equal(t, http.StatusBadRequest, resp.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Equal(t, clientMsg, result["detail"], "4xx client-facing messages must be preserved")
	assert.NotContains(t, resp.Body.String(), "correlation id", "4xx responses are not rewritten")
}
