package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service/onboarding"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

type fakeAuditRepo struct{}

func (f *fakeAuditRepo) LogStep(ctx context.Context, tenantSlug, flowID, stepType, spEntityID, userID string, payload map[string]string) error {
	return nil
}
func (f *fakeAuditRepo) GetFlow(ctx context.Context, tenantSlug, flowID string) ([]domain.FlowStep, error) {
	return nil, nil
}
func (f *fakeAuditRepo) GetRecentSteps(ctx context.Context, tenantSlug string, limit int) ([]domain.FlowStep, error) {
	return nil, nil
}

// onboardingTestTenant is the tenant slug every happy-path onboarding test acts
// as. The test API injects it into the request context so the per-handler
// tenant-scoping guard (requireOnboardingTenant) sees a matching caller.
const onboardingTestTenant = "acme"

// injectOnboardingTenant returns a Huma middleware that injects a tenant (and,
// optionally, caller groups) into the request context — standing in for the
// auth + TenantFromJWT middleware chain that runs in production.
func injectOnboardingTenant(slug string, groups []string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		goCtx := tenant.WithContext(ctx.Context(), &tenant.Tenant{
			Slug:        slug,
			DisplayName: slug,
			Plan:        "standard",
			Status:      "active",
		})
		if groups != nil {
			goCtx = middleware.SetGroups(goCtx, groups)
		}
		next(huma.WithContext(ctx, goCtx))
	}
}

// newTestAPI returns a Huma API wired to a real OnboardingService backed by
// in-memory stores. It injects the onboardingTestTenant into every request so
// the tenant-scoping guard is satisfied for the same-tenant happy path.
func newTestAPI(t *testing.T) huma.API {
	t.Helper()
	return newTestAPIForTenant(t, newOnboardingService(t), onboardingTestTenant, nil)
}

// newOnboardingService builds a real OnboardingService over in-memory stores in
// Plan B1 compat mode (no capability prober).
func newOnboardingService(t *testing.T) OnboardingService {
	t.Helper()
	configDB := store.NewMemoryStore()
	sessionDB := store.NewMemoryStore()
	tenants := store.NewTenantStore(configDB, "config")
	stateStore := store.NewOnboardingStateStore(sessionDB, "session")
	return onboarding.NewService(onboarding.Config{
		Tenants: tenants,
		State:   stateStore,
		Audit:   &fakeAuditRepo{},
		// This handler test runs in Plan B1 compat mode with no capability prober
		// wired, so it must explicitly opt into the unprobed all-allowed stub.
		// Production never sets this flag and thus fails closed.
		AllowUnprobedCapabilities: true,
	})
}

// newTestAPIForTenant wires the onboarding routes with a middleware that injects
// the given tenant slug and caller groups, so IDOR/authorization behavior can be
// exercised for callers other than the resource owner.
func newTestAPIForTenant(t *testing.T, svc OnboardingService, callerSlug string, groups []string) huma.API {
	t.Helper()
	r := chi.NewRouter()
	api := humachi.New(r, huma.DefaultConfig("test", "test"))
	api.UseMiddleware(injectOnboardingTenant(callerSlug, groups))
	RegisterOnboardingRoutes(api, svc)
	return api
}

func postJSON(t *testing.T, api huma.API, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	api.Adapter().ServeHTTP(rr, req)
	return rr
}

func TestOnboarding_HappyPath_EndToEnd(t *testing.T) {
	api := newTestAPI(t)

	// Step 1 — create
	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding", map[string]string{
		"slug":        "acme",
		"displayName": "Acme Corp",
	})
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	// Step 2 — capabilities (no body → Huma returns 204)
	rr = postJSON(t, api, http.MethodPut, "/api/v1/onboarding/acme/capabilities", map[string]any{
		"packs": []string{"core", "user_directory"},
	})
	require.Equal(t, http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())

	// Step 3 — IaC
	rr = postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/iac", map[string]string{"format": "cfn"})
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var iacOut struct {
		Format         string `json:"format"`
		ExternalID     string `json:"externalId"`
		DownloadURL    string `json:"downloadUrl"`
		QuickCreateURL string `json:"cloudformationQuickCreateUrl"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&iacOut))
	assert.Equal(t, "cfn", iacOut.Format)
	assert.NotEmpty(t, iacOut.ExternalID)
	// The test API wires an OnboardingService with Renderer=nil (Plan B1 compat
	// path — see newTestAPI), so DownloadURL and QuickCreateURL stay empty.
	// Plan B2 end-to-end coverage lives in the service-layer tests.
	assert.Empty(t, iacOut.DownloadURL, "test API runs in B1 compat mode")
	assert.Empty(t, iacOut.QuickCreateURL)

	// Step 4 — identity (no body → Huma returns 204)
	rr = postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/identity", map[string]string{
		"roleArn":   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		"poolId":    "eu-north-1_xyz999",
		"clientId":  "client-abc",
		"secretArn": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		"region":    "eu-north-1",
	})
	require.Equal(t, http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())

	// Step 5 — probe (stub)
	rr = postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/probe", nil)
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	// Step 6 — complete (no body → Huma returns 204)
	rr = postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/complete", nil)
	require.Equal(t, http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())

	// After completion: GetState returns 404 because the row was deleted.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/acme", nil)
	getRR := httptest.NewRecorder()
	api.Adapter().ServeHTTP(getRR, req)
	assert.Equal(t, http.StatusNotFound, getRR.Code)
}

func TestOnboarding_GetStateAllowsResume(t *testing.T) {
	api := newTestAPI(t)

	postJSON(t, api, http.MethodPost, "/api/v1/onboarding", map[string]string{
		"slug":        "acme",
		"displayName": "Acme",
	})
	postJSON(t, api, http.MethodPut, "/api/v1/onboarding/acme/capabilities", map[string]any{
		"packs": []string{"core"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/acme", nil)
	rr := httptest.NewRecorder()
	api.Adapter().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var state domain.OnboardingState
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&state))
	assert.Equal(t, 2, state.CurrentStep, "resume returns last completed step")
	assert.Empty(t, state.ExternalID, "ExternalID must never leak through GetState")
}

func TestOnboarding_InvalidSlugReturns422(t *testing.T) {
	api := newTestAPI(t)
	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding", map[string]string{
		"slug":        "InvalidSlug", // uppercase not allowed
		"displayName": "Acme",
	})
	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code, "Huma validates pattern before handler; 422 is expected")
}

func TestOnboarding_CompleteBeforeProbeReturns400(t *testing.T) {
	api := newTestAPI(t)
	postJSON(t, api, http.MethodPost, "/api/v1/onboarding", map[string]string{
		"slug":        "acme",
		"displayName": "Acme",
	})
	postJSON(t, api, http.MethodPut, "/api/v1/onboarding/acme/capabilities", map[string]any{
		"packs": []string{"core"},
	})

	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/complete", nil)
	assert.Equal(t, http.StatusBadRequest, rr.Code, "must reject completion before step 5")
}

// spyOnboardingService records whether any privileged sink was invoked, so the
// IDOR tests can assert a rejected caller never reaches the service.
type spyOnboardingService struct{ called bool }

func (s *spyOnboardingService) CreateTenant(context.Context, onboarding.CreateTenantInput) (*domain.OnboardingState, error) {
	s.called = true
	return &domain.OnboardingState{}, nil
}
func (s *spyOnboardingService) SetCapabilities(context.Context, string, []string) error {
	s.called = true
	return nil
}
func (s *spyOnboardingService) GenerateIaC(context.Context, string, string) (*onboarding.IaCArtifact, error) {
	s.called = true
	return &onboarding.IaCArtifact{Format: "cfn", ExternalID: "secret-external-id"}, nil
}
func (s *spyOnboardingService) RegisterIdentity(context.Context, string, onboarding.RegisterIdentityInput) error {
	s.called = true
	return nil
}
func (s *spyOnboardingService) ProbeCapabilities(context.Context, string) (map[string]bool, error) {
	s.called = true
	return map[string]bool{}, nil
}
func (s *spyOnboardingService) Complete(context.Context, string) error {
	s.called = true
	return nil
}
func (s *spyOnboardingService) GetState(context.Context, string) (*domain.OnboardingState, error) {
	s.called = true
	return &domain.OnboardingState{}, nil
}

// TestOnboarding_CrossTenantRejected verifies BOLA/IDOR protection: a
// non-operator caller authenticated for tenant A must not be able to drive the
// onboarding wizard for tenant B via the {slug} path param. The request is
// rejected with 403 and the privileged service sink is never invoked. It
// mirrors middleware.TestTenantFromJWTForAPI_HeaderOverride_NonOperatorRejected.
func TestOnboarding_CrossTenantRejected(t *testing.T) {
	spy := &spyOnboardingService{}
	// Caller is authenticated for tenant "attacker" with a per-tenant admin
	// group (NOT a global operator) and targets "victim" via the path slug.
	api := newTestAPIForTenant(t, spy, "attacker", []string{"Admins"})

	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding/victim/iac", map[string]string{"format": "cfn"})

	assert.Equal(t, http.StatusForbidden, rr.Code, "cross-tenant onboarding must be rejected; body=%s", rr.Body.String())
	assert.False(t, spy.called, "service sink must not be invoked for a rejected cross-tenant caller")
	assert.NotContains(t, rr.Body.String(), "secret-external-id", "ExternalID must not leak on a rejected request")
}

// TestOnboarding_SameTenantAllowed confirms the guard does not over-block: a
// caller whose JWT tenant matches the path slug reaches the service.
func TestOnboarding_SameTenantAllowed(t *testing.T) {
	spy := &spyOnboardingService{}
	api := newTestAPIForTenant(t, spy, "acme", []string{"Admins"})

	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/iac", map[string]string{"format": "cfn"})

	require.Equal(t, http.StatusOK, rr.Code, "same-tenant caller must be allowed; body=%s", rr.Body.String())
	assert.True(t, spy.called, "service sink must run for a matching-tenant caller")
}

// TestOnboarding_GlobalOperatorAllowedCrossTenant confirms the deliberate
// escape hatch: a genuine global operator may target any tenant slug.
func TestOnboarding_GlobalOperatorAllowedCrossTenant(t *testing.T) {
	spy := &spyOnboardingService{}
	api := newTestAPIForTenant(t, spy, "gateway-ops", []string{middleware.GlobalOperatorGroup})

	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding/victim/iac", map[string]string{"format": "cfn"})

	require.Equal(t, http.StatusOK, rr.Code, "global operator must be allowed cross-tenant; body=%s", rr.Body.String())
	assert.True(t, spy.called, "service sink must run for a global operator")
}

// TestOnboarding_NoTenantContextRejected verifies the fail-closed default: with
// no verified tenant in context the wizard is refused with 403.
func TestOnboarding_NoTenantContextRejected(t *testing.T) {
	spy := &spyOnboardingService{}
	r := chi.NewRouter()
	api := humachi.New(r, huma.DefaultConfig("test", "test")) // no tenant middleware
	RegisterOnboardingRoutes(api, spy)

	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/iac", map[string]string{"format": "cfn"})

	assert.Equal(t, http.StatusForbidden, rr.Code, "missing tenant context must fail closed; body=%s", rr.Body.String())
	assert.False(t, spy.called, "service sink must not run without tenant context")
}

// TestMapServiceError_400BodyIsGeneric verifies the 400 body
// carries only the fixed generic message, never the raw service error string
// (which can disclose internal detail — CWE-209).
func TestMapServiceError_400BodyIsGeneric(t *testing.T) {
	api := newTestAPI(t)
	postJSON(t, api, http.MethodPost, "/api/v1/onboarding", map[string]string{
		"slug":        "acme",
		"displayName": "Acme",
	})
	postJSON(t, api, http.MethodPut, "/api/v1/onboarding/acme/capabilities", map[string]any{
		"packs": []string{"core"},
	})

	// Completing before the probe step makes the service return a detailed error
	// ("onboarding: cannot complete from step N ..."). The handler must map it to
	// a 400 with a stable generic body.
	rr := postJSON(t, api, http.MethodPost, "/api/v1/onboarding/acme/complete", nil)
	require.Equal(t, http.StatusBadRequest, rr.Code, "body=%s", rr.Body.String())

	body := rr.Body.String()
	assert.Contains(t, body, "onboarding request could not be processed", "400 must carry the generic message")
	assert.NotContains(t, body, "cannot complete from step", "raw service error detail must not leak to the client")
	assert.NotContains(t, body, "onboarding:", "internal error prefix must not leak to the client")
}

// TestMapServiceError_NotFoundIsGeneric confirms the 404 branch is likewise
// stripped of the wrapped error detail.
func TestMapServiceError_NotFoundIsGeneric(t *testing.T) {
	err := mapServiceError(store.ErrNotFound)
	var se huma.StatusError
	require.True(t, errors.As(err, &se), "mapServiceError must return a huma.StatusError")
	assert.Equal(t, http.StatusNotFound, se.GetStatus())
	assert.Equal(t, "onboarding session not found (expired or never started)", se.Error())
}
