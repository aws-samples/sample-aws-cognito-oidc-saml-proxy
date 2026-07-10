package saml

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withChiTenant returns r with a chi route context carrying the given tenant
// path param, mirroring how the /t/{tenant}/... routes populate it at runtime.
// The multi-tenant session-provider paths resolve the identity source scoped to
// this tenant, so tests exercising them must supply the tenant the app was
// created under; without it the provider fails closed.
func withChiTenant(r *http.Request, tenantSlug string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenant", tenantSlug)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// newTestSessionProviderCompat creates a SessionProvider using the legacy compat
// constructor for tests that use a static Cognito auth client.
func newTestSessionProviderCompat() *SessionProvider {
	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "test-client-id", "https://idp.example.com/saml/acs", "", "")
	hmacKey := []byte("test-hmac-key-for-unit-tests-32b")
	return NewSessionProviderCompat(auth, hmacKey)
}

// newTestSessionProviderMultiTenant creates a SessionProvider with SourceStore
// and AppStore for multi-tenant tests.
func newTestSessionProviderMultiTenant(t *testing.T) (*SessionProvider, *store.SourceStore, *store.AppStore) {
	t.Helper()
	ms := store.NewMemoryStore()
	sourceStore := store.NewSourceStore(ms, "test-table")
	appStore := store.NewAppStore(ms, "test-table")
	hmacKey := []byte("test-hmac-key-for-unit-tests-32b")

	sp := NewSessionProvider(
		WithSourceStore(sourceStore),
		WithAppStore(appStore),
		WithHMACKey(hmacKey),
		WithProviderBaseURL("https://idp.example.com"),
	)
	return sp, sourceStore, appStore
}

func TestSessionProvider_GetSession_NoCookie_RedirectsToCognito(t *testing.T) {
	sp := newTestSessionProviderCompat()

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RelayState:    "some-relay-state",
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session, "should return nil to indicate redirect was written")

	result := rr.Result()
	defer func() { _ = result.Body.Close() }()

	assert.Equal(t, http.StatusFound, result.StatusCode)

	location := result.Header.Get("Location")
	assert.Contains(t, location, "test.auth.eu-north-1.amazoncognito.com")
	assert.Contains(t, location, "response_type=code")
	assert.Contains(t, location, "client_id=test-client-id")
}

func TestSessionProvider_GetSession_RedirectContainsPKCEChallenge(t *testing.T) {
	sp := newTestSessionProviderCompat()

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RelayState:    "",
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)

	location := rr.Result().Header.Get("Location")
	assert.Contains(t, location, "code_challenge=")
	assert.Contains(t, location, "code_challenge_method=S256")
}

func TestSessionProvider_GetSession_SetsFlowCookie(t *testing.T) {
	sp := newTestSessionProviderCompat()

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RelayState:    "relay",
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
	}

	sp.GetSession(rr, req, authnReq)

	cookies := rr.Result().Cookies()
	var flowCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == flowCookieName {
			flowCookie = c
			break
		}
	}

	require.NotNil(t, flowCookie, "flow cookie should be set")
	assert.True(t, flowCookie.HttpOnly)
	assert.True(t, flowCookie.Secure)
	assert.Equal(t, cookieMaxAge, flowCookie.MaxAge)

	// Verify the cookie can be decoded.
	state, err := sp.signedDecode(flowCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, "relay", state.RelayState)
	assert.NotEmpty(t, state.Verifier)
	assert.Equal(t, "https://sp.example.com/saml", state.SPEntityID)
}

func TestSessionProvider_GetSession_WithValidSessionCookie_ReturnsSession(t *testing.T) {
	sp := newTestSessionProviderCompat()

	// Create a valid session and encode it.
	now := time.Now()
	session := &crewsaml.Session{
		ID:         "test-session-id",
		CreateTime: now,
		ExpireTime: now.Add(8 * time.Hour),
		UserEmail:  "user@example.com",
	}

	cookieVal, err := sp.encodeSessionCookie(session)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: cookieVal,
	})
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
	}

	result := sp.GetSession(rr, req, authnReq)
	require.NotNil(t, result)
	assert.Equal(t, "user@example.com", result.UserEmail)
}

// TestSessionProvider_GetSession_RevokedCookieRejected asserts that an
// authentic, correctly-bound session cookie whose SessionIndex has been revoked
// server-side (by a logout at the SLO Lambda) is NOT honoured — GetSession falls
// through to a fresh Cognito redirect instead of replaying the dead session.
func TestSessionProvider_GetSession_RevokedCookieRejected(t *testing.T) {
	sp := newTestSessionProviderCompat()
	sessionStore := store.NewSessionStore(store.NewMemoryDB(), "test")
	sp.SetSessionStore(sessionStore)

	now := time.Now()
	session := &crewsaml.Session{
		ID:         "test-session-id",
		Index:      "_session_revoked_idx",
		CreateTime: now,
		ExpireTime: now.Add(8 * time.Hour),
		UserEmail:  "user@example.com",
	}
	// Revoke the session server-side, as a verified SLO would.
	require.NoError(t, sessionStore.RevokeSession(context.Background(), session.Index))

	cookieVal, err := sp.encodeSessionCookie(session)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
	}

	result := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, result, "a revoked session cookie must not be honoured")
	assert.Equal(t, http.StatusFound, rr.Result().StatusCode, "should fall through to a fresh Cognito redirect")
}

// TestSessionProvider_GetSession_LiveCookieWithStore_ReturnsSession is the flip
// side: with a session store wired but no revocation recorded, a valid cookie is
// still honoured — the revocation check must not reject live sessions.
func TestSessionProvider_GetSession_LiveCookieWithStore_ReturnsSession(t *testing.T) {
	sp := newTestSessionProviderCompat()
	sp.SetSessionStore(store.NewSessionStore(store.NewMemoryDB(), "test"))

	now := time.Now()
	session := &crewsaml.Session{
		ID:         "test-session-id",
		Index:      "_session_live_idx",
		CreateTime: now,
		ExpireTime: now.Add(8 * time.Hour),
		UserEmail:  "user@example.com",
	}

	cookieVal, err := sp.encodeSessionCookie(session)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
	}

	result := sp.GetSession(rr, req, authnReq)
	require.NotNil(t, result, "a live (non-revoked) session cookie must still be honoured")
	assert.Equal(t, "user@example.com", result.UserEmail)
}

// seedSAMLAppForTenant creates an identity source and a SAML app bound to it in
// the given tenant, returning the source ID. It mirrors seedSAMLApp but is not
// hard-coded to the "acme" tenant so cross-tenant tests can populate two tenants.
func seedSAMLAppForTenant(t *testing.T, sourceStore *store.SourceStore, appStore *store.AppStore, tenantSlug, entityID string) string {
	t.Helper()
	sourceID, err := sourceStore.Create(context.Background(), tenantSlug, &tenant.IdentitySource{
		DisplayName: "Cognito " + tenantSlug,
		Type:        "cognito",
		PoolID:      "eu-north-1_" + tenantSlug,
		Region:      "eu-north-1",
		Domain:      tenantSlug + ".auth.eu-north-1.amazoncognito.com",
		ClientID:    tenantSlug + "-client-id",
		Status:      "active",
	})
	require.NoError(t, err)

	_, err = appStore.Create(context.Background(), tenantSlug, &tenant.Application{
		DisplayName: "App " + tenantSlug,
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID: entityID,
		AcsURL:   "https://sp.example.com/saml/acs",
		AcsURLs:  []string{"https://sp.example.com/saml/acs"},
	})
	require.NoError(t, err)
	return sourceID
}

// TestSessionProvider_GetSession_CrossTenantCookieRejected verifies that a
// session cookie minted (and signed) for tenant A + SP-A must NOT be
// honoured when replayed on tenant B's path targeting SP-B. Instead of returning
// the foreign session, GetSession falls through to a fresh Cognito redirect for
// tenant B.
func TestSessionProvider_GetSession_CrossTenantCookieRejected(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const spA = "https://sp-a.example.com/saml"
	const spB = "https://sp-b.example.com/saml"
	sourceA := seedSAMLAppForTenant(t, sourceStore, appStore, "acme", spA)
	seedSAMLAppForTenant(t, sourceStore, appStore, "globex", spB)

	// Mint a valid, signed session bound to tenant "acme" + SP-A.
	now := time.Now()
	session := &crewsaml.Session{
		ID:         "session-acme",
		CreateTime: now,
		ExpireTime: now.Add(8 * time.Hour),
		UserEmail:  "attacker@acme.example.com",
	}
	cookieVal, err := sp.encodeBoundSessionCookie(session, "acme", sourceA, spA)
	require.NoError(t, err)

	// Replay it on tenant "globex" targeting SP-B.
	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/globex/saml/sso", nil), "globex")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: spB},
	}

	result := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, result, "cross-tenant session cookie must not be returned")

	// It fell through to a fresh Cognito redirect for the CURRENT tenant (globex),
	// proving the acme cookie was rejected rather than silently accepted.
	res := rr.Result()
	defer func() { _ = res.Body.Close() }()
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Contains(t, res.Header.Get("Location"), "globex.auth.eu-north-1.amazoncognito.com")
}

// TestSessionProvider_GetSession_SameTenantDifferentSPRejected verifies that
// within a single tenant a session minted for SP-A is not reused for SP-B. In
// the SP-initiated flow crewjam populates req.ServiceProviderMetadata before
// calling GetSession, so the SP binding is compared and the mismatch is caught.
func TestSessionProvider_GetSession_SameTenantDifferentSPRejected(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const spA = "https://sp-a.example.com/saml"
	const spB = "https://sp-b.example.com/saml"
	sourceA := seedSAMLAppForTenant(t, sourceStore, appStore, "acme", spA)
	seedSAMLAppForTenant(t, sourceStore, appStore, "acme", spB)

	now := time.Now()
	session := &crewsaml.Session{
		ID:         "session-spa",
		CreateTime: now,
		ExpireTime: now.Add(8 * time.Hour),
		UserEmail:  "user@acme.example.com",
	}
	cookieVal, err := sp.encodeBoundSessionCookie(session, "acme", sourceA, spA)
	require.NoError(t, err)

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: spB},
	}

	result := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, result, "session bound to SP-A must not be reused for SP-B")
	res := rr.Result()
	defer func() { _ = res.Body.Close() }()
	assert.Equal(t, http.StatusFound, res.StatusCode, "should fall through to fresh auth")
}

// TestSessionProvider_GetSession_MatchingBindingAccepted verifies the positive
// case: a session cookie bound to the same tenant AND target SP as the request
// is accepted and returned unchanged.
func TestSessionProvider_GetSession_MatchingBindingAccepted(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const spA = "https://sp-a.example.com/saml"
	sourceA := seedSAMLAppForTenant(t, sourceStore, appStore, "acme", spA)

	now := time.Now()
	session := &crewsaml.Session{
		ID:         "session-ok",
		CreateTime: now,
		ExpireTime: now.Add(8 * time.Hour),
		UserEmail:  "user@acme.example.com",
	}
	cookieVal, err := sp.encodeBoundSessionCookie(session, "acme", sourceA, spA)
	require.NoError(t, err)

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: spA},
	}

	result := sp.GetSession(rr, req, authnReq)
	require.NotNil(t, result, "matching tenant+SP session cookie should be accepted")
	assert.Equal(t, "user@acme.example.com", result.UserEmail)
	assert.NotEqual(t, http.StatusFound, rr.Result().StatusCode, "no redirect should be written")
}

// TestSessionProvider_GetSession_IdPInitiatedNilSPAccepted verifies that a
// tenant-matching cookie is still honoured when the request has no SP metadata
// yet — the IdP-initiated case, where crewjam calls GetSession before resolving
// the SP. Tenant binding is still enforced, but the SP comparison is skipped.
func TestSessionProvider_GetSession_IdPInitiatedNilSPAccepted(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const spA = "https://sp-a.example.com/saml"
	sourceA := seedSAMLAppForTenant(t, sourceStore, appStore, "acme", spA)

	now := time.Now()
	session := &crewsaml.Session{
		ID:         "session-idp",
		CreateTime: now,
		ExpireTime: now.Add(8 * time.Hour),
		UserEmail:  "user@acme.example.com",
	}
	cookieVal, err := sp.encodeBoundSessionCookie(session, "acme", sourceA, spA)
	require.NoError(t, err)

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	rr := httptest.NewRecorder()

	// No ServiceProviderMetadata yet (mirrors crewjam ServeIDPInitiated ordering).
	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
	}

	result := sp.GetSession(rr, req, authnReq)
	require.NotNil(t, result, "tenant-matching cookie should be accepted when SP is not yet known")
	assert.Equal(t, "user@acme.example.com", result.UserEmail)
}

func TestSessionProvider_HandleCallback_MissingCode(t *testing.T) {
	sp := newTestSessionProviderCompat()

	req := httptest.NewRequest(http.MethodGet, "/saml/acs", nil)
	rr := httptest.NewRecorder()

	sp.HandleCallback(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.True(t, strings.Contains(rr.Body.String(), "missing authorization code"))
}

func TestSessionProvider_HandleCallback_MissingFlowCookie(t *testing.T) {
	sp := newTestSessionProviderCompat()

	req := httptest.NewRequest(http.MethodGet, "/saml/acs?code=abc123", nil)
	rr := httptest.NewRecorder()

	sp.HandleCallback(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.True(t, strings.Contains(rr.Body.String(), "missing flow cookie"))
}

func TestSessionProvider_MultiTenant_GetSession_ResolvesIdentitySource(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	// Create identity source.
	source := &tenant.IdentitySource{
		DisplayName: "Acme Cognito",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Domain:      "acme.auth.eu-north-1.amazoncognito.com",
		ClientID:    "acme-client-id",
		Status:      "active",
	}
	sourceID, err := sourceStore.Create(context.Background(), "acme", source)
	require.NoError(t, err)

	// Create application pointing to that source.
	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID: "https://sp.example.com/saml",
		AcsURL:   "https://sp.example.com/saml/acs",
		AcsURLs:  []string{"https://sp.example.com/saml/acs"},
	}
	_, err = appStore.Create(context.Background(), "acme", app, samlCfg)
	require.NoError(t, err)

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RelayState:    "relay",
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session, "should redirect to Cognito")

	result := rr.Result()
	defer func() { _ = result.Body.Close() }()
	assert.Equal(t, http.StatusFound, result.StatusCode)

	location := result.Header.Get("Location")
	assert.Contains(t, location, "acme.auth.eu-north-1.amazoncognito.com")
	assert.Contains(t, location, "client_id=acme-client-id")

	// Verify flow cookie stores tenant and source IDs.
	var flowCookie *http.Cookie
	for _, c := range result.Cookies() {
		if c.Name == flowCookieName {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie)
	state, err := sp.signedDecode(flowCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, "acme", state.TenantSlug)
	assert.Equal(t, sourceID, state.SourceID)
}

func TestSessionProvider_AuditTrail_SSO_Initiated(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	// Create audit store and wire it to the session provider
	ms := store.NewMemoryStore()
	auditStore := store.NewAuditStore(ms, "test-table")
	sp.SetAuditStore(auditStore)

	// Create identity source and application
	source := &tenant.IdentitySource{
		DisplayName: "Test Cognito",
		Type:        "cognito",
		PoolID:      "eu-north-1_test",
		Region:      "eu-north-1",
		Domain:      "test.auth.eu-north-1.amazoncognito.com",
		ClientID:    "test-client-id",
		Status:      "active",
	}
	sourceID, err := sourceStore.Create(context.Background(), "test-tenant", source)
	require.NoError(t, err)

	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID: "https://sp.example.com/saml",
		AcsURL:   "https://sp.example.com/saml/acs",
		AcsURLs:  []string{"https://sp.example.com/saml/acs"},
	}
	_, err = appStore.Create(context.Background(), "test-tenant", app, samlCfg)
	require.NoError(t, err)

	// Make SSO request with an AuthnRequest ID
	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/test-tenant/saml/sso", nil), "test-tenant")
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RelayState:    "relay",
		RequestBuffer: []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
		Request: crewsaml.AuthnRequest{
			ID: "test-authn-request-id-12345",
		},
	}

	// Call GetSession - should log sso_initiated
	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session, "should redirect to Cognito")

	// Verify audit entry was created
	steps, err := auditStore.GetFlow(context.Background(), "test-tenant", "test-authn-request-id-12345")
	require.NoError(t, err)
	require.Len(t, steps, 1)

	assert.Equal(t, "test-authn-request-id-12345", steps[0].FlowID)
	assert.Equal(t, "sso_initiated", steps[0].StepType)
	assert.Equal(t, "https://sp.example.com/saml", steps[0].SPEntityID)
	assert.Empty(t, steps[0].UserID)

	// Verify GetRecentSteps returns the entry
	recentSteps, err := auditStore.GetRecentSteps(context.Background(), "test-tenant", 10)
	require.NoError(t, err)
	assert.Len(t, recentSteps, 1)
	assert.Equal(t, "sso_initiated", recentSteps[0].StepType)
}

// fakeVerifier is a stub idTokenVerifier for testing the direct ID-token path.
type fakeVerifier struct {
	claims      map[string]interface{}
	err         error
	gotToken    string
	gotClientID string
	calls       int
}

func (f *fakeVerifier) Verify(tokenString, expectedClientID string) (map[string]interface{}, error) {
	f.calls++
	f.gotToken = tokenString
	f.gotClientID = expectedClientID
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

// seedSAMLApp creates an identity source and a SAML app bound to it, returning
// the source for assertions.
func seedSAMLApp(t *testing.T, sourceStore *store.SourceStore, appStore *store.AppStore, source *tenant.IdentitySource, entityID string) string {
	t.Helper()
	sourceID, err := sourceStore.Create(context.Background(), "acme", source)
	require.NoError(t, err)

	app := &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID: entityID,
		AcsURL:   "https://sp.example.com/saml/acs",
		AcsURLs:  []string{"https://sp.example.com/saml/acs"},
	}
	_, err = appStore.Create(context.Background(), "acme", app, samlCfg)
	require.NoError(t, err)
	return sourceID
}

func TestExtractBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"valid", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"case-insensitive scheme", "bearer abc.def.ghi", "abc.def.ghi"},
		{"trims whitespace", "Bearer    abc.def.ghi   ", "abc.def.ghi"},
		{"wrong scheme", "Basic abc123", ""},
		{"scheme only", "Bearer ", ""},
		{"no scheme", "abc.def.ghi", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			assert.Equal(t, tc.want, extractBearerToken(r))
		})
	}
}

func TestSessionProvider_GetSession_ValidIDToken_IssuesSessionWithoutRedirect(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const entityID = "https://sp.example.com/saml"
	seedSAMLApp(t, sourceStore, appStore, &tenant.IdentitySource{
		DisplayName: "Acme Cognito",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Domain:      "acme.auth.eu-north-1.amazoncognito.com",
		ClientID:    "acme-client-id",
		Status:      "active",
	}, entityID)

	fake := &fakeVerifier{claims: map[string]interface{}{
		"sub":            "user-123",
		"email":          "user@example.com",
		"given_name":     "Test",
		"family_name":    "User",
		"cognito:groups": []interface{}{"admins", "users"},
	}}
	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		assert.Equal(t, "eu-north-1_abc123", poolID)
		assert.Equal(t, "eu-north-1", region)
		return fake
	}

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	req.Header.Set("Authorization", "Bearer some.id.token")
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	require.NotNil(t, session, "valid ID token should yield a session")
	assert.Equal(t, "user@example.com", session.UserEmail)
	assert.Equal(t, "user@example.com", session.NameID)
	assert.Equal(t, "user-123", session.SubjectID)
	assert.Equal(t, "Test", session.UserGivenName)
	assert.ElementsMatch(t, []string{"admins", "users"}, session.Groups)

	// No redirect to Cognito.
	assert.NotEqual(t, http.StatusFound, rr.Result().StatusCode)
	// Verifier was called with the SP's bound client ID and the presented token.
	assert.Equal(t, "acme-client-id", fake.gotClientID)
	assert.Equal(t, "some.id.token", fake.gotToken)

	// A session cookie should be set for reuse.
	var sessCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessCookie = c
		}
	}
	require.NotNil(t, sessCookie, "session cookie should be set")
	assert.True(t, sessCookie.HttpOnly)
}

func TestSessionProvider_GetSession_InvalidIDToken_FailsClosed(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const entityID = "https://sp.example.com/saml"
	seedSAMLApp(t, sourceStore, appStore, &tenant.IdentitySource{
		Type:     "cognito",
		PoolID:   "eu-north-1_abc123",
		Region:   "eu-north-1",
		Domain:   "acme.auth.eu-north-1.amazoncognito.com",
		ClientID: "acme-client-id",
		Status:   "active",
	}, entityID)

	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		return &fakeVerifier{err: fmt.Errorf("signature mismatch")}
	}

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	req.Header.Set("Authorization", "Bearer bad.token")
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session, "invalid token must not yield a session")
	// Fails closed with 401 rather than silently redirecting.
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotEqual(t, http.StatusFound, rr.Code)
}

func TestSessionProvider_GetSession_NoToken_FallsThroughToRedirect(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const entityID = "https://sp.example.com/saml"
	seedSAMLApp(t, sourceStore, appStore, &tenant.IdentitySource{
		Type:     "cognito",
		PoolID:   "eu-north-1_abc123",
		Region:   "eu-north-1",
		Domain:   "acme.auth.eu-north-1.amazoncognito.com",
		ClientID: "acme-client-id",
		Status:   "active",
	}, entityID)

	called := false
	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		called = true
		return &fakeVerifier{}
	}

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme") // no Authorization header
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)
	assert.Equal(t, http.StatusFound, rr.Result().StatusCode, "should redirect to Cognito when no token")
	assert.False(t, called, "verifier should not be consulted without a token")
}

func TestSessionProvider_GetSession_TokenButSourceMissingPoolID_BadRequest(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	const entityID = "https://sp.example.com/saml"
	// Source has a domain (so redirect would work) but no poolID/region, so the
	// token cannot be verified.
	seedSAMLApp(t, sourceStore, appStore, &tenant.IdentitySource{
		Type:     "cognito",
		Domain:   "acme.auth.eu-north-1.amazoncognito.com",
		ClientID: "acme-client-id",
		Status:   "active",
	}, entityID)

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	req.Header.Set("Authorization", "Bearer some.token")
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSessionProvider_GetSession_TokenWithReplayedAuthnRequest_Forbidden(t *testing.T) {
	sp, sourceStore, appStore := newTestSessionProviderMultiTenant(t)

	// Wire a replay store and pre-mark the AuthnRequest ID as seen.
	ms := store.NewMemoryStore()
	replayStore := store.NewReplayStore(ms, "test-table")
	sp.SetReplayStore(replayStore)
	require.NoError(t, replayStore.MarkSeen(context.Background(), "replayed-id", time.Minute))

	const entityID = "https://sp.example.com/saml"
	seedSAMLApp(t, sourceStore, appStore, &tenant.IdentitySource{
		Type:     "cognito",
		PoolID:   "eu-north-1_abc123",
		Region:   "eu-north-1",
		ClientID: "acme-client-id",
		Status:   "active",
	}, entityID)

	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		return &fakeVerifier{claims: map[string]interface{}{"sub": "u", "email": "u@example.com"}}
	}

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	req.Header.Set("Authorization", "Bearer some.token")
	rr := httptest.NewRecorder()

	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
		Request:                 crewsaml.AuthnRequest{ID: "replayed-id"},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}
