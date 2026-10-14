package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSPWithPending builds a multi-tenant SessionProvider with a pending-login
// store wired in.
func newSPWithPending(t *testing.T) (*SessionProvider, *store.SourceStore, *store.AppStore, *store.PendingLoginStore) {
	t.Helper()
	ms := store.NewMemoryStore()
	sourceStore := store.NewSourceStore(ms, "test-table")
	appStore := store.NewAppStore(ms, "test-table")
	pending := store.NewPendingLoginStore(ms, "test-table")
	sp := NewSessionProvider(
		WithSourceStore(sourceStore),
		WithAppStore(appStore),
		WithHMACKey([]byte("test-hmac-key-for-unit-tests-32b")),
		WithProviderBaseURL("https://idp.example.com"),
	)
	sp.SetPendingLoginStore(pending)
	return sp, sourceStore, appStore, pending
}

// seedCustomLoginApp creates a source + SAML app configured with a custom login
// page. Returns the source ID.
func seedCustomLoginApp(t *testing.T, sourceStore *store.SourceStore, appStore *store.AppStore, entityID, customLoginURL string, trusted []string) string {
	t.Helper()
	sourceID, err := sourceStore.Create(context.Background(), "acme", &tenant.IdentitySource{
		DisplayName: "Acme Cognito",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Domain:      "acme.auth.eu-north-1.amazoncognito.com",
		ClientID:    "acme-client-id",
		Status:      "active",
	})
	require.NoError(t, err)

	app := &tenant.Application{
		DisplayName:              "Custom Login App",
		Protocol:                 "saml",
		SourceID:                 sourceID,
		Status:                   "active",
		CustomLoginURL:           customLoginURL,
		TrustedLoginRedirectURIs: trusted,
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

func TestSAML_CustomLogin_RedirectReplacesCognito(t *testing.T) {
	sp, sourceStore, appStore, pending := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://login.example.com/start", []string{"https://login.example.com/"})

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	rr := httptest.NewRecorder()
	authnReq := &crewsaml.IdpAuthnRequest{
		RelayState:              "relay-xyz",
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
		Request:                 crewsaml.AuthnRequest{ID: "authn-1"},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)

	res := rr.Result()
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusFound, res.StatusCode)

	loc := res.Header.Get("Location")
	u, err := url.Parse(loc)
	require.NoError(t, err)
	// REPLACE: must go to the custom login page, NOT the Cognito domain.
	assert.Equal(t, "login.example.com", u.Host)
	assert.NotContains(t, u.Host, "amazoncognito.com")

	q := u.Query()
	flowID := q.Get("state")
	assert.NotEmpty(t, flowID)
	assert.Contains(t, q.Get("return_to"), "/t/acme/saml/login/complete")

	// M-4: the redirect binds the flow to this browser with a __Host- cookie
	// that the cross-site hand-back can carry (SameSite=None; Secure; HttpOnly).
	bind := findCookie(res.Cookies(), loginBindingCookieName)
	require.NotNil(t, bind, "redirect must set the login binding cookie")
	assert.True(t, bind.Secure)
	assert.True(t, bind.HttpOnly)
	assert.Equal(t, http.SameSiteNoneMode, bind.SameSite)
	assert.Equal(t, "/", bind.Path)
	assert.Empty(t, bind.Domain, "__Host- cookies must not set Domain")
	assert.Equal(t, cookieMaxAge, bind.MaxAge)
	// The cookie is bound to exactly this flow.
	bound := withChiTenant(httptest.NewRequest(http.MethodPost, "/t/acme/saml/login/complete", nil), "acme")
	bound.AddCookie(bind)
	assert.NoError(t, sp.verifyLoginBinding(bound, flowID))
	assert.ErrorIs(t, sp.verifyLoginBinding(bound, "some-other-flow"), errLoginBindingMismatch)

	// Pending login was persisted with the original request context.
	pl, err := pending.Get(context.Background(), flowID)
	require.NoError(t, err)
	assert.Equal(t, "saml", pl.Protocol)
	assert.Equal(t, "acme", pl.TenantSlug)
	assert.Equal(t, entityID, pl.SPEntityID)
	assert.Equal(t, "relay-xyz", pl.RelayState)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("<samlp:AuthnRequest/>")), pl.SAMLRequestB64)
}

func TestSAML_CustomLogin_UntrustedURL_Fails(t *testing.T) {
	sp, sourceStore, appStore, _ := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	// customLoginURL is NOT covered by the allowlist (config written directly,
	// bypassing API validation) -> runtime defensive check must reject it.
	seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://evil.example.com/login", []string{"https://login.example.com/"})

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	rr := httptest.NewRecorder()
	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.NotEqual(t, http.StatusFound, rr.Code)
}

func TestSAML_CustomLogin_NoCustomURL_FallsBackToCognito(t *testing.T) {
	sp, sourceStore, appStore, _ := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	// No custom login URL -> standard Cognito redirect.
	seedCustomLoginApp(t, sourceStore, appStore, entityID, "", nil)

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	rr := httptest.NewRecorder()
	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)
	res := rr.Result()
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusFound, res.StatusCode)
	loc := res.Header.Get("Location")
	assert.Contains(t, loc, "amazoncognito.com")
}

func TestSAML_CompleteCustomLogin_Success(t *testing.T) {
	sp, sourceStore, appStore, pending := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	sourceID := seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://login.example.com/start", []string{"https://login.example.com/"})

	require.NoError(t, pending.Create(context.Background(), &store.PendingLogin{
		FlowID:         "flow-ok",
		Protocol:       "saml",
		TenantSlug:     "acme",
		SourceID:       sourceID,
		SAMLRequestB64: base64.StdEncoding.EncodeToString([]byte("<samlp:AuthnRequest/>")),
		RelayState:     "relay-1",
		SPEntityID:     entityID,
	}, time.Minute))

	fake := &fakeVerifier{claims: map[string]interface{}{
		"sub":   "user-9",
		"email": "user9@example.com",
	}}
	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		assert.Equal(t, "eu-north-1_abc123", poolID)
		assert.Equal(t, "eu-north-1", region)
		return fake
	}

	sessCookie, pl, err := sp.CompleteCustomLogin(context.Background(), "flow-ok", "the.id.token")
	require.NoError(t, err)
	require.NotNil(t, pl)
	assert.Equal(t, "relay-1", pl.RelayState)
	// Token verified against the SP's bound identity source client ID.
	assert.Equal(t, "acme-client-id", fake.gotClientID)
	assert.Equal(t, "the.id.token", fake.gotToken)

	// Session cookie decodes to a session carrying the token claims.
	sess, err := sp.decodeSessionCookie(sessCookie)
	require.NoError(t, err)
	assert.Equal(t, "user9@example.com", sess.UserEmail)

	// Single-use: the pending login is consumed.
	_, gerr := pending.Get(context.Background(), "flow-ok")
	assert.ErrorIs(t, gerr, store.ErrNotFound)
}

func TestSAML_CompleteCustomLogin_InvalidToken_ConsumesPending(t *testing.T) {
	sp, sourceStore, appStore, pending := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	sourceID := seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://login.example.com/start", []string{"https://login.example.com/"})

	require.NoError(t, pending.Create(context.Background(), &store.PendingLogin{
		FlowID: "flow-bad", Protocol: "saml", TenantSlug: "acme", SourceID: sourceID, SPEntityID: entityID,
	}, time.Minute))

	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		return &fakeVerifier{err: fmt.Errorf("signature mismatch")}
	}

	_, _, err := sp.CompleteCustomLogin(context.Background(), "flow-bad", "bad.token")
	require.Error(t, err)

	// Even on failure, the flow is single-use and consumed.
	_, gerr := pending.Get(context.Background(), "flow-bad")
	assert.ErrorIs(t, gerr, store.ErrNotFound)
}

func TestSAML_CompleteCustomLogin_MissingFlow(t *testing.T) {
	sp, _, _, _ := newSPWithPending(t)
	_, _, err := sp.CompleteCustomLogin(context.Background(), "nope", "tok")
	assert.Error(t, err)
}

func TestSAML_CompleteCustomLogin_WrongProtocol(t *testing.T) {
	sp, _, _, pending := newSPWithPending(t)
	require.NoError(t, pending.Create(context.Background(), &store.PendingLogin{
		FlowID: "flow-oidc", Protocol: "oidc", TenantSlug: "acme", SourceID: "src",
	}, time.Minute))

	_, _, err := sp.CompleteCustomLogin(context.Background(), "flow-oidc", "tok")
	assert.Error(t, err)
}

// findCookie returns the cookie with the given name from a Set-Cookie list, or nil.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// mintLoginBindingCookie returns the __Host-saml_login cookie the provider
// would set when redirecting flowID to its custom login page.
func mintLoginBindingCookie(t *testing.T, sp *SessionProvider, flowID string) *http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	require.NoError(t, sp.setLoginBindingCookie(rr, flowID))
	c := findCookie(rr.Result().Cookies(), loginBindingCookieName)
	require.NotNil(t, c)
	return c
}

// loginCompleteEnv is a full tenant IdP wired for POST /saml/login/complete.
type loginCompleteEnv struct {
	router      chi.Router
	sessionProv *SessionProvider
	pending     *store.PendingLoginStore
	verifier    *fakeVerifier
	entityID    string
}

func setupLoginCompleteEnv(t *testing.T) *loginCompleteEnv {
	t.Helper()
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(ms, "t")
	appStore := store.NewAppStore(ms, "t")
	claimStore := store.NewClaimStore(ms, "t")
	sourceStore := store.NewSourceStore(ms, "t")
	sessionStore := store.NewSessionStore(ms, "t")
	pending := store.NewPendingLoginStore(ms, "t")
	ctx := context.Background()

	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug: "acme", DisplayName: "ACME", Plan: "free", Status: "active",
	}))
	const entityID = "https://sp.example.com/saml"
	seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://login.example.com/start", []string{"https://login.example.com/"})

	spProvider := NewSPProvider(appStore)
	sessionProv := NewSessionProvider(
		WithSourceStore(sourceStore),
		WithAppStore(appStore),
		WithHMACKey([]byte("test-hmac-key-for-unit-tests-32b")),
		WithProviderBaseURL("https://idp.example.com"),
	)
	sessionProv.SetPendingLoginStore(pending)
	verifier := &fakeVerifier{claims: map[string]interface{}{
		"sub": "user-1", "email": "user@example.com",
	}}
	sessionProv.verifierFactory = func(_, _ string) idTokenVerifier { return verifier }

	handler := NewTenantIdPHandler(
		WithSigner(signer),
		WithCertificate(cert),
		WithSPProvider(spProvider),
		WithSessionProvider(sessionProv),
		WithAssertionMaker(NewAssertionMaker(appStore, claimStore)),
		WithBaseURL("https://idp.example.com"),
	)
	r := chi.NewRouter()
	RegisterTenantRoutes(r, TenantRoutesConfig{
		Handler: handler, SessionProv: sessionProv, Sessions: sessionStore,
		Tenants: tenantStore, Apps: appStore, Claims: claimStore,
		Audit: store.NewAuditStore(ms, "t"),
	})
	return &loginCompleteEnv{router: r, sessionProv: sessionProv, pending: pending, verifier: verifier, entityID: entityID}
}

// seedPendingSAMLLogin records a pending SAML login for flowID whose stored
// AuthnRequest is valid for the test IdP (Destination = tenant SSO URL).
func (e *loginCompleteEnv) seedPendingSAMLLogin(t *testing.T, flowID string) {
	t.Helper()
	authn := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-%s" Version="2.0" IssueInstant="%s" Destination="https://idp.example.com/t/acme/saml/sso" AssertionConsumerServiceURL="https://sp.example.com/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		flowID, time.Now().UTC().Format("2006-01-02T15:04:05Z"), e.entityID)
	require.NoError(t, e.pending.Create(context.Background(), &store.PendingLogin{
		FlowID: flowID, Protocol: "saml", TenantSlug: "acme",
		SourceID:       e.sourceIDFor(t),
		SAMLRequestB64: base64.StdEncoding.EncodeToString([]byte(authn)),
		RelayState:     "relay-1",
		SPEntityID:     e.entityID,
	}, time.Minute))
}

func (e *loginCompleteEnv) sourceIDFor(t *testing.T) string {
	t.Helper()
	app, _, err := e.sessionProv.apps.GetByTenantEntityID(context.Background(), "acme", e.entityID)
	require.NoError(t, err)
	return app.SourceID
}

// postLoginComplete performs the custom-login hand-back POST with the given
// state and optional binding cookie.
func (e *loginCompleteEnv) postLoginComplete(flowID string, binding *http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Set("id_token", "the.id.token")
	form.Set("state", flowID)
	req := httptest.NewRequest(http.MethodPost, "/t/acme/saml/login/complete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if binding != nil {
		req.AddCookie(binding)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// TestSAML_LoginComplete_NoBindingCookie_Forbidden is the M-4 regression: a
// hand-back that does not carry the browser-binding cookie (an attacker posting
// their token + the victim's state into the victim's browser, or a replay from
// another browser) is refused and the pending login is left intact so the
// legitimate browser can still complete it.
func TestSAML_LoginComplete_NoBindingCookie_Forbidden(t *testing.T) {
	env := setupLoginCompleteEnv(t)
	env.seedPendingSAMLLogin(t, "flow-1")

	rr := env.postLoginComplete("flow-1", nil)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "login flow not bound to this browser")
	assert.Empty(t, env.verifier.gotToken, "token must not be verified without the binding")

	// Not consumed.
	pl, err := env.pending.Get(context.Background(), "flow-1")
	require.NoError(t, err)
	assert.Equal(t, "flow-1", pl.FlowID)
}

// TestSAML_LoginComplete_WrongFlowCookie_Forbidden: a binding cookie minted for
// a different flow does not satisfy this flow's hand-back.
func TestSAML_LoginComplete_WrongFlowCookie_Forbidden(t *testing.T) {
	env := setupLoginCompleteEnv(t)
	env.seedPendingSAMLLogin(t, "flow-1")

	rr := env.postLoginComplete("flow-1", mintLoginBindingCookie(t, env.sessionProv, "flow-other"))
	assert.Equal(t, http.StatusForbidden, rr.Code)
	_, err := env.pending.Get(context.Background(), "flow-1")
	require.NoError(t, err, "pending login must survive a mismatched binding")
}

// TestSAML_LoginComplete_ForgedCookie_Forbidden: a cookie signed under another
// key (or tampered) is rejected, not merely mismatched.
func TestSAML_LoginComplete_ForgedCookie_Forbidden(t *testing.T) {
	env := setupLoginCompleteEnv(t)
	env.seedPendingSAMLLogin(t, "flow-1")

	rr := env.postLoginComplete("flow-1", &http.Cookie{Name: loginBindingCookieName, Value: "00000000.Zm9v.deadbeef"})
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestSAML_LoginComplete_MatchingCookie_Succeeds: the browser that was
// redirected completes the flow; the IdP emits the SAMLResponse and the
// binding cookie is cleared.
func TestSAML_LoginComplete_MatchingCookie_Succeeds(t *testing.T) {
	env := setupLoginCompleteEnv(t)
	env.seedPendingSAMLLogin(t, "flow-1")

	rr := env.postLoginComplete("flow-1", mintLoginBindingCookie(t, env.sessionProv, "flow-1"))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "SAMLResponse")
	assert.Contains(t, rr.Body.String(), "https://sp.example.com/saml/acs")
	assert.Equal(t, "the.id.token", env.verifier.gotToken)

	res := rr.Result()
	cleared := findCookie(res.Cookies(), loginBindingCookieName)
	require.NotNil(t, cleared, "success must clear the binding cookie")
	assert.Less(t, cleared.MaxAge, 0)
	assert.Empty(t, cleared.Value)
	assert.Equal(t, http.SameSiteNoneMode, cleared.SameSite)
	assert.True(t, cleared.Secure)

	// M-8: the saml_session cookie lives as long as the session (the app has no
	// SessionDurationSec, so the 8h default), not the 10-minute flow TTL.
	sess := findCookie(res.Cookies(), sessionCookieName)
	require.NotNil(t, sess, "success must set the session cookie")
	assert.Equal(t, int((8*time.Hour).Seconds()), sess.MaxAge)

	// Consumed.
	_, err := env.pending.Get(context.Background(), "flow-1")
	assert.ErrorIs(t, err, store.ErrNotFound)
}
