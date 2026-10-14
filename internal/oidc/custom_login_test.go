package oidc

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// fakeOIDCVerifier is a stub idTokenVerifier for OIDC custom-login tests.
type fakeOIDCVerifier struct {
	claims      map[string]interface{}
	err         error
	gotToken    string
	gotClientID string
}

func (f *fakeOIDCVerifier) Verify(token, expectedClientID string) (map[string]interface{}, error) {
	f.gotToken = token
	f.gotClientID = expectedClientID
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

type customLoginEnv struct {
	storage  *Storage
	appStore *store.AppStore
	pending  *store.PendingLoginStore
	handler  *LoginHandler
	server   *httptest.Server
	appID    string
	sourceID string
	verifier *fakeOIDCVerifier
}

func setupCustomLoginEnv(t *testing.T, customLoginURL string, trusted []string) *customLoginEnv {
	t.Helper()
	storage, appStore, _, sourceStore := newTestStorage(t)
	ms := store.NewMemoryStore()
	pending := store.NewPendingLoginStore(ms, "test")
	ctx := context.Background()

	sourceID, err := sourceStore.Create(ctx, "test", &tenant.IdentitySource{
		DisplayName: "Test Cognito",
		Type:        "cognito",
		Domain:      "test.auth.eu-north-1.amazoncognito.com",
		PoolID:      "eu-north-1_TEST",
		ClientID:    "test-cognito-client",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	appID, err := appStore.Create(ctx, "test", &tenant.Application{
		DisplayName:              "Custom Login OIDC App",
		Protocol:                 "oidc",
		SourceID:                 sourceID,
		Status:                   "active",
		CustomLoginURL:           customLoginURL,
		TrustedLoginRedirectURIs: trusted,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, appStore.UpdateOIDCConfig(ctx, "test", appID, &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://rp.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email"},
		TokenEndpointAuthMethod: "none",
		IDTokenLifetimeSec:      3600,
	}))

	hmacKey := make([]byte, 32)
	_, _ = rand.Read(hmacKey)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Start()
	t.Cleanup(server.Close)

	verifier := &fakeOIDCVerifier{}
	handler, err := NewLoginHandler(storage, appStore, sourceStore, nil, hmacKey, server.URL, pending)
	require.NoError(t, err)
	handler.verifierFactory = func(poolID, region string) idTokenVerifier { return verifier }

	r := chi.NewRouter()
	r.Route("/t/{tenant}/oidc", func(r chi.Router) {
		r.Get("/login", handler.HandleLogin)
		r.Post("/login/complete", handler.HandleLoginComplete)
	})
	server.Config.Handler = r

	return &customLoginEnv{
		storage: storage, appStore: appStore, pending: pending, handler: handler,
		server: server, appID: appID, sourceID: sourceID, verifier: verifier,
	}
}

func (e *customLoginEnv) createAuthRequest(t *testing.T) string {
	t.Helper()
	created, err := e.storage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     e.appID,
		RedirectURI:  "https://rp.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		State:        "rp-state",
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	require.NoError(t, err)
	return created.GetID()
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

// bindingCookie returns the __Host-oidc_login cookie the handler would set
// when redirecting flowID to its custom login page.
func (e *customLoginEnv) bindingCookie(t *testing.T, flowID string) *http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	require.NoError(t, e.handler.setLoginBindingCookie(rr, flowID))
	c := findCookie(rr.Result().Cookies(), oidcLoginBindingCookieName)
	require.NotNil(t, c)
	return c
}

// postComplete performs the hand-back POST for flowID with an id_token form
// field and the optional binding cookie.
func (e *customLoginEnv) postComplete(t *testing.T, flowID, token string, binding *http.Cookie) *http.Response {
	t.Helper()
	form := url.Values{}
	if token != "" {
		form.Set("id_token", token)
	}
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/t/test/oidc/login/complete?state="+flowID,
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if binding != nil {
		req.AddCookie(binding)
	}
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	return resp
}

func TestOIDC_CustomLogin_RedirectReplacesCognito(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	client := noRedirectClient()
	authRequestID := env.createAuthRequest(t)

	resp, err := client.Get(env.server.URL + "/t/test/oidc/login?authRequestID=" + authRequestID)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	require.NoError(t, err)
	// REPLACE: redirects to the custom login page, not Cognito.
	assert.Equal(t, "login.example.com", u.Host)
	assert.NotContains(t, u.Host, "amazoncognito.com")

	q := u.Query()
	flowID := q.Get("state")
	assert.NotEmpty(t, flowID)
	assert.Contains(t, q.Get("return_to"), "/t/test/oidc/login/complete")

	pl, err := env.pending.Get(context.Background(), flowID)
	require.NoError(t, err)
	assert.Equal(t, "oidc", pl.Protocol)
	assert.Equal(t, authRequestID, pl.AuthRequestID)
	assert.Equal(t, env.sourceID, pl.SourceID)

	// M-4: the redirect binds the flow to this browser with a __Host- cookie
	// that the cross-site hand-back can carry (SameSite=None; Secure; HttpOnly).
	bind := findCookie(resp.Cookies(), oidcLoginBindingCookieName)
	require.NotNil(t, bind, "redirect must set the login binding cookie")
	assert.True(t, bind.Secure)
	assert.True(t, bind.HttpOnly)
	assert.Equal(t, http.SameSiteNoneMode, bind.SameSite)
	assert.Equal(t, "/", bind.Path)
	assert.Empty(t, bind.Domain, "__Host- cookies must not set Domain")
	assert.Equal(t, oidcFlowCookieMaxAge, bind.MaxAge)
	bound := httptest.NewRequest(http.MethodPost, "/t/test/oidc/login/complete", nil)
	bound.AddCookie(bind)
	assert.NoError(t, env.handler.verifyLoginBinding(bound, flowID))
	assert.ErrorIs(t, env.handler.verifyLoginBinding(bound, "some-other-flow"), errLoginBindingMismatch)
}

// TestOIDC_LoginComplete_NoBindingCookie_Forbidden is the M-4 regression: a
// hand-back without the browser-binding cookie (an attacker posting their token
// + the victim's state into the victim's browser) is refused before the pending
// login is read, so it is neither consumed nor completed.
func TestOIDC_LoginComplete_NoBindingCookie_Forbidden(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	ctx := context.Background()
	authRequestID := env.createAuthRequest(t)
	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-nobind", Protocol: "oidc", TenantSlug: "test", SourceID: env.sourceID, AppID: env.appID, AuthRequestID: authRequestID,
	}, 10*time.Minute))
	env.verifier.claims = map[string]interface{}{"sub": "attacker", "email": "attacker@example.com"}

	resp := env.postComplete(t, "flow-nobind", "attacker.id.token", nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, env.verifier.gotToken, "token must not be verified without the binding")

	// Pending login intact and AuthRequest not completed.
	pl, err := env.pending.Get(ctx, "flow-nobind")
	require.NoError(t, err)
	assert.Equal(t, authRequestID, pl.AuthRequestID)
	ar, err := env.storage.AuthRequestByID(ctx, authRequestID)
	require.NoError(t, err)
	assert.False(t, ar.Done())
}

// TestOIDC_LoginComplete_WrongFlowCookie_Forbidden: a binding cookie minted for
// a different flow does not satisfy this flow's hand-back.
func TestOIDC_LoginComplete_WrongFlowCookie_Forbidden(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	ctx := context.Background()
	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-a", Protocol: "oidc", TenantSlug: "test", SourceID: env.sourceID, AuthRequestID: env.createAuthRequest(t),
	}, 10*time.Minute))

	resp := env.postComplete(t, "flow-a", "tok", env.bindingCookie(t, "flow-b"))
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_, err := env.pending.Get(ctx, "flow-a")
	require.NoError(t, err, "pending login must survive a mismatched binding")
}

// TestOIDC_LoginComplete_ForgedCookie_Forbidden: a cookie not signed by this
// handler's key is rejected.
func TestOIDC_LoginComplete_ForgedCookie_Forbidden(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	ctx := context.Background()
	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-f", Protocol: "oidc", TenantSlug: "test", SourceID: env.sourceID, AuthRequestID: env.createAuthRequest(t),
	}, 10*time.Minute))

	resp := env.postComplete(t, "flow-f", "tok", &http.Cookie{Name: oidcLoginBindingCookieName, Value: "00000000.Zm9v.deadbeef"})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestOIDC_LoginComplete_Success(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	ctx := context.Background()
	authRequestID := env.createAuthRequest(t)

	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID:        "flow-ok",
		Protocol:      "oidc",
		TenantSlug:    "test",
		SourceID:      env.sourceID,
		AppID:         env.appID,
		AuthRequestID: authRequestID,
	}, 10*time.Minute))

	env.verifier.claims = map[string]interface{}{
		"sub":         "cognito-sub-1",
		"email":       "user@example.com",
		"given_name":  "Test",
		"family_name": "User",
	}

	// The browser that was redirected carries the M-4 binding cookie.
	resp := env.postComplete(t, "flow-ok", "the.id.token", env.bindingCookie(t, "flow-ok"))
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/t/test/oidc/authorize/callback")
	assert.Contains(t, loc, "id="+authRequestID)

	// Success clears the binding cookie with matching attributes.
	cleared := findCookie(resp.Cookies(), oidcLoginBindingCookieName)
	require.NotNil(t, cleared, "success must clear the binding cookie")
	assert.Less(t, cleared.MaxAge, 0)
	assert.Empty(t, cleared.Value)
	assert.Equal(t, http.SameSiteNoneMode, cleared.SameSite)
	assert.True(t, cleared.Secure)

	// Token verified against the source client ID.
	assert.Equal(t, "test-cognito-client", env.verifier.gotClientID)
	assert.Equal(t, "the.id.token", env.verifier.gotToken)

	// Auth request completed with the token claims.
	completed, err := env.storage.AuthRequestByID(ctx, authRequestID)
	require.NoError(t, err)
	assert.True(t, completed.Done())
	assert.Equal(t, "cognito-sub-1", completed.GetSubject())

	// Single-use: pending consumed.
	_, gerr := env.pending.Get(ctx, "flow-ok")
	assert.ErrorIs(t, gerr, store.ErrNotFound)
}

func TestOIDC_LoginComplete_BearerHeaderAlsoWorks(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	client := noRedirectClient()
	ctx := context.Background()
	authRequestID := env.createAuthRequest(t)

	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-bearer", Protocol: "oidc", TenantSlug: "test", SourceID: env.sourceID, AuthRequestID: authRequestID,
	}, 10*time.Minute))
	env.verifier.claims = map[string]interface{}{"sub": "s", "email": "u@example.com"}

	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/t/test/oidc/login/complete?state=flow-bearer", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer header.id.token")
	// Bearer is just another token carrier for the same browser hand-back; the
	// M-4 binding cookie is still required.
	req.AddCookie(env.bindingCookie(t, "flow-bearer"))
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "header.id.token", env.verifier.gotToken)
}

func TestOIDC_LoginComplete_InvalidToken(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	ctx := context.Background()
	authRequestID := env.createAuthRequest(t)

	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-bad", Protocol: "oidc", TenantSlug: "test", SourceID: env.sourceID, AuthRequestID: authRequestID,
	}, 10*time.Minute))
	env.verifier.err = fmt.Errorf("signature mismatch")

	resp := env.postComplete(t, "flow-bad", "bad.token", env.bindingCookie(t, "flow-bad"))
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestOIDC_LoginComplete_MissingFlow(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})

	resp := env.postComplete(t, "missing", "tok", env.bindingCookie(t, "missing"))
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestOIDC_LoginComplete_WrongProtocol(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	ctx := context.Background()

	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-saml", Protocol: "saml", TenantSlug: "test", SourceID: env.sourceID,
	}, 10*time.Minute))

	resp := env.postComplete(t, "flow-saml", "tok", env.bindingCookie(t, "flow-saml"))
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestOIDC_LoginComplete_MissingToken(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	client := noRedirectClient()
	ctx := context.Background()

	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-notoken", Protocol: "oidc", TenantSlug: "test", SourceID: env.sourceID, AuthRequestID: "ar",
	}, 10*time.Minute))

	resp, err := client.PostForm(env.server.URL+"/t/test/oidc/login/complete?state=flow-notoken", url.Values{})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
