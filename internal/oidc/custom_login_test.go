package oidc

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
}

func TestOIDC_LoginComplete_Success(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	client := noRedirectClient()
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

	form := url.Values{}
	form.Set("id_token", "the.id.token")
	resp, err := client.PostForm(env.server.URL+"/t/test/oidc/login/complete?state=flow-ok", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/t/test/oidc/authorize/callback")
	assert.Contains(t, loc, "id="+authRequestID)

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
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "header.id.token", env.verifier.gotToken)
}

func TestOIDC_LoginComplete_InvalidToken(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	client := noRedirectClient()
	ctx := context.Background()
	authRequestID := env.createAuthRequest(t)

	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-bad", Protocol: "oidc", TenantSlug: "test", SourceID: env.sourceID, AuthRequestID: authRequestID,
	}, 10*time.Minute))
	env.verifier.err = fmt.Errorf("signature mismatch")

	form := url.Values{}
	form.Set("id_token", "bad.token")
	resp, err := client.PostForm(env.server.URL+"/t/test/oidc/login/complete?state=flow-bad", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestOIDC_LoginComplete_MissingFlow(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	client := noRedirectClient()

	form := url.Values{}
	form.Set("id_token", "tok")
	resp, err := client.PostForm(env.server.URL+"/t/test/oidc/login/complete?state=missing", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestOIDC_LoginComplete_WrongProtocol(t *testing.T) {
	env := setupCustomLoginEnv(t, "https://login.example.com/start", []string{"https://login.example.com/"})
	client := noRedirectClient()
	ctx := context.Background()

	require.NoError(t, env.pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-saml", Protocol: "saml", TenantSlug: "test", SourceID: env.sourceID,
	}, 10*time.Minute))

	form := url.Values{}
	form.Set("id_token", "tok")
	resp, err := client.PostForm(env.server.URL+"/t/test/oidc/login/complete?state=flow-saml", form)
	require.NoError(t, err)
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
