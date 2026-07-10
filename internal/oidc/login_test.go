package oidc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// decodeOnlyVerifier is an explicit, named test double implementing
// cognito.IDTokenVerifier. It decodes the JWT payload and returns its claims
// WITHOUT verifying the signature, so tests can drive the callback flow with the
// mock Cognito server's unsigned (alg:none) tokens. Production never uses this —
// it selects the JWKS-backed verifier.
type decodeOnlyVerifier struct{}

func (decodeOnlyVerifier) Verify(tokenString, _ string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errTestBadToken
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

var errTestBadToken = errors.New("decodeOnlyVerifier: token is not a 3-part JWT")

// testLoginEnv holds the test environment for login/callback tests.
type testLoginEnv struct {
	router       chi.Router
	storage      *Storage
	appStore     *store.AppStore
	sourceStore  *store.SourceStore
	loginHandler *LoginHandler
	hmacKey      []byte
	appID        string
	sourceID     string
	cognito      *httptest.Server
	server       *httptest.Server
}

func setupLoginTestEnv(t *testing.T) *testLoginEnv {
	t.Helper()

	storage, appStore, _, sourceStore := newTestStorage(t)

	// Create mock Cognito server
	cognitoServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost {
			claims := map[string]interface{}{
				"sub":            "cognito-user-sub-123",
				"email":          "user@example.com",
				"email_verified": true,
				"given_name":     "Test",
				"family_name":    "User",
				"token_use":      "id",
				"exp":            time.Now().Add(1 * time.Hour).Unix(),
				"iat":            time.Now().Unix(),
			}
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
			payload, _ := json.Marshal(claims)
			payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
			token := header + "." + payloadB64 + "."

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id_token":     token,
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
			})
			return
		}
		http.NotFound(w, r)
	}))

	// Patch http.DefaultTransport to trust the mock Cognito TLS certificate.
	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test-only
		},
	}
	t.Cleanup(func() {
		http.DefaultTransport = origTransport
		cognitoServer.Close()
	})

	cognitoDomain := strings.TrimPrefix(cognitoServer.URL, "https://")

	ctx := context.Background()

	// Bootstrap tenant
	tenantStore := store.NewTenantStore(storage.db, "test")
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "test",
		DisplayName: "Test Tenant",
		Plan:        "free",
		Status:      "active",
	}))

	// Create identity source
	sourceID, err := sourceStore.Create(ctx, "test", &tenant.IdentitySource{
		DisplayName: "Test Cognito",
		Type:        "cognito",
		Domain:      cognitoDomain,
		PoolID:      "eu-north-1_TEST",
		ClientID:    "test-cognito-client",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	// Create OIDC app
	appID, err := appStore.Create(ctx, "test", &tenant.Application{
		DisplayName: "Login Test OIDC App",
		Protocol:    "oidc",
		SourceID:    sourceID,
		Status:      "active",
	}, nil)
	require.NoError(t, err)

	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://rp.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email", "profile"},
		TokenEndpointAuthMethod: "none",
		IDTokenLifetimeSec:      3600,
	}
	require.NoError(t, appStore.UpdateOIDCConfig(ctx, "test", appID, oidcCfg))

	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)

	// Create an unstarted server so we know the base URL.
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	server := httptest.NewUnstartedServer(dummyHandler)
	server.Start()
	baseURL := server.URL

	// The mock Cognito server issues unsigned (alg:none) tokens and exposes no
	// JWKS endpoint, so the production JWKS verifier cannot validate them.
	// Inject an explicit, named test verifier that decodes the token's claims
	// without checking the signature — exercising the exported injection seam.
	loginHandler, err := NewLoginHandler(storage, appStore, sourceStore, nil, hmacKey, baseURL, nil,
		WithVerifierFactory(func(_, _ string) cognito.IDTokenVerifier { return decodeOnlyVerifier{} }))
	require.NoError(t, err)

	// Build the real router with login/callback routes.
	r := chi.NewRouter()

	// Root-level /login redirect
	r.Get("/login", loginHandler.HandleLoginRedirect)

	r.Route("/t/{tenant}/oidc", func(r chi.Router) {
		r.Get("/login", loginHandler.HandleLogin)
		r.Get("/callback", loginHandler.HandleCallback)
	})

	server.Config.Handler = r

	t.Cleanup(server.Close)

	return &testLoginEnv{
		router:       r,
		storage:      storage,
		appStore:     appStore,
		sourceStore:  sourceStore,
		loginHandler: loginHandler,
		hmacKey:      hmacKey,
		appID:        appID,
		sourceID:     sourceID,
		cognito:      cognitoServer,
		server:       server,
	}
}

// noRedirectClient returns an http.Client that does not follow redirects.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestHandleLogin_RedirectsToCognito(t *testing.T) {
	env := setupLoginTestEnv(t)
	ctx := context.Background()
	client := noRedirectClient()

	// Create an auth request in storage.
	authReq := &oidc.AuthRequest{
		ClientID:     env.appID,
		RedirectURI:  "https://rp.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		State:        "rp-state-123",
		Nonce:        "rp-nonce-456",
		ResponseType: oidc.ResponseTypeCode,
	}

	created, err := env.storage.CreateAuthRequest(ctx, authReq, "")
	require.NoError(t, err)

	// Call the login handler.
	loginURL := env.server.URL + "/t/test/oidc/login?authRequestID=" + created.GetID()
	resp, err := client.Get(loginURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Should redirect (302) to Cognito.
	assert.Equal(t, http.StatusFound, resp.StatusCode, "login should redirect to Cognito")

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "Location header must be set")

	locURL, err := url.Parse(loc)
	require.NoError(t, err)

	// Verify it redirects to the mock Cognito domain.
	cognitoDomain := strings.TrimPrefix(env.cognito.URL, "https://")
	assert.Equal(t, cognitoDomain, locURL.Host, "should redirect to Cognito domain")

	q := locURL.Query()

	// PKCE parameters
	assert.NotEmpty(t, q.Get("code_challenge"), "code_challenge must be present")
	assert.Equal(t, "S256", q.Get("code_challenge_method"), "code_challenge_method must be S256")

	// OAuth2 parameters
	assert.Equal(t, "code", q.Get("response_type"), "response_type must be code")
	assert.Equal(t, created.GetID(), q.Get("state"), "state must be the authRequestID")
	assert.Contains(t, q.Get("scope"), "openid", "scope must include openid")

	// redirect_uri should point to the OIDC callback
	redirectURI := q.Get("redirect_uri")
	assert.Contains(t, redirectURI, "/t/test/oidc/callback", "redirect_uri must point to tenant-scoped callback")

	// Verify flow cookie is set.
	var foundFlowCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == oidcFlowCookieName {
			foundFlowCookie = true
			assert.NotEmpty(t, c.Value, "flow cookie must have a value")
			assert.True(t, c.HttpOnly, "flow cookie must be HttpOnly")
			break
		}
	}
	assert.True(t, foundFlowCookie, "oidc_flow cookie must be set")
}

func TestHandleLogin_MissingAuthRequestID(t *testing.T) {
	env := setupLoginTestEnv(t)

	resp, err := http.Get(env.server.URL + "/t/test/oidc/login")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleLogin_InvalidAuthRequestID(t *testing.T) {
	env := setupLoginTestEnv(t)

	resp, err := http.Get(env.server.URL + "/t/test/oidc/login?authRequestID=nonexistent-id")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandleCallback_CompletesAuthRequest(t *testing.T) {
	env := setupLoginTestEnv(t)
	ctx := context.Background()
	client := noRedirectClient()

	// Step 1: Create an auth request.
	authReq := &oidc.AuthRequest{
		ClientID:     env.appID,
		RedirectURI:  "https://rp.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		State:        "rp-state-123",
		ResponseType: oidc.ResponseTypeCode,
	}

	created, err := env.storage.CreateAuthRequest(ctx, authReq, "")
	require.NoError(t, err)
	authRequestID := created.GetID()

	// Step 2: Call the login handler to get the flow cookie.
	loginURL := env.server.URL + "/t/test/oidc/login?authRequestID=" + authRequestID
	loginResp, err := client.Get(loginURL)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()
	require.Equal(t, http.StatusFound, loginResp.StatusCode)

	// Extract the flow cookie.
	var flowCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie, "flow cookie must be set")

	// Step 3: Simulate Cognito callback with code and state.
	callbackURL := env.server.URL + "/t/test/oidc/callback?code=test-auth-code&state=" + url.QueryEscape(authRequestID)
	callbackReq, err := http.NewRequest(http.MethodGet, callbackURL, nil)
	require.NoError(t, err)
	callbackReq.AddCookie(flowCookie)

	callbackResp, err := client.Do(callbackReq)
	require.NoError(t, err)
	defer func() { _ = callbackResp.Body.Close() }()

	// Should redirect to the authorize callback endpoint.
	require.Equal(t, http.StatusFound, callbackResp.StatusCode)

	loc := callbackResp.Header.Get("Location")
	require.NotEmpty(t, loc, "Location header must be set after callback")
	assert.Contains(t, loc, "/t/test/oidc/authorize/callback", "should redirect to authorize/callback")
	assert.Contains(t, loc, "id="+authRequestID, "redirect must include the auth request ID")

	// Verify the auth request is now marked as done.
	completedReq, err := env.storage.AuthRequestByID(ctx, authRequestID)
	require.NoError(t, err)
	assert.True(t, completedReq.Done(), "auth request should be marked as done")
	assert.Equal(t, "cognito-user-sub-123", completedReq.GetSubject(), "subject should be set from Cognito claims")

	// Verify the flow cookie is cleared.
	var flowCookieCleared bool
	for _, c := range callbackResp.Cookies() {
		if c.Name == oidcFlowCookieName && c.MaxAge < 0 {
			flowCookieCleared = true
			break
		}
	}
	assert.True(t, flowCookieCleared, "flow cookie should be cleared after callback")
}

// TestHandleCallback_RejectsUnverifiedToken verifies that the
// OAuth-code callback checks the ID token's signature/claims in-process and
// fails CLOSED when verification fails, rather than decoding the token and
// establishing a session regardless.
func TestHandleCallback_RejectsUnverifiedToken(t *testing.T) {
	env := setupLoginTestEnv(t)
	ctx := context.Background()
	client := noRedirectClient()

	// Swap in a verifier that rejects every token, simulating a bad signature,
	// wrong audience, or a token minted by a compromised endpoint.
	env.loginHandler.verifierFactory = func(_, _ string) idTokenVerifier {
		return rejectingVerifier{}
	}

	authReq := &oidc.AuthRequest{
		ClientID:     env.appID,
		RedirectURI:  "https://rp.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		ResponseType: oidc.ResponseTypeCode,
	}
	created, err := env.storage.CreateAuthRequest(ctx, authReq, "")
	require.NoError(t, err)
	authRequestID := created.GetID()

	loginResp, err := client.Get(env.server.URL + "/t/test/oidc/login?authRequestID=" + authRequestID)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()
	require.Equal(t, http.StatusFound, loginResp.StatusCode)

	var flowCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie)

	callbackURL := env.server.URL + "/t/test/oidc/callback?code=test-auth-code&state=" + url.QueryEscape(authRequestID)
	callbackReq, err := http.NewRequest(http.MethodGet, callbackURL, nil)
	require.NoError(t, err)
	callbackReq.AddCookie(flowCookie)

	callbackResp, err := client.Do(callbackReq)
	require.NoError(t, err)
	defer func() { _ = callbackResp.Body.Close() }()

	// Must NOT redirect on to the authorize callback — the token was not verified.
	assert.Equal(t, http.StatusBadGateway, callbackResp.StatusCode,
		"callback must reject a token that fails verification")

	// The auth request must remain incomplete: no session is established.
	req, err := env.storage.AuthRequestByID(ctx, authRequestID)
	require.NoError(t, err)
	assert.False(t, req.Done(), "auth request must not be completed when verification fails")
}

// rejectingVerifier is a named test double whose Verify always fails, used to
// assert the callback fails closed. It never accepts a token.
type rejectingVerifier struct{}

func (rejectingVerifier) Verify(_, _ string) (map[string]interface{}, error) {
	return nil, errors.New("rejectingVerifier: verification failed")
}

func TestHandleCallback_MissingCode(t *testing.T) {
	env := setupLoginTestEnv(t)

	// Callback without code parameter.
	resp, err := http.Get(env.server.URL + "/t/test/oidc/callback?state=some-state")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleCallback_MissingState(t *testing.T) {
	env := setupLoginTestEnv(t)

	resp, err := http.Get(env.server.URL + "/t/test/oidc/callback?code=some-code")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleCallback_MissingFlowCookie(t *testing.T) {
	env := setupLoginTestEnv(t)

	resp, err := http.Get(env.server.URL + "/t/test/oidc/callback?code=some-code&state=some-state")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleCallback_StateMismatch(t *testing.T) {
	env := setupLoginTestEnv(t)
	ctx := context.Background()
	client := noRedirectClient()

	// Create an auth request and get a flow cookie.
	authReq := &oidc.AuthRequest{
		ClientID:     env.appID,
		RedirectURI:  "https://rp.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}
	created, err := env.storage.CreateAuthRequest(ctx, authReq, "")
	require.NoError(t, err)

	loginURL := env.server.URL + "/t/test/oidc/login?authRequestID=" + created.GetID()
	loginResp, err := client.Get(loginURL)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	var flowCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie)

	// Call callback with a DIFFERENT state parameter (CSRF attempt).
	callbackURL := env.server.URL + "/t/test/oidc/callback?code=test-code&state=wrong-state-id"
	callbackReq, err := http.NewRequest(http.MethodGet, callbackURL, nil)
	require.NoError(t, err)
	callbackReq.AddCookie(flowCookie)

	callbackResp, err := client.Do(callbackReq)
	require.NoError(t, err)
	defer func() { _ = callbackResp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, callbackResp.StatusCode, "state mismatch should return 403")
}

func TestHandleLoginRedirect_ResolveTenant(t *testing.T) {
	env := setupLoginTestEnv(t)
	ctx := context.Background()
	client := noRedirectClient()

	// Create an auth request with a tenant slug set.
	// Normally this is set by CreateAuthRequest when the issuer context is present.
	// For this test, we set it manually via CompleteAuthRequest pattern.
	authReq := &oidc.AuthRequest{
		ClientID:     env.appID,
		RedirectURI:  "https://rp.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}
	created, err := env.storage.CreateAuthRequest(ctx, authReq, "")
	require.NoError(t, err)

	// Manually update the tenant slug on the auth request in storage.
	// In production, this is set by CreateAuthRequest via the issuer context.
	var item authRequestItem
	err = env.storage.db.Get(ctx, oidcAuthRequestPK(created.GetID()), oidcAuthRequestSK(), &item)
	require.NoError(t, err)
	item.TenantSlug = "test"
	item.PK = oidcAuthRequestPK(created.GetID())
	item.SK = oidcAuthRequestSK()
	err = env.storage.db.Put(ctx, &item)
	require.NoError(t, err)

	// Call the root /login redirect.
	loginURL := env.server.URL + "/login?authRequestID=" + created.GetID()
	resp, err := client.Get(loginURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode, "should redirect to tenant-scoped login")

	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/t/test/oidc/login", "should redirect to tenant-scoped login path")
	assert.Contains(t, loc, "authRequestID="+created.GetID(), "should preserve the authRequestID")
}

func TestHandleLoginRedirect_MissingAuthRequestID(t *testing.T) {
	env := setupLoginTestEnv(t)

	resp, err := http.Get(env.server.URL + "/login")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCookieSigningRoundtrip(t *testing.T) {
	hmacKey := make([]byte, 32)
	_, err := rand.Read(hmacKey)
	require.NoError(t, err)

	h, err := NewLoginHandler(nil, nil, nil, nil, hmacKey, "http://localhost", nil)
	require.NoError(t, err)

	state := &oidcFlowState{
		AuthRequestID: "test-request-123",
		Verifier:      "test-verifier-abc",
		TenantSlug:    "acme",
		SourceID:      "src-1",
		CreatedAt:     time.Now().Unix(),
	}

	// Encode
	encoded, err := h.signedEncode(state)
	require.NoError(t, err)
	assert.Contains(t, encoded, ".", "encoded cookie must contain a dot separator")

	// Decode
	decoded, err := h.signedDecode(encoded)
	require.NoError(t, err)
	assert.Equal(t, state.AuthRequestID, decoded.AuthRequestID)
	assert.Equal(t, state.Verifier, decoded.Verifier)
	assert.Equal(t, state.TenantSlug, decoded.TenantSlug)
	assert.Equal(t, state.SourceID, decoded.SourceID)
	assert.Equal(t, state.CreatedAt, decoded.CreatedAt)
}

func TestCookieSigningTamperedPayload(t *testing.T) {
	hmacKey := make([]byte, 32)
	_, err := rand.Read(hmacKey)
	require.NoError(t, err)

	h, err := NewLoginHandler(nil, nil, nil, nil, hmacKey, "http://localhost", nil)
	require.NoError(t, err)

	state := &oidcFlowState{
		AuthRequestID: "test-request-123",
		Verifier:      "test-verifier-abc",
		TenantSlug:    "acme",
		SourceID:      "src-1",
		CreatedAt:     time.Now().Unix(),
	}

	encoded, err := h.signedEncode(state)
	require.NoError(t, err)

	// Tamper with the payload
	parts := strings.SplitN(encoded, ".", 2)
	require.Len(t, parts, 2)
	tampered := "tampered" + parts[0] + "." + parts[1]

	_, err = h.signedDecode(tampered)
	assert.Error(t, err, "decoding a tampered cookie should fail")
}

func TestCompleteAuthRequest(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}

	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)
	assert.False(t, authReq.Done(), "new auth request should not be done")

	// Complete the request with Cognito claims. email_verified=true here.
	err = s.CompleteAuthRequest(ctx, authReq.GetID(), "user-sub-123", "user@example.com", "Test", "User", true, []string{"admins", "users"})
	require.NoError(t, err)

	// Verify it is now done.
	completed, err := s.AuthRequestByID(ctx, authReq.GetID())
	require.NoError(t, err)
	assert.True(t, completed.Done(), "completed auth request should be done")
	assert.Equal(t, "user-sub-123", completed.GetSubject())
	assert.False(t, completed.GetAuthTime().IsZero(), "auth time should be set")

	// email_verified must reflect the real Cognito claim that was passed
	// in, not an unconditional true.
	verifiedInfo := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromScopes(ctx, verifiedInfo, "user-sub-123", "test-client", []string{"email"}))
	assert.True(t, bool(verifiedInfo.EmailVerified), "email_verified must carry through when the Cognito claim is true")
}

// TestCompleteAuthRequest_EmailVerifiedFalse verifies that an
// unverified Cognito email surfaces as email_verified=false everywhere,
// never a hard-coded true.
func TestCompleteAuthRequest_EmailVerifiedFalse(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		ResponseType: oidc.ResponseTypeCode,
	}
	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	// Cognito asserted email_verified=false for this login.
	require.NoError(t, s.CompleteAuthRequest(ctx, authReq.GetID(), "unverified-sub", "unverified@example.com", "No", "Verify", false, nil))

	info := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromScopes(ctx, info, "unverified-sub", "test-client", []string{"email"}))
	assert.Equal(t, "unverified@example.com", info.Email)
	assert.False(t, bool(info.EmailVerified), "unverified Cognito email must not be advertised as verified")
}

func TestCompleteAuthRequest_NotFound(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	err := s.CompleteAuthRequest(ctx, "nonexistent-id", "user-sub-123", "user@example.com", "Test", "User", true, []string{})
	assert.Error(t, err, "completing a nonexistent auth request should fail")
}

func TestTenantSlugFromIssuer(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		expected string
	}{
		{
			name:     "standard issuer",
			issuer:   "http://localhost/t/acme/oidc",
			expected: "acme",
		},
		{
			name:     "HTTPS issuer",
			issuer:   "https://auth.example.com/t/tenant-123/oidc",
			expected: "tenant-123",
		},
		{
			name:     "empty issuer",
			issuer:   "",
			expected: "",
		},
		{
			name:     "issuer without /t/ marker",
			issuer:   "http://localhost/oidc",
			expected: "",
		},
		{
			name:     "issuer with trailing slash",
			issuer:   "http://localhost/t/acme/oidc/",
			expected: "acme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tenantSlugFromIssuer(tt.issuer)
			assert.Equal(t, tt.expected, got)
		})
	}
}
