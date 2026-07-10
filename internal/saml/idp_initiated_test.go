package saml

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idpInitiatedEnv wires a full tenant IdP (signer + SP provider + multi-tenant
// session provider with an injected fake verifier) for IdP-initiated tests.
type idpInitiatedEnv struct {
	server   *httptest.Server
	verifier *fakeVerifier
	entityID string
}

func setupIdPInitiatedEnv(t *testing.T) *idpInitiatedEnv {
	return setupIdPInitiatedEnvWith(t, true)
}

func setupIdPInitiatedEnvWith(t *testing.T, allowIdPInitiated bool) *idpInitiatedEnv {
	t.Helper()
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(ms, "t")
	appStore := store.NewAppStore(ms, "t")
	claimStore := store.NewClaimStore(ms, "t")
	sourceStore := store.NewSourceStore(ms, "t")
	sessionStore := store.NewSessionStore(ms, "t")
	ctx := context.Background()

	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug: "acme", DisplayName: "ACME", Plan: "free", Status: "active",
	}))

	sourceID, err := sourceStore.Create(ctx, "acme", &tenant.IdentitySource{
		DisplayName: "Cognito", Type: "cognito",
		PoolID: "us-east-1_abc123", Region: "us-east-1",
		Domain: "acme.auth.us-east-1.amazoncognito.com", ClientID: "client-1", Status: "active",
	})
	require.NoError(t, err)

	const entityID = "https://sp.example.com/saml"
	_, err = appStore.Create(ctx, "acme", &tenant.Application{
		DisplayName: "SP", Protocol: "saml", SourceID: sourceID, Status: "active",
	}, &tenant.SAMLConfig{
		EntityID:          entityID,
		AcsURL:            "https://sp.example.com/acs",
		AcsURLs:           []string{"https://sp.example.com/acs"},
		NameIDFormat:      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:      "email",
		AllowIDPInitiated: allowIdPInitiated,
	})
	require.NoError(t, err)

	spProvider := NewSPProvider(appStore)
	sessionProv := NewSessionProvider(
		WithSourceStore(sourceStore),
		WithAppStore(appStore),
		WithHMACKey([]byte("test-hmac-key-for-unit-tests-32b")),
		WithProviderBaseURL("https://idp.example.com"),
	)
	verifier := &fakeVerifier{claims: map[string]interface{}{
		"sub": "user-1", "email": "user@example.com", "given_name": "Test", "family_name": "User",
	}}
	sessionProv.verifierFactory = func(_, _ string) idTokenVerifier { return verifier }
	assertMaker := NewAssertionMaker(appStore, claimStore)

	handler := NewTenantIdPHandler(
		WithSigner(signer),
		WithCertificate(cert),
		WithSPProvider(spProvider),
		WithSessionProvider(sessionProv),
		WithAssertionMaker(assertMaker),
		WithBaseURL("https://idp.example.com"),
	)

	r := chi.NewRouter()
	RegisterTenantRoutes(r, TenantRoutesConfig{
		Handler:     handler,
		SessionProv: sessionProv,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       store.NewAuditStore(ms, "t"),
	})

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return &idpInitiatedEnv{server: ts, verifier: verifier, entityID: entityID}
}

func TestIdPInitiated_Success_EmitsSAMLResponse(t *testing.T) {
	env := setupIdPInitiatedEnv(t)

	form := url.Values{}
	form.Set("id_token", "the.id.token")
	form.Set("entityId", env.entityID)
	form.Set("relayState", "deep-link-123")

	resp, err := http.PostForm(env.server.URL+"/t/acme/saml/idp-initiate", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// crewjam writes an HTTP-POST auto-submit form to the SP's ACS.
	assert.Contains(t, html, "SAMLResponse")
	assert.Contains(t, html, "https://sp.example.com/acs")
	assert.Contains(t, html, "deep-link-123") // RelayState echoed
	// Token was verified against the app's bound source client id.
	assert.Equal(t, "client-1", env.verifier.gotClientID)
	assert.Equal(t, "the.id.token", env.verifier.gotToken)
}

func TestIdPInitiated_BearerHeaderAccepted(t *testing.T) {
	env := setupIdPInitiatedEnv(t)

	form := url.Values{}
	form.Set("entityId", env.entityID)
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/t/acme/saml/idp-initiate", nil)
	require.NoError(t, err)
	// entityId via query so we can use a bodyless bearer request.
	req.URL.RawQuery = "entityId=" + url.QueryEscape(env.entityID)
	req.Header.Set("Authorization", "Bearer header.token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "header.token", env.verifier.gotToken)
}

func TestIdPInitiated_MissingToken(t *testing.T) {
	env := setupIdPInitiatedEnv(t)
	form := url.Values{}
	form.Set("entityId", env.entityID)
	resp, err := http.PostForm(env.server.URL+"/t/acme/saml/idp-initiate", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIdPInitiated_MissingEntityID(t *testing.T) {
	env := setupIdPInitiatedEnv(t)
	form := url.Values{}
	form.Set("id_token", "tok")
	resp, err := http.PostForm(env.server.URL+"/t/acme/saml/idp-initiate", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIdPInitiated_UnknownApp_Unauthorized(t *testing.T) {
	env := setupIdPInitiatedEnv(t)
	form := url.Values{}
	form.Set("id_token", "tok")
	form.Set("entityId", "https://unknown.example.com/saml")
	resp, err := http.PostForm(env.server.URL+"/t/acme/saml/idp-initiate", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	// Unknown app -> rejected before token verification (404).
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestIdPInitiated_InvalidToken(t *testing.T) {
	env := setupIdPInitiatedEnv(t)
	env.verifier.err = assert.AnError
	form := url.Values{}
	form.Set("id_token", "bad")
	form.Set("entityId", env.entityID)
	resp, err := http.PostForm(env.server.URL+"/t/acme/saml/idp-initiate", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIdPInitiated_DisabledApp_Forbidden(t *testing.T) {
	env := setupIdPInitiatedEnvWith(t, false) // IdP-initiated NOT enabled

	form := url.Values{}
	form.Set("id_token", "the.id.token")
	form.Set("entityId", env.entityID)

	resp, err := http.PostForm(env.server.URL+"/t/acme/saml/idp-initiate", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	// The token must not even be verified when the feature is disabled.
	assert.Empty(t, env.verifier.gotToken)
}
