package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cognitoClaimsFor builds minimal verified Cognito claims for an email/sub, for
// constructing a pre-existing session cookie in the shadowing regression tests.
func cognitoClaimsFor(email, sub string) *cognito.UserClaims {
	return &cognito.UserClaims{
		Sub:              sub,
		Email:            email,
		EmailVerified:    true,
		CustomAttributes: map[string]string{},
	}
}

// idpInitiatedEnv wires a full tenant IdP (signer + SP provider + multi-tenant
// session provider with an injected fake verifier) for IdP-initiated tests.
type idpInitiatedEnv struct {
	server      *httptest.Server
	verifier    *fakeVerifier
	entityID    string
	sessionProv *SessionProvider
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
	return &idpInitiatedEnv{server: ts, verifier: verifier, entityID: entityID, sessionProv: sessionProv}
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

// nameIDFromAutoPost extracts the Subject NameID from the base64-encoded
// SAMLResponse carried in the IdP's HTTP-POST auto-submit HTML form.
func nameIDFromAutoPost(t *testing.T, pageHTML string) string {
	t.Helper()
	// The form field looks like: <input ... name="SAMLResponse" value="BASE64"/>
	marker := `name="SAMLResponse" value="`
	i := strings.Index(pageHTML, marker)
	require.GreaterOrEqual(t, i, 0, "auto-post HTML must contain a SAMLResponse field")
	rest := pageHTML[i+len(marker):]
	j := strings.Index(rest, `"`)
	require.GreaterOrEqual(t, j, 0)
	// crewjam HTML-escapes the base64 value in the auto-post form (e.g. '+' ->
	// '&#43;'), so unescape before decoding.
	b64 := html.UnescapeString(rest[:j])
	raw, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	var resp struct {
		Assertion struct {
			Subject struct {
				NameID string `xml:"NameID"`
			} `xml:"Subject"`
		} `xml:"Assertion"`
	}
	require.NoError(t, xml.Unmarshal(raw, &resp))
	return resp.Assertion.Subject.NameID
}

// postIdPInitiateWithCookie POSTs an IdP-initiated request carrying the given
// raw saml_session cookie value, returning the response.
func postIdPInitiateWithCookie(t *testing.T, env *idpInitiatedEnv, cookieValue string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("id_token", "the.id.token")
	form.Set("entityId", env.entityID)
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/t/acme/saml/idp-initiate",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieValue})
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// TestIdPInitiated_FreshTokenWinsOverExistingCookie is the H-2 regression: the
// browser already holds a valid saml_session cookie for a DIFFERENT user (Y),
// bound to this same tenant/SP. The caller then presents a fresh, verified ID
// token for user X. The emitted assertion MUST be for X (the freshly verified
// token), not Y (the pre-existing cookie). On the unfixed code r.AddCookie
// appended the fresh cookie after the browser's, and r.Cookie() returned Y.
func TestIdPInitiated_FreshTokenWinsOverExistingCookie(t *testing.T) {
	env := setupIdPInitiatedEnv(t)

	// A valid, correctly-bound session cookie for a PREVIOUS user Y.
	prevSession := buildSessionFromClaims(cognitoClaimsFor("previous-user@example.com", "user-prev"))
	cookieY, err := env.sessionProv.encodeBoundSessionCookie(prevSession, "acme", "src-ignored", env.entityID)
	require.NoError(t, err)

	// The fresh token verifies to user X.
	env.verifier.claims = map[string]interface{}{
		"sub": "user-x", "email": "user@example.com", "given_name": "Ex", "family_name": "User",
	}

	resp := postIdPInitiateWithCookie(t, env, cookieY)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	nameID := nameIDFromAutoPost(t, string(body))
	assert.Equal(t, "user@example.com", nameID,
		"assertion must carry the freshly verified token identity, not the pre-existing cookie's")
	assert.NotEqual(t, "previous-user@example.com", nameID)
}

// TestIdPInitiated_StaleCookie_NoPanic is the M-1 regression: a browser carrying
// a stale/garbage saml_session cookie on an IdP-initiated request used to drive
// a nil-pointer dereference (req.ServiceProviderMetadata) and a 500. It must now
// complete normally (200) with the correct, freshly verified identity.
func TestIdPInitiated_StaleCookie_NoPanic(t *testing.T) {
	env := setupIdPInitiatedEnv(t)

	resp := postIdPInitiateWithCookie(t, env, "garbage-not-a-valid-signed-cookie")
	defer func() { _ = resp.Body.Close() }()

	require.NotEqual(t, http.StatusInternalServerError, resp.StatusCode,
		"a stale/invalid cookie must not cause a nil-pointer panic / 500")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	nameID := nameIDFromAutoPost(t, string(body))
	assert.Equal(t, "user@example.com", nameID)
}

// TestIdPInitiated_ForeignCookie_IgnoredNoPanic is a second M-1/H-2 case: the
// pre-existing cookie is validly signed but bound to a DIFFERENT SP. The trusted
// hand-off must win (correct identity emitted) and the foreign cookie must not
// cause a panic or leak its SP binding.
func TestIdPInitiated_ForeignCookie_IgnoredNoPanic(t *testing.T) {
	env := setupIdPInitiatedEnv(t)

	foreignSession := buildSessionFromClaims(cognitoClaimsFor("foreign-user@example.com", "user-foreign"))
	foreignCookie, err := env.sessionProv.encodeBoundSessionCookie(
		foreignSession, "acme", "src-ignored", "https://other-sp.example.com/saml")
	require.NoError(t, err)

	resp := postIdPInitiateWithCookie(t, env, foreignCookie)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	nameID := nameIDFromAutoPost(t, string(body))
	assert.Equal(t, "user@example.com", nameID,
		"foreign-SP cookie must not shadow the freshly verified session")
}
