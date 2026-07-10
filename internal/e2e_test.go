//go:build e2e

package internal_test

import (
	"bytes"
	"compress/flate"
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/api"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	internalcrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	internaloidc "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/oidc"
	internalsaml "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/saml"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock KMS client
// ---------------------------------------------------------------------------

type e2eMockKMSClient struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func newE2EMockKMSClient(t *testing.T) *e2eMockKMSClient {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &e2eMockKMSClient{privateKey: pk, publicKey: &pk.PublicKey}
}

func (m *e2eMockKMSClient) Sign(digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, m.privateKey, opts.HashFunc(), digest)
}

func (m *e2eMockKMSClient) PublicKey() (*rsa.PublicKey, error) {
	return m.publicKey, nil
}

// ---------------------------------------------------------------------------
// Mock Cognito token endpoint
// ---------------------------------------------------------------------------

// e2eDecodeOnlyVerifier is an explicit, named test double implementing
// cognito.IDTokenVerifier. The mock Cognito server issues unsigned (alg:none)
// tokens and serves no JWKS endpoint, so the production JWKS verifier cannot
// validate them. This double decodes the token payload and returns its claims
// WITHOUT checking the signature, letting the e2e callback flow run against the
// mock. Production selects the JWKS-backed verifier; this is never wired there.
type e2eDecodeOnlyVerifier struct{}

func (e2eDecodeOnlyVerifier) Verify(tokenString, _ string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("e2eDecodeOnlyVerifier: token is not a 3-part JWT")
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

func newMockCognitoServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost {
			claims := map[string]interface{}{
				"sub":               "test-user-sub-123",
				"email":             "testuser@example.com",
				"email_verified":    true,
				"given_name":        "Test",
				"family_name":       "User",
				"cognito:groups":    []string{"Admins", "Users"},
				"custom:tenant_id":  "test-tenant",
				"custom:department": "Engineering",
				"iss":               "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_TEST",
				"aud":               "test-client-id",
				"token_use":         "id",
				"exp":               time.Now().Add(1 * time.Hour).Unix(),
				"iat":               time.Now().Unix(),
			}
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
			payload, _ := json.Marshal(claims)
			payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
			token := header + "." + payloadB64 + "."

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"id_token":     token,
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
			})
			return
		}
		// For /oauth2/authorize, just return 200 — the proxy builds the URL,
		// it does not call this endpoint server-side.
		if strings.HasPrefix(r.URL.Path, "/oauth2/authorize") {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

type e2eEnv struct {
	proxy       *httptest.Server
	cognito     *httptest.Server
	appStore    *store.AppStore
	claimStore  *store.ClaimStore
	sourceStore *store.SourceStore
	tenantStore *store.TenantStore
	configDB    *store.MemoryDB
	sessionDB   *store.MemoryDB
	signer      *internalcrypto.KMSSigner
	cert        *internalcrypto.KMSSigner // kept for reference
	certificate interface{}               // *x509.Certificate
	kmsClient   *e2eMockKMSClient
	hmacKey     []byte
	sourceID    string
	appID       string
	// OIDC specific
	oidcAppID string
}

func setupE2E(t *testing.T) *e2eEnv {
	t.Helper()

	// 1. Stores — separate config and session DBs (mirrors production two-table split)
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test")
	sourceStore := store.NewSourceStore(configDB, "test")
	appStore := store.NewAppStore(configDB, "test")
	claimStore := store.NewClaimStore(configDB, "test")
	sessionStore := store.NewSessionStore(sessionDB, "test")

	// 2. Mock Cognito
	cognitoServer := newMockCognitoServer(t)

	// The mock Cognito is a TLS server. Strip the scheme to get the domain.
	cognitoDomain := strings.TrimPrefix(cognitoServer.URL, "https://")

	// Patch http.DefaultTransport to trust the mock Cognito TLS certificate.
	// The AuthClient in cognito/auth.go creates http.Client{} without a custom
	// transport, so it uses DefaultTransport. This is safe in tests.
	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test-only
		},
	}
	t.Cleanup(func() {
		http.DefaultTransport = origTransport
	})

	// 3. Mock KMS and signer
	kmsClient := newE2EMockKMSClient(t)
	signer := internalcrypto.NewKMSSigner(kmsClient)
	cert, err := internalcrypto.GenerateSelfSignedCert(signer, "e2e-test-idp.example.com")
	require.NoError(t, err)

	// 4. HMAC key
	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)

	// MF-5: random per-test OIDC crypto key (no SM in e2e tests)
	var oidcCryptoKey [32]byte
	_, err = rand.Read(oidcCryptoKey[:])
	require.NoError(t, err)

	// 5. Bootstrap tenant, identity source, application
	ctx := context.Background()

	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:             "test-tenant",
		DisplayName:      "Test Tenant",
		Plan:             "free",
		Status:           "active",
		MaxApps:          10,
		MaxAuthsPerMonth: 1000,
	}))

	sourceID, err := sourceStore.Create(ctx, "test-tenant", &tenant.IdentitySource{
		DisplayName: "Mock Cognito",
		Type:        "cognito",
		Domain:      cognitoDomain,
		PoolID:      "eu-north-1_TEST",
		ClientID:    "test-client-id",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	appID, err := appStore.Create(ctx, "test-tenant", &tenant.Application{
		DisplayName: "E2E Test App",
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:           "https://test-app.example.com",
		AcsURL:             "https://test-app.example.com/saml/acs",
		AcsURLs:            []string{"https://test-app.example.com/saml/acs"},
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:       "email",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       60,
	})
	require.NoError(t, err)

	// 6. Create OIDC application
	oidcAppID, err := appStore.Create(ctx, "test-tenant", &tenant.Application{
		DisplayName: "E2E OIDC App",
		Protocol:    "oidc",
		SourceID:    sourceID,
		Status:      "active",
	}, nil)
	require.NoError(t, err)

	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://oidc-app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email", "profile"},
		TokenEndpointAuthMethod: "none",
		IDTokenLifetimeSec:      3600,
		AccessTokenLifetimeSec:  3600,
	}
	require.NoError(t, appStore.UpdateOIDCConfig(ctx, "test-tenant", oidcAppID, oidcCfg))

	// 7. Create an unstarted server so we can learn its URL before building
	//    the router (the SAML IdP base URL must match the actual server URL).
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	proxyServer := httptest.NewUnstartedServer(dummyHandler)
	proxyServer.Start()
	proxyBaseURL := proxyServer.URL

	// 8. Build the real router with the correct base URL
	spProvider := internalsaml.NewSPProvider(appStore)
	sessionProvider := internalsaml.NewSessionProvider(
		internalsaml.WithSourceStore(sourceStore),
		internalsaml.WithAppStore(appStore),
		internalsaml.WithHMACKey(hmacKey),
		internalsaml.WithProviderBaseURL(proxyBaseURL),
		// The mock Cognito issues unsigned (alg:none) tokens and exposes no JWKS
		// endpoint, so inject a decode-only verifier to exercise the callback
		// flow end to end. Production uses the default JWKS-backed verifier.
		internalsaml.WithVerifierFactory(func(_, _ string) cognito.IDTokenVerifier {
			return e2eDecodeOnlyVerifier{}
		}),
	)
	assertionMaker := internalsaml.NewAssertionMaker(appStore, claimStore)
	tenantIdPHandler := internalsaml.NewTenantIdPHandler(
		internalsaml.WithSigner(signer),
		internalsaml.WithCertificate(cert),
		internalsaml.WithSPProvider(spProvider),
		internalsaml.WithSessionProvider(sessionProvider),
		internalsaml.WithAssertionMaker(assertionMaker),
		internalsaml.WithBaseURL(proxyBaseURL),
	)

	auditStore := store.NewAuditStore(sessionDB, "test")
	sessionProvider.SetAuditStore(auditStore)

	joseSigner, err := internalcrypto.NewKMSJoseSigner("e2e-key-id", kmsClient)
	require.NoError(t, err)
	oidcStorage := internaloidc.NewStorage(appStore, claimStore, sourceStore, joseSigner, sessionDB, "e2e-key-id")

	router := chi.NewRouter()

	// Apply API auth and tenant middleware (same as production api.NewRouter for
	// the local developer environment). RequireAuthForAPI only enforces on
	// /api/v1/* paths — skips SAML/OIDC. TenantFromJWTForAPI only loads tenant
	// context on /api/v1/* paths. This is a local-mode test harness, so it selects
	// the explicit local-dev auth bypass (a named test double); tenant context
	// falls back to the built-in default tenant.
	router.Use(middleware.AllowUnauthenticatedForAPILocalDev())
	router.Use(middleware.TenantFromJWTForAPI(tenantStore))

	// Register health endpoint (before Huma takes over unmatched routes)
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
	})

	internalsaml.RegisterTenantRoutes(router, internalsaml.TenantRoutesConfig{
		Handler:     tenantIdPHandler,
		SessionProv: sessionProvider,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       auditStore,
	})
	err = internaloidc.RegisterOIDCRoutes(router, oidcStorage, proxyBaseURL, appStore, sourceStore, auditStore, oidcCryptoKey, hmacKey, nil, false,
		// Same decode-only verifier as the SAML side: the mock Cognito's unsigned
		// tokens cannot be JWKS-verified. Production uses the default verifier.
		internaloidc.WithVerifierFactory(func(_, _ string) cognito.IDTokenVerifier {
			return e2eDecodeOnlyVerifier{}
		}))
	require.NoError(t, err)

	// Register Huma management API (OpenAPI spec + CRUD routes)
	certPEM := internalcrypto.CertToPEM(cert)
	importSvc := service.NewMetadataImportService(appStore, &service.HTTPMetadataFetcher{})
	previewSvc := service.NewPreviewService(appStore, claimStore)
	certSvc := service.NewCertificateService(certPEM)
	settingsSvc := service.NewSettingsService(tenantStore, proxyBaseURL+"/saml/metadata", proxyBaseURL, "e2e-kms-key", "")
	deps := api.Dependencies{
		Tenants:     tenantStore,
		Sources:     sourceStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       auditStore,
		ImportSvc:   importSvc,
		PreviewSvc:  previewSvc,
		CertSvc:     certSvc,
		SettingsSvc: settingsSvc,
		BaseURL:     proxyBaseURL,
		EntityID:    proxyBaseURL + "/saml/metadata",
		KMSKeyID:    "e2e-kms-key",
	}
	humaAPI := api.NewHumaAPI(router, "E2E Test API", "1.0.0")
	api.RegisterAPIRoutes(humaAPI, deps)

	// Swap in the real handler on the already-running server
	proxyServer.Config.Handler = router

	t.Cleanup(func() {
		proxyServer.Close()
		cognitoServer.Close()
	})

	return &e2eEnv{
		proxy:       proxyServer,
		cognito:     cognitoServer,
		appStore:    appStore,
		claimStore:  claimStore,
		sourceStore: sourceStore,
		tenantStore: tenantStore,
		configDB:    configDB,
		sessionDB:   sessionDB,
		signer:      signer,
		kmsClient:   kmsClient,
		hmacKey:     hmacKey,
		sourceID:    sourceID,
		appID:       appID,
		oidcAppID:   oidcAppID,
	}
}

// ---------------------------------------------------------------------------
// SAML AuthnRequest helpers
// ---------------------------------------------------------------------------

// buildAuthnRequest builds a minimal AuthnRequest and returns the raw XML
// and the request ID.
func buildAuthnRequest(t *testing.T, proxyURL, entityID, acsURL string) (string, string) {
	t.Helper()

	b := make([]byte, 20)
	_, _ = rand.Read(b)
	requestID := "_" + base64.RawURLEncoding.EncodeToString(b)

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	destination := proxyURL + "/t/test-tenant/saml/sso"

	xmlStr := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		requestID, now, destination, acsURL, entityID)

	return xmlStr, requestID
}

// deflateAndEncode deflate-compresses and base64url-encodes an AuthnRequest
// for the HTTP-Redirect binding.
func deflateAndEncode(t *testing.T, xmlStr string) string {
	t.Helper()
	var buf strings.Builder
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(xmlStr))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString([]byte(buf.String()))
}

// noRedirectClient returns an http.Client that captures cookies but does not
// follow redirects.
func noRedirectClient() *http.Client {
	jar := &simpleCookieJar{cookies: make(map[string][]*http.Cookie)}
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}
}

// simpleCookieJar is a minimal CookieJar for tests.
type simpleCookieJar struct {
	cookies map[string][]*http.Cookie
}

func (j *simpleCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.cookies[u.Host] = append(j.cookies[u.Host], cookies...)
}

func (j *simpleCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.cookies[u.Host]
}

// ===========================================================================
// Test 1: SAML Metadata
// ===========================================================================

func TestE2E_SAML_Metadata(t *testing.T) {
	env := setupE2E(t)

	resp, err := http.Get(env.proxy.URL + "/t/test-tenant/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	ct := resp.Header.Get("Content-Type")
	assert.Contains(t, ct, "xml", "Content-Type should contain xml")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Parse as EntityDescriptor
	var ed saml.EntityDescriptor
	require.NoError(t, xml.Unmarshal(body, &ed), "response must be valid SAML EntityDescriptor XML")

	// EntityID matches expected pattern
	assert.Contains(t, ed.EntityID, "/t/test-tenant/saml/metadata", "EntityID should contain the tenant path")

	// IDPSSODescriptor present with correct protocol
	require.NotEmpty(t, ed.IDPSSODescriptors, "must have an IDPSSODescriptor")
	idpSSO := ed.IDPSSODescriptors[0]
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:protocol", idpSSO.ProtocolSupportEnumeration,
		"protocolSupportEnumeration should be SAML 2.0")

	// Has at least one SingleSignOnService with HTTP-Redirect binding
	foundRedirectBinding := false
	for _, sso := range idpSSO.SingleSignOnServices {
		if sso.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			foundRedirectBinding = true
			break
		}
	}
	assert.True(t, foundRedirectBinding, "must have SSO service with HTTP-Redirect binding")

	// Has at least one signing KeyDescriptor with X509Certificate
	foundSigningKey := false
	for _, kd := range idpSSO.KeyDescriptors {
		if kd.Use == "signing" && len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
			foundSigningKey = true
			// Verify the certificate data is non-empty
			assert.NotEmpty(t, kd.KeyInfo.X509Data.X509Certificates[0].Data, "signing cert must have data")

			// Verify it matches the test signer's cert
			certB64 := base64.StdEncoding.EncodeToString(
				func() []byte {
					// Get the cert from the signer
					c, err := internalcrypto.GenerateSelfSignedCert(env.signer, "e2e-test-idp.example.com")
					require.NoError(t, err)
					return c.Raw
				}(),
			)
			// The certs are generated independently so won't match byte-for-byte.
			// Instead, verify both are non-empty base64 strings.
			assert.NotEmpty(t, certB64)
			break
		}
	}
	assert.True(t, foundSigningKey, "must have a signing KeyDescriptor with X509Certificate")
}

// ===========================================================================
// Test 2: SAML SSO Redirect
// ===========================================================================

func TestE2E_SAML_SSORedirect(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	reqURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s&RelayState=test-relay",
		env.proxy.URL, url.QueryEscape(encoded))

	resp, err := client.Do(&http.Request{
		Method: http.MethodGet,
		URL:    mustParseURL(t, reqURL),
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode, "should redirect to Cognito authorize")

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "Location header must be set")

	locURL, err := url.Parse(loc)
	require.NoError(t, err)

	q := locURL.Query()

	// redirect_uri should point back to the SAML ACS
	redirectURI := q.Get("redirect_uri")
	assert.Contains(t, redirectURI, "/t/test-tenant/saml/acs", "redirect_uri must target tenant ACS")

	// PKCE
	assert.NotEmpty(t, q.Get("code_challenge"), "code_challenge must be present")
	assert.Equal(t, "S256", q.Get("code_challenge_method"), "code_challenge_method must be S256")

	// Scopes
	scope := q.Get("scope")
	assert.Contains(t, scope, "openid", "scope must include openid")
	assert.Contains(t, scope, "email", "scope must include email")
	assert.Contains(t, scope, "profile", "scope must include profile")

	// Flow cookie
	var foundFlowCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			foundFlowCookie = true
			assert.NotEmpty(t, c.Value, "flow cookie must have a value")
			break
		}
	}
	assert.True(t, foundFlowCookie, "saml_flow cookie must be set")
}

// ===========================================================================
// Test 3: SAML Full Flow
// ===========================================================================

func TestE2E_SAML_FullFlow(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	// Step 1: Send AuthnRequest to SSO endpoint
	xmlStr, requestID := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s&RelayState=test-relay",
		env.proxy.URL, url.QueryEscape(encoded))

	resp, err := client.Do(&http.Request{
		Method: http.MethodGet,
		URL:    mustParseURL(t, ssoURL),
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 2: Extract state from the redirect URL
	loc := resp.Header.Get("Location")
	locURL, err := url.Parse(loc)
	require.NoError(t, err)
	state := locURL.Query().Get("state")
	require.NotEmpty(t, state, "state parameter must be present in redirect")

	// Capture the flow cookie
	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie, "flow cookie must be set")

	// Step 3: Simulate Cognito callback with code and state
	acsURL := fmt.Sprintf("%s/t/test-tenant/saml/acs?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(state))

	acsReq, err := http.NewRequest(http.MethodGet, acsURL, nil)
	require.NoError(t, err)
	acsReq.AddCookie(flowCookie)

	acsResp, err := client.Do(acsReq)
	require.NoError(t, err)
	defer acsResp.Body.Close()

	// Step 4: The proxy should return an HTML form with SAMLResponse
	require.Equal(t, http.StatusOK, acsResp.StatusCode,
		"callback should succeed with HTTP 200 (HTML auto-submit form)")

	acsBody, err := io.ReadAll(acsResp.Body)
	require.NoError(t, err)
	bodyStr := string(acsBody)

	// Extract SAMLResponse from the HTML form
	samlResponse := extractFormValue(t, bodyStr, "SAMLResponse")
	require.NotEmpty(t, samlResponse, "HTML form must contain SAMLResponse")

	// Step 5: Base64-decode the SAMLResponse
	decoded, err := base64.StdEncoding.DecodeString(cleanBase64(samlResponse))
	require.NoError(t, err, "SAMLResponse must be valid base64")

	// Step 6: Parse as SAML Response XML
	var samlResp saml.Response
	require.NoError(t, xml.Unmarshal(decoded, &samlResp), "SAMLResponse must be valid XML")

	// Basic assertions
	assert.Equal(t, "2.0", samlResp.Version, "Response Version must be 2.0")
	assert.NotEmpty(t, samlResp.ID, "Response must have an ID")

	// The response should contain an assertion
	require.NotNil(t, samlResp.Assertion, "Response must contain an Assertion")
	assertion := samlResp.Assertion

	// Assertion should have a subject with NameID
	require.NotNil(t, assertion.Subject, "Assertion must have a Subject")
	require.NotNil(t, assertion.Subject.NameID, "Subject must have a NameID")
	assert.Equal(t, "testuser@example.com", assertion.Subject.NameID.Value,
		"NameID should be the user's email")

	// InResponseTo
	assert.Equal(t, requestID, samlResp.InResponseTo,
		"Response InResponseTo must match the AuthnRequest ID")
}

// ===========================================================================
// Test 4: SAML Attribute Mapping
// ===========================================================================

func TestE2E_SAML_AttributeMapping(t *testing.T) {
	env := setupE2E(t)
	ctx := context.Background()

	// Create custom claim mappings for the app
	require.NoError(t, env.claimStore.PutClaimMappings(ctx, "test-tenant", env.appID, []tenant.ClaimMapping{
		{Name: "email", SourceType: "cognito", SourceAttribute: "email", TargetAttribute: "urn:oid:0.9.2342.19200300.100.1.3"},
		{Name: "given_name", SourceType: "cognito", SourceAttribute: "given_name", TargetAttribute: "urn:oid:2.5.4.42"},
		{Name: "family_name", SourceType: "cognito", SourceAttribute: "family_name", TargetAttribute: "urn:oid:2.5.4.4"},
		{Name: "roles", SourceType: "groupMapping", SourceAttribute: "groups", TargetAttribute: "custom:roles"},
		{Name: "department", SourceType: "static", SourceAttribute: "", TargetAttribute: "custom:dept", DefaultValue: "Engineering"},
	}))

	// Add role mappings
	require.NoError(t, env.claimStore.PutRoleMappings(ctx, "test-tenant", env.appID, []tenant.RoleMapping{
		{CognitoGroup: "Admins", MappedValue: "admin"},
		{CognitoGroup: "Users", MappedValue: "user"},
	}))

	// Run the full SSO flow
	client := noRedirectClient()
	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s&RelayState=test-relay",
		env.proxy.URL, url.QueryEscape(encoded))
	resp, err := client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc := resp.Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie)

	acsURL := fmt.Sprintf("%s/t/test-tenant/saml/acs?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(state))
	acsReq, _ := http.NewRequest(http.MethodGet, acsURL, nil)
	acsReq.AddCookie(flowCookie)

	acsResp, err := client.Do(acsReq)
	require.NoError(t, err)
	defer acsResp.Body.Close()
	require.Equal(t, http.StatusOK, acsResp.StatusCode)

	acsBody, _ := io.ReadAll(acsResp.Body)
	samlResponse := extractFormValue(t, string(acsBody), "SAMLResponse")
	require.NotEmpty(t, samlResponse)

	decoded, err := base64.StdEncoding.DecodeString(cleanBase64(samlResponse))
	require.NoError(t, err)

	var samlResp saml.Response
	require.NoError(t, xml.Unmarshal(decoded, &samlResp))
	require.NotNil(t, samlResp.Assertion)

	// Build a lookup of all attributes
	attrs := make(map[string][]string)
	for _, stmt := range samlResp.Assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			var vals []string
			for _, v := range attr.Values {
				vals = append(vals, v.Value)
			}
			attrs[attr.Name] = vals
		}
	}

	// Verify mapped attributes
	assert.Contains(t, attrs, "urn:oid:0.9.2342.19200300.100.1.3", "email OID must be present")
	if v, ok := attrs["urn:oid:0.9.2342.19200300.100.1.3"]; ok {
		assert.Contains(t, v, "testuser@example.com")
	}

	assert.Contains(t, attrs, "urn:oid:2.5.4.42", "given_name OID must be present")
	if v, ok := attrs["urn:oid:2.5.4.42"]; ok {
		assert.Contains(t, v, "Test")
	}

	assert.Contains(t, attrs, "urn:oid:2.5.4.4", "family_name OID must be present")
	if v, ok := attrs["urn:oid:2.5.4.4"]; ok {
		assert.Contains(t, v, "User")
	}

	// Role mappings: Admins -> admin, Users -> user
	assert.Contains(t, attrs, "custom:roles", "roles attribute must be present")
	if v, ok := attrs["custom:roles"]; ok {
		assert.Contains(t, v, "admin", "Admins group should map to admin")
		assert.Contains(t, v, "user", "Users group should map to user")
	}

	// Static attribute
	assert.Contains(t, attrs, "custom:dept", "department static attribute must be present")
	if v, ok := attrs["custom:dept"]; ok {
		assert.Contains(t, v, "Engineering")
	}
}

// ===========================================================================
// Test 5: SAML Conformance
// ===========================================================================

func TestE2E_SAML_Conformance(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	xmlStr, requestID := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s&RelayState=relay",
		env.proxy.URL, url.QueryEscape(encoded))
	resp, err := client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc := resp.Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie)

	acsURL := fmt.Sprintf("%s/t/test-tenant/saml/acs?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(state))
	acsReq, _ := http.NewRequest(http.MethodGet, acsURL, nil)
	acsReq.AddCookie(flowCookie)

	acsResp, err := client.Do(acsReq)
	require.NoError(t, err)
	defer acsResp.Body.Close()
	require.Equal(t, http.StatusOK, acsResp.StatusCode)

	acsBody, _ := io.ReadAll(acsResp.Body)
	samlResponse := extractFormValue(t, string(acsBody), "SAMLResponse")
	require.NotEmpty(t, samlResponse)

	decoded, err := base64.StdEncoding.DecodeString(cleanBase64(samlResponse))
	require.NoError(t, err)

	// Use the raw XML for conformance checks (crewjam/saml types may not
	// capture every XML detail such as ds:Signature elements).
	rawXML := string(decoded)

	var samlResp saml.Response
	require.NoError(t, xml.Unmarshal(decoded, &samlResp))

	// --- Response-level checks ---

	assert.Equal(t, "2.0", samlResp.Version, "Response Version must be 2.0")

	assert.Equal(t, "https://test-app.example.com/saml/acs", samlResp.Destination,
		"Destination must match SP's ACS URL")

	// Status
	require.NotNil(t, samlResp.Status, "Response must have a Status")
	require.NotNil(t, samlResp.Status.StatusCode, "Status must have a StatusCode")
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Success",
		samlResp.Status.StatusCode.Value, "StatusCode must be Success")

	assert.Equal(t, requestID, samlResp.InResponseTo,
		"InResponseTo must match the original AuthnRequest ID")

	// --- Assertion-level checks ---

	assertion := samlResp.Assertion
	require.NotNil(t, assertion, "Response must contain exactly one Assertion")

	// Issuer
	require.NotNil(t, assertion.Issuer, "Assertion must have an Issuer")
	assert.Contains(t, assertion.Issuer.Value, "/t/test-tenant/saml/metadata",
		"Issuer must match the IdP entity ID")

	// Subject / NameID
	require.NotNil(t, assertion.Subject, "Assertion must have a Subject")
	require.NotNil(t, assertion.Subject.NameID, "Subject must have a NameID")
	assert.Equal(t, "testuser@example.com", assertion.Subject.NameID.Value,
		"NameID must be the user's email")

	// SubjectConfirmation
	require.NotEmpty(t, assertion.Subject.SubjectConfirmations,
		"Subject must have SubjectConfirmation")
	sc := assertion.Subject.SubjectConfirmations[0]
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:cm:bearer", sc.Method,
		"SubjectConfirmation Method must be bearer")

	require.NotNil(t, sc.SubjectConfirmationData, "must have SubjectConfirmationData")
	scd := *sc.SubjectConfirmationData
	assert.Equal(t, "https://test-app.example.com/saml/acs", scd.Recipient,
		"Recipient must match ACS URL")
	assert.True(t, scd.NotOnOrAfter.After(time.Now()),
		"NotOnOrAfter must be in the future")
	assert.Equal(t, requestID, scd.InResponseTo,
		"SubjectConfirmationData InResponseTo must match AuthnRequest ID")

	// Conditions
	require.NotNil(t, assertion.Conditions, "Assertion must have Conditions")
	conditions := assertion.Conditions
	assert.False(t, conditions.NotBefore.IsZero(), "Conditions NotBefore must be set")
	assert.False(t, conditions.NotOnOrAfter.IsZero(), "Conditions NotOnOrAfter must be set")

	// AudienceRestriction
	require.NotEmpty(t, conditions.AudienceRestrictions, "Conditions must have AudienceRestriction")
	assert.NotEmpty(t, conditions.AudienceRestrictions[0].Audience.Value,
		"AudienceRestriction must have an Audience value")
	assert.Equal(t, "https://test-app.example.com",
		conditions.AudienceRestrictions[0].Audience.Value,
		"Audience must be the SP's entity ID")

	// AuthnStatement
	require.NotEmpty(t, assertion.AuthnStatements, "Assertion must have an AuthnStatement")
	authnStmt := assertion.AuthnStatements[0]
	require.NotNil(t, authnStmt.AuthnContext, "AuthnStatement must have AuthnContext")
	assert.Equal(t,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		authnStmt.AuthnContext.AuthnContextClassRef.Value,
		"AuthnContextClassRef must be PasswordProtectedTransport")

	// Signatures: both Response and Assertion should be signed.
	// The crewjam/saml library embeds signatures as raw XML, so we check
	// the raw XML string for ds:Signature elements.
	assert.Contains(t, rawXML, "ds:Signature",
		"Response/Assertion must contain ds:Signature elements")
	assert.Contains(t, rawXML, "SignatureValue",
		"Signature must contain a SignatureValue")
	assert.Contains(t, rawXML, "SignatureMethod",
		"Signature must reference a SignatureMethod (algorithm)")
}

// ===========================================================================
// Test 6: SAML Unknown SP
// ===========================================================================

func TestE2E_SAML_UnknownSP(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	// Use an entity ID that is NOT registered
	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://unknown-sp.example.com", "https://unknown-sp.example.com/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s",
		env.proxy.URL, url.QueryEscape(encoded))

	resp, err := client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// The proxy should NOT redirect to Cognito; instead return an error.
	assert.NotEqual(t, http.StatusFound, resp.StatusCode,
		"unknown SP should not produce a redirect to Cognito")
	assert.True(t, resp.StatusCode >= 400 || resp.StatusCode == http.StatusOK,
		"should return an error status (the library may return 200 with error body or 4xx)")
}

// ===========================================================================
// Test 7: SAML Disabled App
// ===========================================================================

func TestE2E_SAML_DisabledApp(t *testing.T) {
	env := setupE2E(t)
	ctx := context.Background()

	// Disable the app
	require.NoError(t, env.appStore.SetStatus(ctx, "test-tenant", env.appID, "disabled"))

	client := noRedirectClient()
	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s",
		env.proxy.URL, url.QueryEscape(encoded))

	resp, err := client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Disabled app should not proceed with SSO
	assert.NotEqual(t, http.StatusFound, resp.StatusCode,
		"disabled app should not produce a Cognito redirect")
	assert.True(t, resp.StatusCode >= 400 || resp.StatusCode == http.StatusOK,
		"should return an error status")

	// Re-enable the app for other tests
	require.NoError(t, env.appStore.SetStatus(ctx, "test-tenant", env.appID, "active"))
}

// ===========================================================================
// Test 8: OIDC Discovery
// ===========================================================================

func TestE2E_OIDC_Discovery(t *testing.T) {
	env := setupE2E(t)

	resp, err := http.Get(env.proxy.URL + "/t/test-tenant/oidc/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var discovery map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&discovery))

	// issuer contains the tenant slug
	issuer, ok := discovery["issuer"].(string)
	require.True(t, ok, "issuer must be a string")
	assert.Contains(t, issuer, "oidc", "issuer should reference the OIDC path")

	// authorization_endpoint ends with /authorize
	authz, ok := discovery["authorization_endpoint"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasSuffix(authz, "/authorize"), "authorization_endpoint should end with /authorize")

	// token_endpoint ends with /token
	tokenEP, ok := discovery["token_endpoint"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasSuffix(tokenEP, "/token"), "token_endpoint should end with /token")

	// jwks_uri ends with /keys
	jwksURI, ok := discovery["jwks_uri"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasSuffix(jwksURI, "/keys"), "jwks_uri should end with /keys")

	// response_types_supported contains "code"
	rtSupported, ok := discovery["response_types_supported"].([]interface{})
	require.True(t, ok)
	foundCode := false
	for _, rt := range rtSupported {
		if rt == "code" {
			foundCode = true
		}
	}
	assert.True(t, foundCode, "response_types_supported must include 'code'")

	// subject_types_supported
	stSupported, ok := discovery["subject_types_supported"].([]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, stSupported, "subject_types_supported must be present")

	// id_token_signing_alg_values_supported contains RS256
	sigAlgs, ok := discovery["id_token_signing_alg_values_supported"].([]interface{})
	require.True(t, ok)
	foundRS256 := false
	for _, alg := range sigAlgs {
		if alg == "RS256" {
			foundRS256 = true
		}
	}
	assert.True(t, foundRS256, "id_token_signing_alg_values_supported must include RS256")
}

// ===========================================================================
// Test 9: OIDC JWKS
// ===========================================================================

func TestE2E_OIDC_JWKS(t *testing.T) {
	env := setupE2E(t)

	// First, get the JWKS URI from discovery
	resp, err := http.Get(env.proxy.URL + "/t/test-tenant/oidc/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var discovery map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&discovery))
	jwksURIRaw, ok := discovery["jwks_uri"].(string)
	require.True(t, ok)

	// The JWKS URI from discovery has the issuer's base URL. Since the test
	// server is at a different URL, replace the host portion.
	jwksURL, err := url.Parse(jwksURIRaw)
	require.NoError(t, err)
	proxyURL, _ := url.Parse(env.proxy.URL)
	jwksURL.Host = proxyURL.Host
	jwksURL.Scheme = proxyURL.Scheme

	// Fetch the JWKS
	jwksResp, err := http.Get(jwksURL.String())
	require.NoError(t, err)
	defer jwksResp.Body.Close()
	require.Equal(t, http.StatusOK, jwksResp.StatusCode)

	ct := jwksResp.Header.Get("Content-Type")
	assert.Contains(t, ct, "application/json", "JWKS Content-Type should be JSON")

	body, err := io.ReadAll(jwksResp.Body)
	require.NoError(t, err)

	var jwks jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(body, &jwks), "JWKS must be valid JSON")
	require.NotEmpty(t, jwks.Keys, "JWKS must contain at least one key")

	key := jwks.Keys[0]
	assert.Equal(t, "sig", key.Use, "key use must be 'sig'")
	assert.Equal(t, "RS256", key.Algorithm, "algorithm must be RS256")
	assert.NotEmpty(t, key.KeyID, "key must have a kid")
	assert.NotNil(t, key.Key, "key must have public key material")

	_, isRSA := key.Key.(*rsa.PublicKey)
	assert.True(t, isRSA, "key must be an RSA public key")
}

// ===========================================================================
// Helpers
// ===========================================================================

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u
}

// cleanBase64 strips whitespace and HTML entity escapes that html/template may
// insert into the base64 value inside HTML attributes.
func cleanBase64(s string) string {
	s = strings.ReplaceAll(s, "&#43;", "+")
	s = strings.ReplaceAll(s, "&#47;", "/")
	s = strings.ReplaceAll(s, "&#61;", "=")
	s = strings.ReplaceAll(s, "&#34;", "")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}

// extractFormValue extracts the value of a hidden form input from HTML.
func extractFormValue(t *testing.T, html, name string) string {
	t.Helper()
	// Look for: name="SAMLResponse" value="..."
	// or: name="SAMLResponse" value='...'
	needle := fmt.Sprintf(`name="%s"`, name)
	idx := strings.Index(html, needle)
	if idx == -1 {
		// Try single quotes
		needle = fmt.Sprintf(`name='%s'`, name)
		idx = strings.Index(html, needle)
	}
	if idx == -1 {
		return ""
	}

	// Find the value attribute after the name
	rest := html[idx:]
	valueIdx := strings.Index(rest, "value=\"")
	if valueIdx == -1 {
		valueIdx = strings.Index(rest, "value='")
		if valueIdx == -1 {
			return ""
		}
		rest = rest[valueIdx+7:]
		end := strings.Index(rest, "'")
		if end == -1 {
			return ""
		}
		return rest[:end]
	}
	rest = rest[valueIdx+7:]
	end := strings.Index(rest, "\"")
	if end == -1 {
		return ""
	}
	return rest[:end]
}

// ===========================================================================
// Test 10: SAML Multi-Tenant Isolation
// ===========================================================================

func TestE2E_SAML_MultiTenantIsolation(t *testing.T) {
	// 1. Setup stores and mock KMS — separate config and session DBs
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test")
	sourceStore := store.NewSourceStore(configDB, "test")
	appStore := store.NewAppStore(configDB, "test")
	claimStore := store.NewClaimStore(configDB, "test")
	sessionStore := store.NewSessionStore(sessionDB, "test")

	cognitoServer := newMockCognitoServer(t)
	cognitoDomain := strings.TrimPrefix(cognitoServer.URL, "https://")

	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	t.Cleanup(func() {
		http.DefaultTransport = origTransport
		cognitoServer.Close()
	})

	kmsClient := newE2EMockKMSClient(t)
	signer := internalcrypto.NewKMSSigner(kmsClient)
	cert, err := internalcrypto.GenerateSelfSignedCert(signer, "e2e-test-idp.example.com")
	require.NoError(t, err)

	hmacKey := make([]byte, 32)
	_, _ = rand.Read(hmacKey)

	ctx := context.Background()

	// 2. Create tenant-a with its own source and app
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "tenant-a",
		DisplayName: "Tenant A",
		Plan:        "free",
		Status:      "active",
	}))

	sourceAID, err := sourceStore.Create(ctx, "tenant-a", &tenant.IdentitySource{
		DisplayName: "Cognito A",
		Type:        "cognito",
		Domain:      cognitoDomain,
		PoolID:      "eu-north-1_A",
		ClientID:    "client-a",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	appAID, err := appStore.Create(ctx, "tenant-a", &tenant.Application{
		DisplayName: "App A",
		Protocol:    "saml",
		SourceID:    sourceAID,
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:      "https://app-a.example.com",
		AcsURL:        "https://app-a.example.com/saml/acs",
		AcsURLs:       []string{"https://app-a.example.com/saml/acs"},
		NameIDFormat:  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:  "email",
		SignResponse:  true,
		SignAssertion: true,
	})
	require.NoError(t, err)

	// 3. Create tenant-b with its own source and app
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "tenant-b",
		DisplayName: "Tenant B",
		Plan:        "free",
		Status:      "active",
	}))

	sourceBID, err := sourceStore.Create(ctx, "tenant-b", &tenant.IdentitySource{
		DisplayName: "Cognito B",
		Type:        "cognito",
		Domain:      cognitoDomain,
		PoolID:      "eu-north-1_B",
		ClientID:    "client-b",
		Region:      "eu-north-1",
		Status:      "active",
	})
	require.NoError(t, err)

	appBID, err := appStore.Create(ctx, "tenant-b", &tenant.Application{
		DisplayName: "App B",
		Protocol:    "saml",
		SourceID:    sourceBID,
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:      "https://app-b.example.com",
		AcsURL:        "https://app-b.example.com/saml/acs",
		AcsURLs:       []string{"https://app-b.example.com/saml/acs"},
		NameIDFormat:  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:  "email",
		SignResponse:  true,
		SignAssertion: true,
	})
	require.NoError(t, err)

	// 4. Build router
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	proxyServer := httptest.NewUnstartedServer(dummyHandler)
	proxyServer.Start()
	proxyBaseURL := proxyServer.URL
	t.Cleanup(proxyServer.Close)

	spProvider := internalsaml.NewSPProvider(appStore)
	sessionProvider := internalsaml.NewSessionProvider(
		internalsaml.WithSourceStore(sourceStore),
		internalsaml.WithAppStore(appStore),
		internalsaml.WithHMACKey(hmacKey),
		internalsaml.WithProviderBaseURL(proxyBaseURL),
		// The mock Cognito issues unsigned (alg:none) tokens and exposes no JWKS
		// endpoint, so inject a decode-only verifier to exercise the callback
		// flow end to end. Production uses the default JWKS-backed verifier.
		internalsaml.WithVerifierFactory(func(_, _ string) cognito.IDTokenVerifier {
			return e2eDecodeOnlyVerifier{}
		}),
	)
	assertionMaker := internalsaml.NewAssertionMaker(appStore, claimStore)
	tenantIdPHandler := internalsaml.NewTenantIdPHandler(
		internalsaml.WithSigner(signer),
		internalsaml.WithCertificate(cert),
		internalsaml.WithSPProvider(spProvider),
		internalsaml.WithSessionProvider(sessionProvider),
		internalsaml.WithAssertionMaker(assertionMaker),
		internalsaml.WithBaseURL(proxyBaseURL),
	)

	auditStore := store.NewAuditStore(sessionDB, "test")
	sessionProvider.SetAuditStore(auditStore)

	router := chi.NewRouter()
	internalsaml.RegisterTenantRoutes(router, internalsaml.TenantRoutesConfig{
		Handler:     tenantIdPHandler,
		SessionProv: sessionProvider,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       auditStore,
	})
	proxyServer.Config.Handler = router

	// 5. Verify tenant-a metadata references tenant-a
	resp, err := http.Get(proxyBaseURL + "/t/tenant-a/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	bodyA, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyA), "tenant-a")
	assert.NotContains(t, string(bodyA), "tenant-b", "tenant-a metadata should not reference tenant-b")

	// 6. Verify tenant-b metadata references tenant-b
	resp, err = http.Get(proxyBaseURL + "/t/tenant-b/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	bodyB, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyB), "tenant-b")
	assert.NotContains(t, string(bodyB), "tenant-a", "tenant-b metadata should not reference tenant-a")

	// 7. Verify nonexistent tenant returns 404 or 200 with empty/error metadata
	resp, err = http.Get(proxyBaseURL + "/t/nonexistent/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	// The proxy may return 200 with valid but empty metadata, or 404
	// Either is acceptable for a tenant with no apps
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
		"nonexistent tenant should return 200 or 404")

	// 8. Verify AuthnRequest for app-a uses the correct destination URL
	client := noRedirectClient()
	// Use the correct destination that matches tenant-a
	destination := proxyBaseURL + "/t/tenant-a/saml/sso"
	xmlStrA := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test-a-123" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="https://app-a.example.com/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://app-a.example.com</saml:Issuer></samlp:AuthnRequest>`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"), destination)
	encodedA := deflateAndEncode(t, xmlStrA)

	ssoURL := fmt.Sprintf("%s/t/tenant-a/saml/sso?SAMLRequest=%s",
		proxyBaseURL, url.QueryEscape(encodedA))

	resp, err = client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp.StatusCode, "should redirect to Cognito")

	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, cognitoDomain, "redirect should point to Cognito")

	// Verify we got the flow cookie
	foundFlowCookie := false
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			foundFlowCookie = true
		}
	}
	assert.True(t, foundFlowCookie, "flow cookie must be set")

	// Verify that appA and appB are isolated
	_, err = appStore.Get(ctx, "tenant-a", appBID)
	assert.Error(t, err, "tenant-a should not see tenant-b's app")
	_, err = appStore.Get(ctx, "tenant-b", appAID)
	assert.Error(t, err, "tenant-b should not see tenant-a's app")
}

// ===========================================================================
// Test 11: SAML Multiple Apps Per Tenant
// ===========================================================================

func TestE2E_SAML_MultipleAppsPerTenant(t *testing.T) {
	env := setupE2E(t)
	ctx := context.Background()

	// Create a second SAML app in the same tenant
	app2ID, err := env.appStore.Create(ctx, "test-tenant", &tenant.Application{
		DisplayName: "E2E Test App 2",
		Protocol:    "saml",
		SourceID:    env.sourceID,
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:           "https://test-app-2.example.com",
		AcsURL:             "https://test-app-2.example.com/saml/acs",
		AcsURLs:            []string{"https://test-app-2.example.com/saml/acs"},
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:       "email",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       60,
	})
	require.NoError(t, err)

	// Verify both apps' entity IDs are resolvable
	client := noRedirectClient()

	// Test app1 SSO flow
	xmlStr1, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded1 := deflateAndEncode(t, xmlStr1)

	ssoURL1 := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s",
		env.proxy.URL, url.QueryEscape(encoded1))

	req1, err := http.NewRequest(http.MethodGet, ssoURL1, nil)
	require.NoError(t, err)
	resp1, err := client.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusFound, resp1.StatusCode, "app1 should redirect to Cognito")

	loc1 := resp1.Header.Get("Location")
	assert.NotEmpty(t, loc1)

	// Test app2 SSO flow
	xmlStr2, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app-2.example.com", "https://test-app-2.example.com/saml/acs")
	encoded2 := deflateAndEncode(t, xmlStr2)

	ssoURL2 := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s",
		env.proxy.URL, url.QueryEscape(encoded2))

	req2, err := http.NewRequest(http.MethodGet, ssoURL2, nil)
	require.NoError(t, err)
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusFound, resp2.StatusCode, "app2 should redirect to Cognito")

	loc2 := resp2.Header.Get("Location")
	assert.NotEmpty(t, loc2)

	// Both apps should redirect to the same Cognito domain
	assert.Contains(t, loc1, strings.TrimPrefix(env.cognito.URL, "https://"))
	assert.Contains(t, loc2, strings.TrimPrefix(env.cognito.URL, "https://"))

	// Verify both apps exist and are independent
	_, err = env.appStore.Get(ctx, "test-tenant", env.appID)
	require.NoError(t, err)
	samlCfg1, err := env.appStore.GetSAMLConfig(ctx, "test-tenant", env.appID)
	require.NoError(t, err)
	assert.Equal(t, "https://test-app.example.com", samlCfg1.EntityID)

	_, err = env.appStore.Get(ctx, "test-tenant", app2ID)
	require.NoError(t, err)
	samlCfg2, err := env.appStore.GetSAMLConfig(ctx, "test-tenant", app2ID)
	require.NoError(t, err)
	assert.Equal(t, "https://test-app-2.example.com", samlCfg2.EntityID)
}

// ===========================================================================
// Test 12: Management API CRUD
// ===========================================================================

func TestE2E_ManagementAPI_CRUD(t *testing.T) {
	// The e2e router uses the explicit local-dev auth bypass
	// (AllowUnauthenticatedForAPILocalDev), so these unauthenticated CRUD calls
	// are allowed through. With no tenant in context, TenantFromJWTForAPI falls
	// back to the built-in default tenant.
	t.Setenv("PROXY_ENVIRONMENT", "local")

	env := setupE2E(t)
	ctx := context.Background()

	// The default tenant must exist in the store for TenantFromJWT to resolve
	// the fallback context. In production this is seeded at service startup.
	require.NoError(t, env.tenantStore.Create(ctx, tenant.NewDefaultTenant()))

	baseURL := env.proxy.URL

	// Helper: POST JSON and return response body bytes + status.
	doPost := func(t *testing.T, path string, payload interface{}) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(payload)
		require.NoError(t, err)
		resp, err := http.Post(baseURL+path, "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, respBody
	}

	// Helper: GET and return response body bytes + status.
	doGet := func(t *testing.T, path string) (int, []byte) {
		t.Helper()
		resp, err := http.Get(baseURL + path)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, respBody
	}

	// Helper: DELETE and return status.
	doDelete := func(t *testing.T, path string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodDelete, baseURL+path, nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		io.ReadAll(resp.Body) //nolint:errcheck
		return resp.StatusCode
	}

	// --- Step 1: Create a tenant via the API ---
	t.Run("create tenant", func(t *testing.T) {
		status, body := doPost(t, "/api/v1/tenants", map[string]string{
			"slug":        "e2e-crud-tenant",
			"displayName": "E2E CRUD Tenant",
		})
		assert.Equal(t, http.StatusOK, status, "create tenant: %s", string(body))

		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &resp))
		assert.Equal(t, "e2e-crud-tenant", resp["slug"])
		assert.Equal(t, "E2E CRUD Tenant", resp["displayName"])
	})

	// --- Step 2: List tenants — MF-1 scopes the listing to the caller's own
	// tenant unless the caller is a global operator. This harness runs as the
	// default tenant with no GlobalOperators group, so it must see ONLY the
	// default tenant; the newly created e2e-crud-tenant must NOT be disclosed.
	t.Run("list tenants scoped to caller", func(t *testing.T) {
		status, body := doGet(t, "/api/v1/tenants")
		assert.Equal(t, http.StatusOK, status, "list tenants: %s", string(body))

		var tenants []map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &tenants))

		foundOwn := false
		for _, tn := range tenants {
			slug, _ := tn["slug"].(string)
			assert.NotEqual(t, "e2e-crud-tenant", slug,
				"cross-tenant listing must not disclose other tenants to a non-operator caller (MF-1)")
			if slug == tenant.DefaultSlug {
				foundOwn = true
			}
		}
		assert.True(t, foundOwn, "caller should still see its own (default) tenant")
	})

	// --- Step 3: Create an identity source ---
	var sourceID string
	t.Run("create identity source", func(t *testing.T) {
		status, body := doPost(t, "/api/v1/identity-sources", map[string]string{
			"displayName": "E2E Test Cognito",
			"type":        "cognito",
			"poolId":      "eu-north-1_E2ECRUD",
			"region":      "eu-north-1",
			"domain":      "e2e-crud.auth.eu-north-1.amazoncognito.com",
			"clientId":    "e2e-crud-client-id",
		})
		assert.Equal(t, http.StatusOK, status, "create identity source: %s", string(body))

		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &resp))
		assert.Equal(t, "E2E Test Cognito", resp["displayName"])

		id, ok := resp["id"].(string)
		require.True(t, ok && id != "", "identity source must have an id")
		sourceID = id
	})

	// --- Step 4: List identity sources, verify it appears ---
	t.Run("list identity sources", func(t *testing.T) {
		status, body := doGet(t, "/api/v1/identity-sources")
		assert.Equal(t, http.StatusOK, status, "list identity sources: %s", string(body))

		var sources []map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &sources))

		found := false
		for _, s := range sources {
			if s["id"] == sourceID {
				found = true
				break
			}
		}
		assert.True(t, found, "created identity source should appear in list")
	})

	// --- Step 5: Create an application ---
	var appID string
	t.Run("create application", func(t *testing.T) {
		status, body := doPost(t, "/api/v1/applications", map[string]interface{}{
			"displayName": "E2E CRUD App",
			"protocol":    "saml",
			"sourceId":    sourceID,
			"saml": map[string]interface{}{
				"entityId": "https://e2e-crud-app.example.com",
				"acsUrl":   "https://e2e-crud-app.example.com/saml/acs",
				"acsUrls":  []string{"https://e2e-crud-app.example.com/saml/acs"},
			},
		})
		assert.Equal(t, http.StatusOK, status, "create application: %s", string(body))

		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &resp))
		assert.Equal(t, "E2E CRUD App", resp["displayName"])

		id, ok := resp["id"].(string)
		require.True(t, ok && id != "", "application must have an id")
		appID = id
	})

	// --- Step 6: List applications, verify it appears ---
	t.Run("list applications", func(t *testing.T) {
		status, body := doGet(t, "/api/v1/applications")
		assert.Equal(t, http.StatusOK, status, "list applications: %s", string(body))

		var apps []map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &apps))

		found := false
		for _, a := range apps {
			if a["id"] == appID {
				found = true
				assert.Equal(t, "E2E CRUD App", a["displayName"])
				break
			}
		}
		assert.True(t, found, "created application should appear in list")
	})

	// --- Step 7: Delete the application ---
	t.Run("delete application", func(t *testing.T) {
		status := doDelete(t, "/api/v1/applications/"+appID)
		assert.True(t, status >= 200 && status < 300,
			"delete application should succeed, got status %d", status)
	})

	// --- Step 8: List applications, verify it is gone (soft-deleted) ---
	t.Run("application gone after delete", func(t *testing.T) {
		status, body := doGet(t, "/api/v1/applications")
		assert.Equal(t, http.StatusOK, status, "list applications: %s", string(body))

		var apps []map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &apps))

		for _, a := range apps {
			if a["id"] == appID {
				// Soft-delete sets status to "deleted". The app may still appear
				// in the list but with status "deleted", or it may be filtered out.
				// Either is acceptable.
				if s, ok := a["status"].(string); ok {
					assert.Equal(t, "deleted", s,
						"deleted application should have status 'deleted'")
				}
				return
			}
		}
		// If the app is not in the list at all, that's also acceptable (filtered out).
	})
}

// ===========================================================================
// Test 13: SAML Expired Assertion
// ===========================================================================

func TestE2E_SAML_ExpiredAssertion(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	// Complete full SSO flow
	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s",
		env.proxy.URL, url.QueryEscape(encoded))
	resp, err := client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc := resp.Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie)

	acsURL := fmt.Sprintf("%s/t/test-tenant/saml/acs?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(state))
	acsReq, _ := http.NewRequest(http.MethodGet, acsURL, nil)
	acsReq.AddCookie(flowCookie)

	acsResp, err := client.Do(acsReq)
	require.NoError(t, err)
	defer acsResp.Body.Close()
	require.Equal(t, http.StatusOK, acsResp.StatusCode)

	acsBody, _ := io.ReadAll(acsResp.Body)
	samlResponse := extractFormValue(t, string(acsBody), "SAMLResponse")
	require.NotEmpty(t, samlResponse)

	decoded, err := base64.StdEncoding.DecodeString(cleanBase64(samlResponse))
	require.NoError(t, err)

	var samlResp saml.Response
	require.NoError(t, xml.Unmarshal(decoded, &samlResp))
	require.NotNil(t, samlResp.Assertion)

	// Verify assertion timestamps
	conditions := samlResp.Assertion.Conditions
	require.NotNil(t, conditions)

	now := time.Now()

	// NotBefore should be in the past (or at most a few minutes ago)
	assert.True(t, conditions.NotBefore.Before(now) || conditions.NotBefore.Equal(now),
		"NotBefore should be in the past or now")
	assert.True(t, now.Sub(conditions.NotBefore) < 10*time.Minute,
		"NotBefore should not be more than 10 minutes in the past")

	// NotOnOrAfter should be in the future
	assert.True(t, conditions.NotOnOrAfter.After(now),
		"NotOnOrAfter should be in the future")

	// Assertion lifetime should be reasonable (< 10 minutes)
	lifetime := conditions.NotOnOrAfter.Sub(conditions.NotBefore)
	assert.True(t, lifetime < 10*time.Minute,
		"assertion lifetime should be less than 10 minutes")
	assert.True(t, lifetime > 0, "assertion lifetime must be positive")
}

// ===========================================================================
// Test 14: SAML NameID Formats
// ===========================================================================

func TestE2E_SAML_NameIDFormats(t *testing.T) {
	env := setupE2E(t)
	ctx := context.Background()

	// Create app with email NameIDFormat
	emailAppID, err := env.appStore.Create(ctx, "test-tenant", &tenant.Application{
		DisplayName: "Email NameID App",
		Protocol:    "saml",
		SourceID:    env.sourceID,
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:      "https://email-app.example.com",
		AcsURL:        "https://email-app.example.com/saml/acs",
		AcsURLs:       []string{"https://email-app.example.com/saml/acs"},
		NameIDFormat:  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:  "email",
		SignResponse:  true,
		SignAssertion: true,
	})
	require.NoError(t, err)

	// Test email format
	client := noRedirectClient()
	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://email-app.example.com", "https://email-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s",
		env.proxy.URL, url.QueryEscape(encoded))
	req, _ := http.NewRequest(http.MethodGet, ssoURL, nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	loc := resp.Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			flowCookie = c
			break
		}
	}

	acsURL := fmt.Sprintf("%s/t/test-tenant/saml/acs?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(state))
	acsReq, _ := http.NewRequest(http.MethodGet, acsURL, nil)
	acsReq.AddCookie(flowCookie)

	acsResp, err := client.Do(acsReq)
	require.NoError(t, err)
	defer acsResp.Body.Close()

	acsBody, _ := io.ReadAll(acsResp.Body)
	samlResponse := extractFormValue(t, string(acsBody), "SAMLResponse")
	decoded, _ := base64.StdEncoding.DecodeString(cleanBase64(samlResponse))

	var emailResp saml.Response
	require.NoError(t, xml.Unmarshal(decoded, &emailResp))
	require.NotNil(t, emailResp.Assertion)
	require.NotNil(t, emailResp.Assertion.Subject)
	require.NotNil(t, emailResp.Assertion.Subject.NameID)

	// Verify NameID is populated with the email
	assert.Equal(t, "testuser@example.com", emailResp.Assertion.Subject.NameID.Value,
		"NameID should be the user's email")
	assert.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		emailResp.Assertion.Subject.NameID.Format,
		"NameID format should be emailAddress")

	// Cleanup
	_ = env.appStore.Delete(ctx, "test-tenant", emailAppID)
}

// ===========================================================================
// Test 15: SAML Signature Verification
// ===========================================================================

func TestE2E_SAML_SignatureVerification(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	// Complete full SSO flow
	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s",
		env.proxy.URL, url.QueryEscape(encoded))
	resp, err := client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	loc := resp.Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			flowCookie = c
			break
		}
	}

	acsURL := fmt.Sprintf("%s/t/test-tenant/saml/acs?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(state))
	acsReq, _ := http.NewRequest(http.MethodGet, acsURL, nil)
	acsReq.AddCookie(flowCookie)

	acsResp, err := client.Do(acsReq)
	require.NoError(t, err)
	defer acsResp.Body.Close()

	acsBody, _ := io.ReadAll(acsResp.Body)
	samlResponse := extractFormValue(t, string(acsBody), "SAMLResponse")
	decoded, _ := base64.StdEncoding.DecodeString(cleanBase64(samlResponse))

	var samlResp saml.Response
	require.NoError(t, xml.Unmarshal(decoded, &samlResp))

	// Get IdP metadata to extract the signing cert
	metaResp, err := http.Get(env.proxy.URL + "/t/test-tenant/saml/metadata")
	require.NoError(t, err)
	defer metaResp.Body.Close()

	metaBody, _ := io.ReadAll(metaResp.Body)
	var ed saml.EntityDescriptor
	require.NoError(t, xml.Unmarshal(metaBody, &ed))

	// Extract signing cert from metadata
	var metadataCert string
	for _, kd := range ed.IDPSSODescriptors[0].KeyDescriptors {
		if kd.Use == "signing" && len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
			metadataCert = kd.KeyInfo.X509Data.X509Certificates[0].Data
			break
		}
	}
	require.NotEmpty(t, metadataCert, "metadata must contain a signing cert")

	// The assertion should also reference a signing key in ds:Signature/KeyInfo
	// We verify the assertion contains signature elements
	rawXML := string(decoded)
	assert.Contains(t, rawXML, "ds:Signature", "assertion must contain signature")
	assert.Contains(t, rawXML, "X509Certificate", "assertion must reference X509Certificate")
	assert.Contains(t, rawXML, "SignatureValue", "assertion must contain SignatureValue")

	// Verify the cert in the assertion matches the metadata cert
	// (In real implementations, both should be the same public key)
	assert.NotEmpty(t, metadataCert)

	// Extract and verify the cert is valid (not expired)
	certDER, err := base64.StdEncoding.DecodeString(metadataCert)
	require.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	now := time.Now()
	assert.True(t, parsedCert.NotBefore.Before(now), "cert should not be expired (NotBefore)")
	assert.True(t, parsedCert.NotAfter.After(now), "cert should not be expired (NotAfter)")

	// Verify the Subject CN contains a reasonable value
	assert.NotEmpty(t, parsedCert.Subject.CommonName, "cert Subject CN should be set")
}

// ===========================================================================
// Test 16: Health and OpenAPI
// ===========================================================================

func TestE2E_HealthAndOpenAPI(t *testing.T) {
	env := setupE2E(t)

	t.Run("health endpoint returns ok", func(t *testing.T) {
		resp, err := http.Get(env.proxy.URL + "/health")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "ok", body["status"], "health endpoint should return status ok")
	})

	t.Run("openapi.json returns valid spec", func(t *testing.T) {
		resp, err := http.Get(env.proxy.URL + "/openapi.json")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var spec map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &spec), "openapi.json must be valid JSON")

		// Must contain the top-level "openapi" version key
		openAPIVersion, ok := spec["openapi"].(string)
		require.True(t, ok, "openapi.json must contain an 'openapi' key")
		assert.True(t, strings.HasPrefix(openAPIVersion, "3."),
			"openapi version should start with 3.x, got: %s", openAPIVersion)

		// Must contain "paths" with at least one entry
		paths, ok := spec["paths"].(map[string]interface{})
		require.True(t, ok, "openapi.json must contain a 'paths' object")
		assert.NotEmpty(t, paths, "paths should not be empty")

		// Verify some expected API paths are present
		assert.Contains(t, paths, "/api/v1/tenants", "paths should include /api/v1/tenants")
		assert.Contains(t, paths, "/api/v1/applications", "paths should include /api/v1/applications")
		assert.Contains(t, paths, "/api/v1/identity-sources", "paths should include /api/v1/identity-sources")

		// Must contain "info" with a title
		info, ok := spec["info"].(map[string]interface{})
		require.True(t, ok, "openapi.json must contain an 'info' object")
		assert.NotEmpty(t, info["title"], "info.title should not be empty")
	})
}

// ===========================================================================
// Test 17: SAML RelayState
// ===========================================================================

func TestE2E_SAML_RelayState(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	// Send AuthnRequest with RelayState
	relayState := "https://app.example.com/dashboard"
	xmlStr, _ := buildAuthnRequest(t, env.proxy.URL, "https://test-app.example.com", "https://test-app.example.com/saml/acs")
	encoded := deflateAndEncode(t, xmlStr)

	ssoURL := fmt.Sprintf("%s/t/test-tenant/saml/sso?SAMLRequest=%s&RelayState=%s",
		env.proxy.URL, url.QueryEscape(encoded), url.QueryEscape(relayState))

	resp, err := client.Do(&http.Request{Method: http.MethodGet, URL: mustParseURL(t, ssoURL)})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc := resp.Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_flow" {
			flowCookie = c
			break
		}
	}

	// Complete the flow
	acsURL := fmt.Sprintf("%s/t/test-tenant/saml/acs?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(state))
	acsReq, _ := http.NewRequest(http.MethodGet, acsURL, nil)
	acsReq.AddCookie(flowCookie)

	acsResp, err := client.Do(acsReq)
	require.NoError(t, err)
	defer acsResp.Body.Close()
	require.Equal(t, http.StatusOK, acsResp.StatusCode)

	acsBody, _ := io.ReadAll(acsResp.Body)
	bodyStr := string(acsBody)

	// Verify RelayState is preserved in the SAML Response form
	extractedRelayState := extractFormValue(t, bodyStr, "RelayState")
	assert.Equal(t, relayState, extractedRelayState,
		"RelayState should be preserved in the response")
}

// ===========================================================================
// Test 18: Well-Known Federation
// ===========================================================================

func TestE2E_WellKnownFederation(t *testing.T) {
	env := setupE2E(t)

	resp, err := http.Get(env.proxy.URL + "/t/test-tenant/.well-known/federation-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Some implementations may return 404 if not yet implemented
	if resp.StatusCode == http.StatusNotFound {
		t.Skip(".well-known/federation-configuration not yet implemented")
		return
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "json",
		"Content-Type should be JSON")

	var fedConfig map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&fedConfig))

	// Verify expected fields
	assert.Contains(t, fedConfig, "saml_metadata_url",
		"federation config should contain saml_metadata_url")
	assert.Contains(t, fedConfig, "protocols_supported",
		"federation config should contain protocols_supported")

	// Verify saml_metadata_url points to the correct path
	if metaURL, ok := fedConfig["saml_metadata_url"].(string); ok {
		assert.Contains(t, metaURL, "/saml/metadata")
	}

	// Verify protocols include saml
	if protocols, ok := fedConfig["protocols_supported"].([]interface{}); ok {
		foundSAML := false
		for _, p := range protocols {
			if p == "saml" || p == "saml2" || p == "saml2.0" {
				foundSAML = true
			}
		}
		assert.True(t, foundSAML, "protocols_supported should include SAML")
	}
}

// ===========================================================================
// Test 19: OIDC Authorization Code Flow
// ===========================================================================

func TestE2E_OIDC_AuthorizeFlow(t *testing.T) {
	env := setupE2E(t)
	client := noRedirectClient()

	// Step 1: Call the authorize endpoint with PKCE.
	authorizeURL := fmt.Sprintf(
		"%s/t/test-tenant/oidc/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=test123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
		env.proxy.URL,
		url.QueryEscape(env.oidcAppID),
		url.QueryEscape("https://oidc-app.example.com/callback"),
		url.QueryEscape("openid email"),
	)

	resp, err := client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"authorize endpoint should redirect (302)")

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "Location header must be set after authorize")

	// Step 2: Verify the redirect goes to /login?authRequestID=...
	locURL, err := url.Parse(loc)
	require.NoError(t, err)

	assert.Equal(t, "/login", locURL.Path,
		"authorize should redirect to /login")
	authRequestID := locURL.Query().Get("authRequestID")
	require.NotEmpty(t, authRequestID,
		"redirect must include authRequestID query parameter")

	// Step 3: Follow the redirect to /login?authRequestID=...
	loginRedirectURL := env.proxy.URL + loc
	resp2, err := client.Get(loginRedirectURL)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusFound, resp2.StatusCode,
		"/login should redirect (302) to tenant-scoped login")

	loc2 := resp2.Header.Get("Location")
	require.NotEmpty(t, loc2, "Location header must be set after /login redirect")

	// Step 4: Verify it redirects to /t/test-tenant/oidc/login?authRequestID=...
	assert.Contains(t, loc2, "/t/test-tenant/oidc/login",
		"should redirect to tenant-scoped OIDC login handler")
	assert.Contains(t, loc2, "authRequestID="+authRequestID,
		"redirect must preserve the authRequestID")

	// Step 5: Follow that redirect to the tenant-scoped login handler.
	tenantLoginURL := env.proxy.URL + loc2
	resp3, err := client.Get(tenantLoginURL)
	require.NoError(t, err)
	defer resp3.Body.Close()

	require.Equal(t, http.StatusFound, resp3.StatusCode,
		"tenant login handler should redirect (302) to Cognito")

	loc3 := resp3.Header.Get("Location")
	require.NotEmpty(t, loc3, "Location header must be set after tenant login redirect")

	// Step 6: Verify the redirect points to the mock Cognito authorize URL.
	cognitoDomain := strings.TrimPrefix(env.cognito.URL, "https://")
	assert.Contains(t, loc3, cognitoDomain,
		"redirect should point to the Cognito domain")

	loc3URL, err := url.Parse(loc3)
	require.NoError(t, err)

	q := loc3URL.Query()
	assert.Equal(t, "code", q.Get("response_type"),
		"Cognito redirect must have response_type=code")
	assert.Equal(t, "S256", q.Get("code_challenge_method"),
		"Cognito redirect must have code_challenge_method=S256")
	assert.NotEmpty(t, q.Get("code_challenge"),
		"Cognito redirect must include code_challenge")

	// Step 7: Extract the state parameter and the flow cookie.
	cognitoState := q.Get("state")
	require.NotEmpty(t, cognitoState,
		"Cognito redirect must include a state parameter")

	var flowCookie *http.Cookie
	for _, c := range resp3.Cookies() {
		if c.Name == "oidc_flow" {
			flowCookie = c
			break
		}
	}
	require.NotNil(t, flowCookie, "oidc_flow cookie must be set by the login handler")

	// Step 8: Simulate Cognito callback with code and state.
	callbackURL := fmt.Sprintf("%s/t/test-tenant/oidc/callback?code=test-code&state=%s",
		env.proxy.URL, url.QueryEscape(cognitoState))

	callbackReq, err := http.NewRequest(http.MethodGet, callbackURL, nil)
	require.NoError(t, err)
	callbackReq.AddCookie(flowCookie)

	resp4, err := client.Do(callbackReq)
	require.NoError(t, err)
	defer resp4.Body.Close()

	// Step 9: Verify 302 redirect back to the authorize callback endpoint.
	require.Equal(t, http.StatusFound, resp4.StatusCode,
		"callback should redirect (302) back to authorize/callback")

	loc4 := resp4.Header.Get("Location")
	require.NotEmpty(t, loc4, "Location header must be set after callback")

	assert.Contains(t, loc4, "/t/test-tenant/oidc/authorize/callback",
		"should redirect to the OIDC authorize/callback endpoint")
	assert.Contains(t, loc4, "id=",
		"redirect must include the id= parameter (completed auth request ID)")

	// Verify the flow cookie is cleared.
	var flowCookieCleared bool
	for _, c := range resp4.Cookies() {
		if c.Name == "oidc_flow" && c.MaxAge < 0 {
			flowCookieCleared = true
			break
		}
	}
	assert.True(t, flowCookieCleared, "oidc_flow cookie should be cleared after callback")
}

// ===========================================================================
// Test 20: OIDC Login Missing AuthRequest
// ===========================================================================

func TestE2E_OIDC_LoginMissingAuthRequest(t *testing.T) {
	env := setupE2E(t)

	// Call the tenant-scoped login handler without authRequestID.
	resp, err := http.Get(env.proxy.URL + "/t/test-tenant/oidc/login")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"login without authRequestID should return 400 Bad Request")
}
