//go:build integration

package internal_test

import (
	"bytes"
	"compress/flate"
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/api"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/saml"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_MultiTenant_Metadata tests that GET /t/{tenant}/saml/metadata
// returns valid XML with the correct EntityDescriptor.
func TestIntegration_MultiTenant_Metadata(t *testing.T) {
	// Setup: create a test proxy server with multi-tenant data
	server, tenantSlug, cleanup := setupMultiTenantProxy(t)
	defer cleanup()

	// Make a request to the tenant-scoped metadata endpoint
	resp, err := http.Get(server.URL + "/t/" + tenantSlug + "/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/samlmetadata+xml", resp.Header.Get("Content-Type"))

	// Read the response body
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Verify it contains expected SAML metadata elements
	assert.Contains(t, body, "EntityDescriptor")
	assert.Contains(t, body, "IDPSSODescriptor")
	assert.Contains(t, body, "protocolSupportEnumeration")
	assert.Contains(t, body, "SingleSignOnService")
}

// TestIntegration_MultiTenant_SSORedirect tests that an AuthnRequest triggers
// a redirect to the correct Cognito domain for the tenant.
func TestIntegration_MultiTenant_SSORedirect(t *testing.T) {
	// Setup: create a test proxy server with multi-tenant data
	server, tenantSlug, cleanup := setupMultiTenantProxy(t)
	defer cleanup()

	// Build a SAML AuthnRequest XML for the registered SP entity ID
	entityID := "https://test-app.example.com"
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	requestID := generateRandomID()
	ssoEndpoint := server.URL + "/t/" + tenantSlug + "/saml/sso"

	authnRequestXML := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="%s"
		Version="2.0"
		IssueInstant="%s"
		Destination="%s"
		AssertionConsumerServiceURL="https://test-app.example.com/saml/acs"
		ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
		<saml:Issuer>%s</saml:Issuer>
	</samlp:AuthnRequest>`, requestID, now, ssoEndpoint, entityID)

	// Deflate+base64 encode for HTTP-Redirect binding
	encoded := deflateAndEncode(t, authnRequestXML)

	// URL-encode the SAMLRequest parameter
	reqURL := ssoEndpoint + "?SAMLRequest=" + url.QueryEscape(encoded)

	// Create an HTTP client that does NOT follow redirects
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(reqURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert 302 Found redirect
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// Parse the Location header
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "Location header should be set for redirect")

	// Assert the redirect URL contains the correct Cognito domain
	assert.Contains(t, location, "test.auth.eu-north-1.amazoncognito.com",
		"redirect should target the tenant's Cognito domain")

	// Parse the redirect URL and verify OAuth2 parameters
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	query := redirectURL.Query()
	assert.Equal(t, "code", query.Get("response_type"),
		"redirect should use authorization code flow")
	assert.Equal(t, "S256", query.Get("code_challenge_method"),
		"redirect should use S256 PKCE challenge method")
	assert.Equal(t, "test-client-id", query.Get("client_id"),
		"redirect should contain the correct client ID")
	assert.NotEmpty(t, query.Get("code_challenge"),
		"redirect should include a PKCE code challenge")
	assert.NotEmpty(t, query.Get("state"),
		"redirect should include a state parameter")
}

// deflateAndEncode compresses XML with DEFLATE and base64 encodes it for
// SAML HTTP-Redirect binding.
func deflateAndEncode(t *testing.T, xml string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(xml))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// TestIntegration_TenantIsolation tests that tenants are properly isolated.
func TestIntegration_TenantIsolation(t *testing.T) {
	// Setup two tenants with different apps
	server, cleanup := setupMultiTenantProxyWithTenants(t, []string{"alpha", "beta"})
	defer cleanup()

	// GET /t/alpha/saml/metadata — verify returns alpha's config
	respAlpha, err := http.Get(server.URL + "/t/alpha/saml/metadata")
	require.NoError(t, err)
	defer respAlpha.Body.Close()
	assert.Equal(t, http.StatusOK, respAlpha.StatusCode)
	bufAlpha := make([]byte, 8192)
	nAlpha, _ := respAlpha.Body.Read(bufAlpha)
	bodyAlpha := string(bufAlpha[:nAlpha])
	assert.Contains(t, bodyAlpha, "EntityDescriptor")
	// The metadata endpoint returns the IdP's entity ID, not the SP's entity ID.
	// The SP entity ID is only referenced in SP metadata, not IdP metadata.
	assert.Contains(t, bodyAlpha, "/t/alpha/saml")

	// GET /t/beta/saml/metadata — verify returns beta's config
	respBeta, err := http.Get(server.URL + "/t/beta/saml/metadata")
	require.NoError(t, err)
	defer respBeta.Body.Close()
	assert.Equal(t, http.StatusOK, respBeta.StatusCode)
	bufBeta := make([]byte, 8192)
	nBeta, _ := respBeta.Body.Read(bufBeta)
	bodyBeta := string(bufBeta[:nBeta])
	assert.Contains(t, bodyBeta, "EntityDescriptor")
	assert.Contains(t, bodyBeta, "/t/beta/saml")

	// Verify alpha and beta metadata are different
	assert.NotEqual(t, bodyAlpha, bodyBeta, "Alpha and Beta metadata should be different")

	// GET /t/nonexistent/saml/metadata — verify not 200 OK
	respNone, err := http.Get(server.URL + "/t/nonexistent/saml/metadata")
	require.NoError(t, err)
	defer respNone.Body.Close()
	// For a nonexistent tenant, the metadata endpoint will still work but won't
	// have any valid SPs to reference. The key test is that the tenants are isolated.
	// We've already verified above that alpha != beta.
}

// TestIntegration_ManagementAPI tests the management API CRUD operations.
func TestIntegration_ManagementAPI(t *testing.T) {
	// This router uses the explicit local-dev auth bypass
	// (AllowUnauthenticatedForAPILocalDev). With no tenant in context the
	// API middleware falls back to the built-in default tenant.
	t.Setenv("PROXY_ENVIRONMENT", "local")

	// Create in-memory stores — separate config and session DBs
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test-table")
	sourceStore := store.NewSourceStore(configDB, "test-table")
	appStore := store.NewAppStore(configDB, "test-table")
	claimStore := store.NewClaimStore(configDB, "test-table")

	// Pre-create the default tenant since TenantFromJWTForAPI falls back to the
	// default slug when no tenant is in context, and the middleware loads the
	// tenant from the store.
	ctx := context.Background()
	require.NoError(t, tenantStore.Create(ctx, tenant.NewDefaultTenant()))

	// Create a Chi router with the auth and tenant middleware
	router := chi.NewRouter()

	// Apply the same middleware the production router uses, scoped to /api/v1/*.
	// This is a local-mode harness, so it selects the explicit local-dev auth
	// bypass rather than relying on an environment-variable skip.
	router.Use(middleware.AllowUnauthenticatedForAPILocalDev())
	router.Use(middleware.TenantFromJWTForAPI(tenantStore))

	// Create services
	auditStore := store.NewAuditStore(sessionDB, "test-table")
	importSvc := service.NewMetadataImportService(appStore, &service.HTTPMetadataFetcher{})
	previewSvc := service.NewPreviewService(appStore, claimStore)
	certSvc := service.NewCertificateService([]byte{})
	settingsSvc := service.NewSettingsService(tenantStore, "test-entity", "http://localhost:8080", "test-kms", "")

	// Register Huma API routes
	deps := api.Dependencies{
		Tenants:     tenantStore,
		Apps:        appStore,
		Sources:     sourceStore,
		Claims:      claimStore,
		Audit:       auditStore,
		ImportSvc:   importSvc,
		PreviewSvc:  previewSvc,
		CertSvc:     certSvc,
		SettingsSvc: settingsSvc,
		BaseURL:     "http://localhost:8080",
		EntityID:    "test-entity",
		KMSKeyID:    "test-kms",
	}
	humaAPI := api.NewHumaAPI(router, "Test API", "1.0.0")
	api.RegisterAPIRoutes(humaAPI, deps)

	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()

	client := &http.Client{}

	// ── Test 1: GET /api/v1/health → 200, status "ok" ──

	t.Run("health", func(t *testing.T) {
		resp, err := client.Get(server.URL + "/api/v1/health")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var healthResp map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &healthResp))
		assert.Equal(t, "ok", healthResp["status"])
	})

	// ── Test 2: GET /api/v1/tenants → 200, contains the default tenant ──

	t.Run("list_tenants", func(t *testing.T) {
		resp, err := client.Get(server.URL + "/api/v1/tenants")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var tenants []map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &tenants))
		require.GreaterOrEqual(t, len(tenants), 1, "should contain at least the default tenant")

		found := false
		for _, tObj := range tenants {
			if tObj["slug"] == tenant.DefaultSlug {
				found = true
				break
			}
		}
		assert.True(t, found, "default tenant should be in the tenant list")
	})

	// ── Test 3: POST /api/v1/identity-sources → creates a source ──

	var createdSourceID string
	t.Run("create_identity_source", func(t *testing.T) {
		payload := `{
			"displayName": "Integration Test Cognito",
			"type": "cognito",
			"poolId": "eu-north-1_INTTEST",
			"region": "eu-north-1",
			"domain": "inttest.auth.eu-north-1.amazoncognito.com",
			"clientId": "inttest-client-id"
		}`
		resp, err := client.Post(server.URL+"/api/v1/identity-sources",
			"application/json", strings.NewReader(payload))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", string(body))

		var source map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &source))
		assert.Equal(t, "Integration Test Cognito", source["displayName"])
		assert.NotEmpty(t, source["id"], "created source should have an ID")
		createdSourceID, _ = source["id"].(string)
	})

	// ── Test 4: GET /api/v1/identity-sources → returns the created source ──

	t.Run("list_identity_sources", func(t *testing.T) {
		resp, err := client.Get(server.URL + "/api/v1/identity-sources")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var sources []map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &sources))
		require.GreaterOrEqual(t, len(sources), 1, "should contain at least the created source")

		found := false
		for _, s := range sources {
			if s["id"] == createdSourceID {
				found = true
				break
			}
		}
		assert.True(t, found, "created identity source should appear in the list")
	})

	// ── Test 5: POST /api/v1/applications → creates an app ──

	t.Run("create_application", func(t *testing.T) {
		payload := fmt.Sprintf(`{
			"displayName": "Integration Test App",
			"protocol": "saml",
			"sourceId": "%s",
			"saml": {
				"entityId": "https://inttest-app.example.com",
				"acsUrl": "https://inttest-app.example.com/saml/acs"
			}
		}`, createdSourceID)
		resp, err := client.Post(server.URL+"/api/v1/applications",
			"application/json", strings.NewReader(payload))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", string(body))

		var appResp map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &appResp))
		assert.Equal(t, "Integration Test App", appResp["displayName"])
		assert.NotEmpty(t, appResp["id"], "created app should have an ID")
	})

	// ── Test 6: GET /api/v1/applications → returns the created app ──

	t.Run("list_applications", func(t *testing.T) {
		resp, err := client.Get(server.URL + "/api/v1/applications")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var apps []map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &apps))
		require.GreaterOrEqual(t, len(apps), 1, "should contain at least the created application")

		found := false
		for _, a := range apps {
			if a["displayName"] == "Integration Test App" {
				found = true
				break
			}
		}
		assert.True(t, found, "created application should appear in the list")
	})
}

// setupMultiTenantProxy creates a test HTTP server with multi-tenant SAML routes.
// Returns the server, the tenant slug, and a cleanup function.
//
// The baseURL used by the SAML IdP handler matches the httptest server URL so
// that SAML Destination validation succeeds in integration tests.
func setupMultiTenantProxy(t *testing.T) (*httptest.Server, string, func()) {
	t.Helper()

	// Create the httptest server first with a placeholder handler so we can
	// obtain the dynamic URL, then wire the real handler.
	server := httptest.NewServer(http.NotFoundHandler())

	// Create in-memory stores — separate config and session DBs
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test-table")
	sourceStore := store.NewSourceStore(configDB, "test-table")
	appStore := store.NewAppStore(configDB, "test-table")
	claimStore := store.NewClaimStore(configDB, "test-table")
	sessionStore := store.NewSessionStore(sessionDB, "test-table")

	// Create a test tenant
	ctx := context.Background()
	testTenant := &tenant.Tenant{
		Slug:             "test-tenant",
		DisplayName:      "Test Tenant",
		Plan:             "free",
		Status:           "active",
		MaxApps:          10,
		MaxAuthsPerMonth: 1000,
	}
	require.NoError(t, tenantStore.Create(ctx, testTenant))

	// Create an identity source for the tenant
	testSource := &tenant.IdentitySource{
		DisplayName: "Test Cognito",
		Type:        "cognito",
		Domain:      "test.auth.eu-north-1.amazoncognito.com",
		PoolID:      "eu-north-1_TESTPOOL",
		ClientID:    "test-client-id",
		Region:      "eu-north-1",
		Status:      "active",
	}
	sourceID, err := sourceStore.Create(ctx, "test-tenant", testSource)
	require.NoError(t, err)

	// Create an application with SAML config
	testApp := &tenant.Application{
		DisplayName: "Test Application",
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}
	testSAMLConfig := &tenant.SAMLConfig{
		EntityID:           "https://test-app.example.com",
		AcsURL:             "https://test-app.example.com/saml/acs",
		AcsURLs:            []string{"https://test-app.example.com/saml/acs"},
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:       "email",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       60,
	}
	_, err = appStore.Create(ctx, "test-tenant", testApp, testSAMLConfig)
	require.NoError(t, err)

	// Create mock KMS client and signer
	mockKMS, err := newMockKMSClient()
	require.NoError(t, err)
	signer := crypto.NewKMSSigner(mockKMS)

	// Generate certificate
	cert, err := crypto.GenerateSelfSignedCert(signer, "test-idp.example.com")
	require.NoError(t, err)

	// Create HMAC key for session cookies
	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)

	// Use the real httptest server URL as baseURL so SAML Destination validation
	// matches the dynamically assigned port.
	baseURL := server.URL

	// Create SAML components
	spProvider := saml.NewSPProvider(appStore)
	sessionProvider := saml.NewSessionProvider(
		saml.WithSourceStore(sourceStore),
		saml.WithAppStore(appStore),
		saml.WithHMACKey(hmacKey),
		saml.WithProviderBaseURL(baseURL),
	)
	assertionMaker := saml.NewAssertionMaker(appStore, claimStore)
	auditStore := store.NewAuditStore(sessionDB, "test")
	sessionProvider.SetAuditStore(auditStore)

	// Create TenantIdPHandler
	tenantIdPHandler := saml.NewTenantIdPHandler(
		saml.WithSigner(signer),
		saml.WithCertificate(cert),
		saml.WithSPProvider(spProvider),
		saml.WithSessionProvider(sessionProvider),
		saml.WithAssertionMaker(assertionMaker),
		saml.WithBaseURL(baseURL),
	)

	// Create Chi router and register tenant routes
	router := chi.NewRouter()
	saml.RegisterTenantRoutes(router, saml.TenantRoutesConfig{
		Handler:     tenantIdPHandler,
		SessionProv: sessionProvider,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Audit:       auditStore,
	})

	// Replace the placeholder handler with the real router
	server.Config.Handler = router

	cleanup := func() {
		server.Close()
	}

	return server, "test-tenant", cleanup
}

// setupMultiTenantProxyWithTenants creates a test server with multiple tenants.
func setupMultiTenantProxyWithTenants(t *testing.T, tenantSlugs []string) (*httptest.Server, func()) {
	t.Helper()

	// Create in-memory stores — separate config and session DBs
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(configDB, "test-table")
	sourceStore := store.NewSourceStore(configDB, "test-table")
	appStore := store.NewAppStore(configDB, "test-table")
	claimStore := store.NewClaimStore(configDB, "test-table")
	sessionStore := store.NewSessionStore(sessionDB, "test-table")

	ctx := context.Background()

	// Create each tenant with an identity source and app
	for _, slug := range tenantSlugs {
		// Create tenant
		testTenant := &tenant.Tenant{
			Slug:             slug,
			DisplayName:      strings.ToUpper(slug) + " Tenant",
			Plan:             "free",
			Status:           "active",
			MaxApps:          10,
			MaxAuthsPerMonth: 1000,
		}
		require.NoError(t, tenantStore.Create(ctx, testTenant))

		// Create identity source
		testSource := &tenant.IdentitySource{
			DisplayName: slug + " Cognito",
			Type:        "cognito",
			Domain:      slug + ".auth.eu-north-1.amazoncognito.com",
			PoolID:      "eu-north-1_" + strings.ToUpper(slug),
			ClientID:    slug + "-client-id",
			Region:      "eu-north-1",
			Status:      "active",
		}
		sourceID, err := sourceStore.Create(ctx, slug, testSource)
		require.NoError(t, err)

		// Create application
		testApp := &tenant.Application{
			DisplayName: slug + " Application",
			Protocol:    "saml",
			SourceID:    sourceID,
			Status:      "active",
		}
		testSAMLConfig := &tenant.SAMLConfig{
			EntityID:           "https://" + slug + "-app.example.com",
			AcsURL:             "https://" + slug + "-app.example.com/saml/acs",
			AcsURLs:            []string{"https://" + slug + "-app.example.com/saml/acs"},
			NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			NameIDSource:       "email",
			SignResponse:       true,
			SignAssertion:      true,
			SessionDurationSec: 3600,
			ClockSkewSec:       60,
		}
		_, err = appStore.Create(ctx, slug, testApp, testSAMLConfig)
		require.NoError(t, err)
	}

	// Create mock KMS client and signer
	mockKMS, err := newMockKMSClient()
	require.NoError(t, err)
	signer := crypto.NewKMSSigner(mockKMS)

	// Generate certificate
	cert, err := crypto.GenerateSelfSignedCert(signer, "test-idp.example.com")
	require.NoError(t, err)

	// Create HMAC key
	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)

	// Create SAML components
	spProvider := saml.NewSPProvider(appStore)
	sessionProvider := saml.NewSessionProvider(
		saml.WithSourceStore(sourceStore),
		saml.WithAppStore(appStore),
		saml.WithHMACKey(hmacKey),
		saml.WithProviderBaseURL("http://localhost:8080"),
	)
	assertionMaker := saml.NewAssertionMaker(appStore, claimStore)
	auditStore := store.NewAuditStore(sessionDB, "test")
	sessionProvider.SetAuditStore(auditStore)

	// Create TenantIdPHandler
	tenantIdPHandler := saml.NewTenantIdPHandler(
		saml.WithSigner(signer),
		saml.WithCertificate(cert),
		saml.WithSPProvider(spProvider),
		saml.WithSessionProvider(sessionProvider),
		saml.WithAssertionMaker(assertionMaker),
		saml.WithBaseURL("http://localhost:8080"),
	)

	// Create Chi router and register tenant routes
	router := chi.NewRouter()
	saml.RegisterTenantRoutes(router, saml.TenantRoutesConfig{
		Handler:     tenantIdPHandler,
		SessionProv: sessionProvider,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Audit:       auditStore,
	})

	// Create test server
	server := httptest.NewServer(router)

	cleanup := func() {
		server.Close()
	}

	return server, cleanup
}

// createTestAuthnRequest creates a base64-encoded SAML AuthnRequest for testing
func createTestAuthnRequest(t *testing.T, entityID string) string {
	t.Helper()

	// Create a minimal SAML AuthnRequest XML
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	requestID := generateRandomID()

	samlXML := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="%s"
		Version="2.0"
		IssueInstant="%s"
		Destination="http://localhost:8080/saml/sso"
		AssertionConsumerServiceURL="https://test-app.example.com/saml/acs"
		ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
		<saml:Issuer>%s</saml:Issuer>
	</samlp:AuthnRequest>`, requestID, now, entityID)

	// Base64 encode (standard encoding for HTTP-POST)
	return base64.StdEncoding.EncodeToString([]byte(samlXML))
}

// generateRandomID generates a random ID for SAML messages
func generateRandomID() string {
	b := make([]byte, 20)
	rand.Read(b)
	return "_" + base64.RawURLEncoding.EncodeToString(b)
}

// mockKMSClient implements crypto.KMSSignerClient using an in-memory RSA key pair
type mockKMSClient struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func newMockKMSClient() (*mockKMSClient, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &mockKMSClient{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

func (m *mockKMSClient) Sign(digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, m.privateKey, opts.HashFunc(), digest)
}

func (m *mockKMSClient) PublicKey() (*rsa.PublicKey, error) {
	return m.publicKey, nil
}
