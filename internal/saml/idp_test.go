package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	proxycrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed certificate and RSA key for testing.
func generateTestCert(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return key, cert
}

func TestNewIdentityProvider_Success(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	spProvider := NewSPProvider(appStore)

	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	cfg := IdPConfig{
		EntityID:    "https://idp.example.com/saml",
		BaseURL:     "https://idp.example.com",
		Signer:      signer,
		Certificate: cert,
		SPProvider:  spProvider,
		SessionProv: sessionProv,
		AssertMaker: assertMaker,
	}

	idp, err := NewIdentityProvider(cfg)
	require.NoError(t, err)
	require.NotNil(t, idp)

	assert.Equal(t, "/saml/metadata", idp.MetadataURL.Path)
	assert.Equal(t, "/saml/sso", idp.SSOURL.Path)
	assert.Equal(t, "/saml/slo", idp.LogoutURL.Path)
	assert.Equal(t, cert, idp.Certificate)
}

func TestNewIdentityProvider_InvalidBaseURL(t *testing.T) {
	signer, cert := generateTestCert(t)

	cfg := IdPConfig{
		EntityID:    "https://idp.example.com/saml",
		BaseURL:     "://invalid-url",
		Signer:      signer,
		Certificate: cert,
	}

	idp, err := NewIdentityProvider(cfg)
	assert.Error(t, err)
	assert.Nil(t, idp)
}

func TestMetadataEndpoint_ReturnsValidXML(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	spProvider := NewSPProvider(appStore)

	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	cfg := IdPConfig{
		EntityID:    "https://idp.example.com/saml",
		BaseURL:     "https://idp.example.com",
		Signer:      signer,
		Certificate: cert,
		SPProvider:  spProvider,
		SessionProv: sessionProv,
		AssertMaker: assertMaker,
	}

	idp, err := NewIdentityProvider(cfg)
	require.NoError(t, err)

	// Use httptest to serve the metadata endpoint.
	ts := httptest.NewServer(http.HandlerFunc(idp.ServeMetadata))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify it's valid XML and contains our entity.
	var ed crewsaml.EntityDescriptor
	err = xml.Unmarshal(body, &ed)
	require.NoError(t, err, "metadata should be valid EntityDescriptor XML")

	// The metadata URL was set to test server URL, so entityID comes from the IdP config.
	// crewjam/saml sets EntityID from MetadataURL by default.
	assert.NotEmpty(t, ed.EntityID)
	assert.NotEmpty(t, ed.IDPSSODescriptors, "should contain IDPSSODescriptor")
}

func TestRegisterRoutes(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")

	// Create an app so the provider has something.
	app := &tenant.Application{
		DisplayName: "Test SP",
		Protocol:    "saml",
		SourceID:    "source-1",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:     "https://sp.example.com/saml",
		AcsURL:       "https://sp.example.com/saml/acs",
		AcsURLs:      []string{"https://sp.example.com/saml/acs"},
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource: "email",
	}
	_, err := appStore.Create(context.Background(), "acme", app, samlCfg)
	require.NoError(t, err)

	spProvider := NewSPProvider(appStore)
	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	cfg := IdPConfig{
		EntityID:    "https://idp.example.com/saml",
		BaseURL:     "https://idp.example.com",
		Signer:      signer,
		Certificate: cert,
		SPProvider:  spProvider,
		SessionProv: sessionProv,
		AssertMaker: assertMaker,
	}

	idp, err := NewIdentityProvider(cfg)
	require.NoError(t, err)

	mux := http.NewServeMux()
	RegisterRoutes(mux, idp, sessionProv)

	// Verify the metadata endpoint is registered and responds.
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTenantIdPHandler_ServeMetadata_TenantScopedURL(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")

	spProvider := NewSPProvider(appStore)
	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	handler := NewTenantIdPHandler(
		WithSigner(signer),
		WithCertificate(cert),
		WithSPProvider(spProvider),
		WithSessionProvider(sessionProv),
		WithAssertionMaker(assertMaker),
		WithBaseURL("https://idp.example.com"),
	)

	// Set up a chi router with the tenant route.
	r := chi.NewRouter()
	r.Get("/t/{tenant}/saml/metadata", handler.ServeMetadata)

	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/t/acme/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var ed crewsaml.EntityDescriptor
	err = xml.Unmarshal(body, &ed)
	require.NoError(t, err, "metadata should be valid EntityDescriptor XML")

	// The entity ID should be the tenant-scoped metadata URL.
	assert.Contains(t, ed.EntityID, "/t/acme/saml/metadata")
	assert.NotEmpty(t, ed.IDPSSODescriptors, "should contain IDPSSODescriptor")

	// Verify SSO URL in the descriptor is also tenant-scoped.
	if len(ed.IDPSSODescriptors) > 0 {
		for _, sso := range ed.IDPSSODescriptors[0].SingleSignOnServices {
			assert.Contains(t, sso.Location, "/t/acme/saml/sso")
		}
	}
}

func TestRegisterTenantRoutes(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(ms, "test-table")
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	sessionStore := store.NewSessionStore(ms, "test-table")

	// Create the test tenant
	ctx := context.Background()
	err := tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "acme",
		DisplayName: "ACME Corp",
		Plan:        "free",
		Status:      "active",
	})
	require.NoError(t, err)

	spProvider := NewSPProvider(appStore)
	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	handler := NewTenantIdPHandler(
		WithSigner(signer),
		WithCertificate(cert),
		WithSPProvider(spProvider),
		WithSessionProvider(sessionProv),
		WithAssertionMaker(assertMaker),
		WithBaseURL("https://idp.example.com"),
	)

	auditStore := store.NewAuditStore(ms, "test-table")
	r := chi.NewRouter()
	RegisterTenantRoutes(r, TenantRoutesConfig{
		Handler:     handler,
		SessionProv: sessionProv,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       auditStore,
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Verify metadata endpoint is registered.
	resp, err := http.Get(ts.URL + "/t/acme/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify SLO endpoint is registered (returns 400 without SAMLRequest).
	sloResp, err := http.Get(ts.URL + "/t/acme/saml/slo")
	require.NoError(t, err)
	defer func() { _ = sloResp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, sloResp.StatusCode)
}

func TestAppMetadataEndpoint(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(ms, "test-table")
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	sessionStore := store.NewSessionStore(ms, "test-table")

	// Create the test tenant
	ctx := context.Background()
	err := tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "acme",
		DisplayName: "ACME Corp",
		Plan:        "free",
		Status:      "active",
	})
	require.NoError(t, err)

	// Create a test app with claim mappings
	appID, err := appStore.Create(ctx, "acme", &tenant.Application{
		DisplayName: "Test App",
		Protocol:    "saml",
		SourceID:    "source-1",
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:     "https://sp.example.com",
		AcsURL:       "https://sp.example.com/acs",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	})
	require.NoError(t, err)

	// Add claim mappings
	err = claimStore.PutClaimMappings(ctx, "acme", appID, []tenant.ClaimMapping{
		{
			Name:            "email",
			SourceType:      "cognito",
			SourceAttribute: "email",
			TargetAttribute: "urn:oid:0.9.2342.19200300.100.1.3",
			Required:        true,
		},
		{
			Name:            "givenName",
			SourceType:      "cognito",
			SourceAttribute: "given_name",
			TargetAttribute: "urn:oid:2.5.4.42",
			Required:        false,
		},
	})
	require.NoError(t, err)

	spProvider := NewSPProvider(appStore)
	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	handler := NewTenantIdPHandler(
		WithSigner(signer),
		WithCertificate(cert),
		WithSPProvider(spProvider),
		WithSessionProvider(sessionProv),
		WithAssertionMaker(assertMaker),
		WithBaseURL("https://idp.example.com"),
	)

	auditStore := store.NewAuditStore(ms, "test-table")
	r := chi.NewRouter()
	RegisterTenantRoutes(r, TenantRoutesConfig{
		Handler:     handler,
		SessionProv: sessionProv,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       auditStore,
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Fetch app-specific metadata
	resp, err := http.Get(ts.URL + "/t/acme/saml/metadata/" + appID)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/samlmetadata+xml", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	metadata := string(body)

	// Verify it includes the NameIDFormat
	assert.Contains(t, metadata, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

	// Verify it includes attribute elements
	assert.Contains(t, metadata, `<saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"`)
	assert.Contains(t, metadata, `<saml:Attribute Name="urn:oid:2.5.4.42"`)

	// Verify it still has standard IdP metadata elements
	assert.Contains(t, metadata, "IDPSSODescriptor")
	assert.Contains(t, metadata, "/t/acme/saml/sso")
}

// TestHandleLoginComplete_ErrorDoesNotLeakInternalError asserts that when the
// session-establish endpoint fails (here a protocol mismatch inside
// CompleteCustomLogin, which returns the internal string "login flow protocol
// mismatch"), the unauthenticated caller receives a stable generic message and
// a correlation id — never the internal error text.
func TestHandleLoginComplete_ErrorDoesNotLeakInternalError(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	tenantStore := store.NewTenantStore(ms, "test-table")
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	sourceStore := store.NewSourceStore(ms, "test-table")
	pending := store.NewPendingLoginStore(ms, "test-table")

	ctx := context.Background()
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug: "acme", DisplayName: "ACME", Plan: "free", Status: "active",
	}))

	// A pending login recorded under a NON-saml protocol makes CompleteCustomLogin
	// fail with "login flow protocol mismatch" — a distinctive internal string
	// that must not reach the client.
	require.NoError(t, pending.Create(ctx, &store.PendingLogin{
		FlowID: "flow-x", Protocol: "oidc", TenantSlug: "acme", SourceID: "src",
	}, time.Minute))

	spProvider := NewSPProvider(appStore)
	sessionProv := NewSessionProvider(
		WithSourceStore(sourceStore),
		WithAppStore(appStore),
		WithHMACKey([]byte("test-hmac-key-for-unit-tests-32b")),
		WithProviderBaseURL("https://idp.example.com"),
	)
	sessionProv.SetPendingLoginStore(pending)
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
	r.Post("/t/{tenant}/saml/login/complete", handler.HandleLoginComplete)

	form := url.Values{}
	form.Set("id_token", "the.id.token")
	form.Set("state", "flow-x")
	req := httptest.NewRequest(http.MethodPost, "/t/acme/saml/login/complete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	body := w.Body.String()
	// Generic, stable client message.
	assert.Contains(t, body, "invalid login request")
	// The internal error must NOT be echoed to the unauthenticated caller.
	assert.NotContains(t, body, "protocol mismatch")
	assert.NotContains(t, body, "login flow")
}

// generateTestCertWithSerial creates a self-signed certificate with the given
// serial number. This allows tests to generate distinct certificates.
func generateTestCertWithSerial(t *testing.T, serial int64) (crypto.Signer, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return key, cert
}

func TestServeMetadata_SingleCert_NoCertStore(t *testing.T) {
	signer, cert := generateTestCert(t)
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	spProvider := NewSPProvider(appStore)

	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
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
	r.Get("/t/{tenant}/saml/metadata", handler.ServeMetadata)

	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/t/acme/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var ed crewsaml.EntityDescriptor
	err = xml.Unmarshal(body, &ed)
	require.NoError(t, err)
	require.NotEmpty(t, ed.IDPSSODescriptors)

	// Without a cert store, only the active cert should be in the metadata.
	// crewjam/saml adds 2 KeyDescriptors: one for signing, one for encryption.
	kds := ed.IDPSSODescriptors[0].KeyDescriptors
	assert.Len(t, kds, 2, "should have exactly 2 KeyDescriptors (signing + encryption) without cert store")
}

func TestServeMetadata_ActiveOnly_NoCertStaged(t *testing.T) {
	signer, activeCert := generateTestCert(t)
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	spProvider := NewSPProvider(appStore)

	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	// Create a cert store with only the active cert.
	certStore := proxycrypto.NewCertStore(ms)
	err := certStore.StoreActiveCert(context.Background(), activeCert)
	require.NoError(t, err)

	handler := NewTenantIdPHandler(
		WithSigner(signer),
		WithCertificate(activeCert),
		WithCertStore(certStore),
		WithSPProvider(spProvider),
		WithSessionProvider(sessionProv),
		WithAssertionMaker(assertMaker),
		WithBaseURL("https://idp.example.com"),
	)

	r := chi.NewRouter()
	r.Get("/t/{tenant}/saml/metadata", handler.ServeMetadata)

	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/t/acme/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var ed crewsaml.EntityDescriptor
	err = xml.Unmarshal(body, &ed)
	require.NoError(t, err)
	require.NotEmpty(t, ed.IDPSSODescriptors)

	// With cert store containing only the active cert, no extra KeyDescriptors
	// should be appended beyond the 2 that crewjam/saml already creates.
	kds := ed.IDPSSODescriptors[0].KeyDescriptors
	assert.Len(t, kds, 2, "should have exactly 2 KeyDescriptors when only active cert is staged")
}

func TestServeMetadata_ActiveAndNextCerts(t *testing.T) {
	signer, activeCert := generateTestCertWithSerial(t, 1)
	_, nextCert := generateTestCertWithSerial(t, 2)
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	spProvider := NewSPProvider(appStore)

	auth := cognito.NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client-id", "https://idp.example.com/saml/acs", "", "")
	sessionProv := NewSessionProviderCompat(auth, []byte("test-hmac-key-32-bytes-long!!!!!"))
	assertMaker := NewAssertionMaker(appStore, claimStore)

	// Create a cert store with both active and next certs.
	certStore := proxycrypto.NewCertStore(ms)
	ctx := context.Background()
	err := certStore.StoreActiveCert(ctx, activeCert)
	require.NoError(t, err)
	err = certStore.StoreNextCert(ctx, nextCert)
	require.NoError(t, err)

	handler := NewTenantIdPHandler(
		WithSigner(signer),
		WithCertificate(activeCert),
		WithCertStore(certStore),
		WithSPProvider(spProvider),
		WithSessionProvider(sessionProv),
		WithAssertionMaker(assertMaker),
		WithBaseURL("https://idp.example.com"),
	)

	r := chi.NewRouter()
	r.Get("/t/{tenant}/saml/metadata", handler.ServeMetadata)

	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/t/acme/saml/metadata")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var ed crewsaml.EntityDescriptor
	err = xml.Unmarshal(body, &ed)
	require.NoError(t, err)
	require.NotEmpty(t, ed.IDPSSODescriptors)

	// With both active and next certs, there should be 3 KeyDescriptors:
	// 2 from crewjam/saml (signing + encryption for active cert) plus 1
	// additional signing KeyDescriptor for the next cert.
	kds := ed.IDPSSODescriptors[0].KeyDescriptors
	assert.Len(t, kds, 3, "should have 3 KeyDescriptors (signing + encryption + next signing)")

	// Verify the third KeyDescriptor is a signing descriptor with the next cert.
	nextKD := kds[2]
	assert.Equal(t, "signing", nextKD.Use)
	require.NotEmpty(t, nextKD.KeyInfo.X509Data.X509Certificates)

	// The next cert's base64 data should differ from the active cert's.
	activeCertData := kds[0].KeyInfo.X509Data.X509Certificates[0].Data
	nextCertData := nextKD.KeyInfo.X509Data.X509Certificates[0].Data
	assert.NotEqual(t, activeCertData, nextCertData, "next cert data should differ from active cert")
}
