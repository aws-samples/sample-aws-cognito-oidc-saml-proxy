//go:build integration

package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	internalcrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/oidc"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	zoidc "github.com/zitadel/oidc/v3/pkg/oidc"
)

// mockKMSClient implements crypto.KMSSignerClient for tests.
type mockKMSClient struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func newMockKMSClient(t *testing.T) *mockKMSClient {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &mockKMSClient{privateKey: pk, publicKey: &pk.PublicKey}
}

func (m *mockKMSClient) Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, m.privateKey, opts.HashFunc(), digest)
}

func (m *mockKMSClient) PublicKey() (*rsa.PublicKey, error) {
	return m.publicKey, nil
}

// setupTestServer creates a test HTTP server with OIDC routes configured.
func setupTestServer(t *testing.T) (*httptest.Server, *store.AppStore, *store.SourceStore) {
	t.Helper()

	// Create in-memory stores — separate config and session DBs
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	appStore := store.NewAppStore(configDB, "test")
	claimStore := store.NewClaimStore(configDB, "test")
	sourceStore := store.NewSourceStore(configDB, "test")

	// Create mock KMS signer
	mock := newMockKMSClient(t)
	joseSigner, err := internalcrypto.NewKMSJoseSigner("test-key-id", mock)
	require.NoError(t, err)

	// Create OIDC storage — uses session DB for auth requests/tokens
	storage := oidc.NewStorage(appStore, claimStore, sourceStore, joseSigner, sessionDB, "test-key-id")

	// HMAC key for login handler
	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)

	// MF-5: test uses a random per-test crypto key (no SM needed in integration tests)
	var cryptoKey [32]byte
	_, err = rand.Read(cryptoKey[:])
	require.NoError(t, err)

	// Create test router
	r := chi.NewRouter()

	// Register OIDC routes
	err = oidc.RegisterOIDCRoutes(r, storage, "http://localhost", appStore, sourceStore, nil, cryptoKey, hmacKey, nil, false)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)

	return server, appStore, sourceStore
}

// createTestTenantAndApp creates a test tenant, identity source, and OIDC application.
func createTestTenantAndApp(t *testing.T, appStore *store.AppStore, sourceStore *store.SourceStore, tenantSlug string) string {
	t.Helper()
	ctx := context.Background()

	// Create identity source
	source := &tenant.IdentitySource{
		DisplayName: "Test Identity Source",
		Type:        "cognito",
		PoolID:      "eu-north-1_test123",
		Region:      "eu-north-1",
		Domain:      "test.example.com",
		ClientID:    "test-client-id",
		Status:      "active",
	}
	sourceID, err := sourceStore.Create(ctx, tenantSlug, source)
	require.NoError(t, err)

	// Create OIDC application
	app := &tenant.Application{
		DisplayName: "Test OIDC App",
		Protocol:    "oidc",
		SourceID:    sourceID,
		Status:      "active",
	}
	appID, err := appStore.Create(ctx, tenantSlug, app, nil)
	require.NoError(t, err)

	// Add OIDC config
	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email", "profile"},
		TokenEndpointAuthMethod: "none",
		IDTokenLifetimeSec:      3600,
		AccessTokenLifetimeSec:  3600,
	}
	err = appStore.UpdateOIDCConfig(ctx, tenantSlug, appID, oidcCfg)
	require.NoError(t, err)

	return appID
}

func TestOIDC_Discovery(t *testing.T) {
	server, appStore, sourceStore := setupTestServer(t)
	tenantSlug := "test-tenant"
	createTestTenantAndApp(t, appStore, sourceStore, tenantSlug)

	// Fetch discovery document
	resp, err := http.Get(server.URL + "/t/" + tenantSlug + "/oidc/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse discovery document
	var discovery map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	require.NoError(t, err)

	// Verify required fields
	issuer, ok := discovery["issuer"].(string)
	require.True(t, ok, "issuer field must be present and be a string")
	assert.NotEmpty(t, issuer, "issuer must not be empty")

	authzEndpoint, ok := discovery["authorization_endpoint"].(string)
	require.True(t, ok, "authorization_endpoint field must be present")
	assert.NotEmpty(t, authzEndpoint)

	tokenEndpoint, ok := discovery["token_endpoint"].(string)
	require.True(t, ok, "token_endpoint field must be present")
	assert.NotEmpty(t, tokenEndpoint)

	jwksURI, ok := discovery["jwks_uri"].(string)
	require.True(t, ok, "jwks_uri field must be present")
	assert.NotEmpty(t, jwksURI)

	userinfoEndpoint, ok := discovery["userinfo_endpoint"].(string)
	require.True(t, ok, "userinfo_endpoint field must be present")
	assert.NotEmpty(t, userinfoEndpoint)

	// Verify response_types_supported includes "code"
	responseTypes, ok := discovery["response_types_supported"].([]interface{})
	require.True(t, ok, "response_types_supported must be an array")
	require.NotEmpty(t, responseTypes)
	found := false
	for _, rt := range responseTypes {
		if rt == "code" {
			found = true
			break
		}
	}
	assert.True(t, found, "response_types_supported must include 'code'")

	// Verify subject_types_supported
	subjectTypes, ok := discovery["subject_types_supported"].([]interface{})
	require.True(t, ok, "subject_types_supported must be an array")
	assert.NotEmpty(t, subjectTypes)

	// Verify id_token_signing_alg_values_supported includes RS256
	signingAlgs, ok := discovery["id_token_signing_alg_values_supported"].([]interface{})
	require.True(t, ok, "id_token_signing_alg_values_supported must be an array")
	require.NotEmpty(t, signingAlgs)
	found = false
	for _, alg := range signingAlgs {
		if alg == "RS256" {
			found = true
			break
		}
	}
	assert.True(t, found, "id_token_signing_alg_values_supported must include 'RS256'")

	// Verify scopes_supported includes openid
	scopes, ok := discovery["scopes_supported"].([]interface{})
	require.True(t, ok, "scopes_supported must be an array")
	require.NotEmpty(t, scopes)
	found = false
	for _, scope := range scopes {
		if scope == "openid" {
			found = true
			break
		}
	}
	assert.True(t, found, "scopes_supported must include 'openid'")

	// Verify grant_types_supported
	grantTypes, ok := discovery["grant_types_supported"].([]interface{})
	require.True(t, ok, "grant_types_supported must be an array")
	assert.NotEmpty(t, grantTypes)
}

func TestOIDC_JWKS(t *testing.T) {
	server, appStore, sourceStore := setupTestServer(t)
	tenantSlug := "test-tenant"
	createTestTenantAndApp(t, appStore, sourceStore, tenantSlug)

	// Fetch JWKS
	resp, err := http.Get(server.URL + "/t/" + tenantSlug + "/oidc/keys")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Content-Type might be "application/json" or include charset
	contentType := resp.Header.Get("Content-Type")
	assert.Contains(t, contentType, "application/json", "Response should be JSON")

	// Read entire response body first
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if err != nil || len(bodyBytes) == 0 {
		t.Logf("JWKS response body: %s", string(bodyBytes))
		t.Logf("Response status: %d", resp.StatusCode)
		t.Logf("Response headers: %v", resp.Header)
	}

	// Parse JWKS from the body bytes
	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(bodyBytes, &jwks)
	if err != nil {
		t.Logf("JWKS parse error: %v", err)
		t.Logf("Response body: %s", string(bodyBytes))
	}
	require.NoError(t, err)

	// Verify key set contains at least one key
	require.NotEmpty(t, jwks.Keys, "JWKS must contain at least one key")

	// Verify first key
	key := jwks.Keys[0]
	assert.Equal(t, "sig", key.Use, "key use must be 'sig'")
	assert.Equal(t, "RS256", key.Algorithm, "algorithm must be RS256")
	assert.NotEmpty(t, key.KeyID, "key ID must not be empty")

	// Verify key has required RSA components
	assert.NotNil(t, key.Key, "key must have a public key")

	// Try to parse as RSA public key
	_, ok := key.Key.(*rsa.PublicKey)
	assert.True(t, ok, "key must be parseable as RSA public key")
}

func TestOIDC_AuthorizationEndpoint(t *testing.T) {
	server, appStore, sourceStore := setupTestServer(t)
	tenantSlug := "test-tenant"
	clientID := createTestTenantAndApp(t, appStore, sourceStore, tenantSlug)

	// Create HTTP client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	tests := []struct {
		name        string
		params      url.Values
		expectError bool
		description string
	}{
		{
			name: "valid authorization request",
			params: url.Values{
				"client_id":     {clientID},
				"redirect_uri":  {"https://app.example.com/callback"},
				"scope":         {"openid email"},
				"response_type": {"code"},
				"state":         {"random-state-123"},
			},
			expectError: false,
			description: "Valid request should redirect to login page",
		},
		{
			name: "missing client_id",
			params: url.Values{
				"redirect_uri":  {"https://app.example.com/callback"},
				"scope":         {"openid"},
				"response_type": {"code"},
			},
			expectError: true,
			description: "Missing client_id should return error",
		},
		{
			name: "missing scope",
			params: url.Values{
				"client_id":     {clientID},
				"redirect_uri":  {"https://app.example.com/callback"},
				"response_type": {"code"},
			},
			expectError: true,
			description: "Missing scope should return error or redirect with error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := server.URL + "/t/" + tenantSlug + "/oidc/authorize?" + tt.params.Encode()
			resp, err := client.Get(authURL)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			// Authorization endpoint should either redirect or return error
			if !tt.expectError {
				// Should redirect (302 or 303)
				assert.True(t, resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther,
					"Expected redirect for valid request, got status %d", resp.StatusCode)
			} else {
				// Should return 4xx error or redirect with error parameter
				assert.True(t, resp.StatusCode >= 300 && resp.StatusCode < 500,
					"Expected error response, got status %d", resp.StatusCode)
			}
		})
	}
}

func TestOIDC_TokenEndpoint(t *testing.T) {
	server, appStore, sourceStore := setupTestServer(t)
	tenantSlug := "test-tenant"
	clientID := createTestTenantAndApp(t, appStore, sourceStore, tenantSlug)

	tests := []struct {
		name        string
		formData    url.Values
		description string
	}{
		{
			name: "missing grant_type",
			formData: url.Values{
				"client_id": {clientID},
				"code":      {"invalid-code"},
			},
			description: "Missing grant_type should return error",
		},
		{
			name: "invalid code",
			formData: url.Values{
				"grant_type":   {"authorization_code"},
				"client_id":    {clientID},
				"code":         {"invalid-code-12345"},
				"redirect_uri": {"https://app.example.com/callback"},
			},
			description: "Invalid code should return error",
		},
		{
			name: "missing redirect_uri",
			formData: url.Values{
				"grant_type": {"authorization_code"},
				"client_id":  {clientID},
				"code":       {"some-code"},
			},
			description: "Missing redirect_uri should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenURL := server.URL + "/t/" + tenantSlug + "/oidc/token"
			resp, err := http.PostForm(tokenURL, tt.formData)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			// Token endpoint should return 400 or 401 for invalid requests
			assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
				"%s - Expected 4xx error, got status %d", tt.description, resp.StatusCode)
		})
	}
}

func TestOIDC_UserInfoEndpoint(t *testing.T) {
	server, appStore, sourceStore := setupTestServer(t)
	tenantSlug := "test-tenant"
	createTestTenantAndApp(t, appStore, sourceStore, tenantSlug)

	// Test without Bearer token - should return 401
	userinfoURL := server.URL + "/t/" + tenantSlug + "/oidc/userinfo"
	resp, err := http.Get(userinfoURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Request without Bearer token should return 401")
}

// setupRefreshTestServer mirrors setupTestServer but also returns the shared
// Storage so a test can mint tokens directly (bypassing the interactive Cognito
// login) before exercising the token endpoint.
func setupRefreshTestServer(t *testing.T) (*httptest.Server, *store.AppStore, *store.SourceStore, *oidc.Storage) {
	t.Helper()

	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	appStore := store.NewAppStore(configDB, "test")
	claimStore := store.NewClaimStore(configDB, "test")
	sourceStore := store.NewSourceStore(configDB, "test")

	mock := newMockKMSClient(t)
	joseSigner, err := internalcrypto.NewKMSJoseSigner("test-key-id", mock)
	require.NoError(t, err)

	storage := oidc.NewStorage(appStore, claimStore, sourceStore, joseSigner, sessionDB, "test-key-id")

	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)

	// MF-5: random per-test crypto key (no SM needed in integration tests)
	var cryptoKey [32]byte
	_, err = rand.Read(cryptoKey[:])
	require.NoError(t, err)

	r := chi.NewRouter()
	require.NoError(t, oidc.RegisterOIDCRoutes(r, storage, "http://localhost", appStore, sourceStore, nil, cryptoKey, hmacKey, nil, false))

	server := httptest.NewServer(r)
	t.Cleanup(server.Close)

	return server, appStore, sourceStore, storage
}

// createRefreshCapableApp registers an OIDC app that holds the refresh_token
// grant and the offline_access scope, using a public (auth_method=none) client.
func createRefreshCapableApp(t *testing.T, appStore *store.AppStore, sourceStore *store.SourceStore, tenantSlug string) string {
	t.Helper()
	ctx := context.Background()

	source := &tenant.IdentitySource{
		DisplayName: "Test Identity Source",
		Type:        "cognito",
		PoolID:      "eu-north-1_test123",
		Region:      "eu-north-1",
		Domain:      "test.example.com",
		ClientID:    "test-client-id",
		Status:      "active",
	}
	sourceID, err := sourceStore.Create(ctx, tenantSlug, source)
	require.NoError(t, err)

	app := &tenant.Application{
		DisplayName: "Refresh OIDC App",
		Protocol:    "oidc",
		SourceID:    sourceID,
		Status:      "active",
	}
	appID, err := appStore.Create(ctx, tenantSlug, app, nil)
	require.NoError(t, err)

	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email", "profile", "offline_access"},
		TokenEndpointAuthMethod: "none",
		IDTokenLifetimeSec:      3600,
		AccessTokenLifetimeSec:  3600,
	}
	require.NoError(t, appStore.UpdateOIDCConfig(ctx, tenantSlug, appID, oidcCfg))
	return appID
}

// TestOIDC_RefreshTokenGrant exercises the full refresh_token grant end-to-end
// through the real zitadel/oidc token endpoint: mint an initial token pair,
// exchange the refresh token for a new pair, and confirm the old refresh token
// is rejected (single-use rotation).
func TestOIDC_RefreshTokenGrant(t *testing.T) {
	server, appStore, sourceStore, storage := setupRefreshTestServer(t)
	tenantSlug := "test-tenant"
	clientID := createRefreshCapableApp(t, appStore, sourceStore, tenantSlug)

	ctx := context.Background()

	// Mint an initial access+refresh pair by simulating a completed auth code
	// exchange directly against storage (the interactive Cognito login is out
	// of scope for this endpoint-level test).
	authReqIn := &zoidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       zoidc.SpaceDelimitedArray{"openid", "email", "profile", "offline_access"},
		ResponseType: zoidc.ResponseTypeCode,
	}
	created, err := storage.CreateAuthRequest(ctx, authReqIn, "")
	require.NoError(t, err)
	require.NoError(t, storage.CompleteAuthRequest(ctx, created.GetID(), "user@example.com",
		"user@example.com", "Ada", "Lovelace", true, []string{"engineers"}))
	completed, err := storage.AuthRequestByID(ctx, created.GetID())
	require.NoError(t, err)

	_, refreshToken, _, err := storage.CreateAccessAndRefreshTokens(ctx, completed, "")
	require.NoError(t, err)
	require.NotEmpty(t, refreshToken)

	// Resolve the token endpoint path from the discovery document. Its host is
	// the configured baseURL, so keep only the path and target the test server.
	discResp, err := http.Get(server.URL + "/t/" + tenantSlug + "/oidc/.well-known/openid-configuration")
	require.NoError(t, err)
	defer discResp.Body.Close()
	var disc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	require.NoError(t, json.NewDecoder(discResp.Body).Decode(&disc))
	require.NotEmpty(t, disc.TokenEndpoint, "discovery must advertise a token endpoint")
	tokenEndpointURL, err := url.Parse(disc.TokenEndpoint)
	require.NoError(t, err)
	tokenURL := server.URL + tokenEndpointURL.Path

	// Exchange the refresh token for a new pair.
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh grant should succeed: %s", string(body))

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(body, &tokenResp))
	assert.NotEmpty(t, tokenResp.AccessToken, "must return a new access token")
	assert.NotEmpty(t, tokenResp.IDToken, "must return a new ID token")
	assert.NotEmpty(t, tokenResp.RefreshToken, "must return a rotated refresh token")
	assert.NotEqual(t, refreshToken, tokenResp.RefreshToken, "refresh token must rotate")

	// The old refresh token must now be rejected (single-use rotation).
	resp2, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode, "reused refresh token must be rejected")

	// The rotated refresh token must work for another exchange.
	resp3, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResp.RefreshToken},
		"client_id":     {clientID},
	})
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusOK, resp3.StatusCode, "rotated refresh token must be usable")
}
