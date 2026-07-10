package cognito

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	proxycrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthClient(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "eu-north-1_abc123", "eu-north-1")

	assert.NotNil(t, client)
	assert.Equal(t, "test.auth.eu-north-1.amazoncognito.com", client.domain)
	assert.Equal(t, "client123", client.clientID)
	assert.Equal(t, "https://app.example.com/callback", client.redirectURI)
	assert.Equal(t, "eu-north-1_abc123", client.poolID)
	assert.Equal(t, "eu-north-1", client.region)
	assert.NotNil(t, client.httpClient)
}

func TestGeneratePKCE(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	verifier, challenge := client.GeneratePKCE()

	// Verifier should be 43 characters (32 bytes base64url encoded)
	assert.Len(t, verifier, 43)

	// Challenge should be different from verifier
	assert.NotEqual(t, verifier, challenge)

	// Challenge should also be 43 characters (SHA256 output is 32 bytes)
	assert.Len(t, challenge, 43)

	// Verify verifier is base64url (no padding, URL-safe)
	assert.NotContains(t, verifier, "=")
	assert.NotContains(t, verifier, "+")
	assert.NotContains(t, verifier, "/")

	// Verify challenge is base64url (no padding, URL-safe)
	assert.NotContains(t, challenge, "=")
	assert.NotContains(t, challenge, "+")
	assert.NotContains(t, challenge, "/")
}

func TestGeneratePKCE_Uniqueness(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	verifier1, challenge1 := client.GeneratePKCE()
	verifier2, challenge2 := client.GeneratePKCE()

	// Each invocation should produce unique values
	assert.NotEqual(t, verifier1, verifier2)
	assert.NotEqual(t, challenge1, challenge2)
}

func TestAuthorizationURL(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	state := "random-state-value"
	codeChallenge := "test-challenge"

	authURL := client.AuthorizationURL(state, codeChallenge)

	// Parse URL
	parsedURL, err := url.Parse(authURL)
	require.NoError(t, err)

	// Verify scheme and host
	assert.Equal(t, "https", parsedURL.Scheme)
	assert.Equal(t, "test.auth.eu-north-1.amazoncognito.com", parsedURL.Host)
	assert.Equal(t, "/oauth2/authorize", parsedURL.Path)

	// Verify query parameters
	query := parsedURL.Query()
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "client123", query.Get("client_id"))
	assert.Equal(t, "https://app.example.com/callback", query.Get("redirect_uri"))
	assert.Equal(t, "openid email profile", query.Get("scope"))
	assert.Equal(t, "random-state-value", query.Get("state"))
	assert.Equal(t, "test-challenge", query.Get("code_challenge"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
}

func TestExchangeCode(t *testing.T) {
	// Mock Cognito token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/oauth2/token", r.URL.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Parse body
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		assert.Equal(t, "test-code", r.Form.Get("code"))
		assert.Equal(t, "https://app.example.com/callback", r.Form.Get("redirect_uri"))
		assert.Equal(t, "client123", r.Form.Get("client_id"))
		assert.Equal(t, "test-verifier", r.Form.Get("code_verifier"))

		// Return token response
		response := map[string]interface{}{
			"id_token":      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			"access_token":  "access-token-value",
			"refresh_token": "refresh-token-value",
			"expires_in":    3600,
			"token_type":    "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Parse server URL to get domain
	serverURL, _ := url.Parse(server.URL)

	client := NewAuthClient(serverURL.Host, "client123", "https://app.example.com/callback", "", "")
	client.domain = serverURL.Host // Use mock server host

	// Override the token URL construction for testing
	ctx := context.Background()
	idToken, err := client.exchangeCodeWithURL(ctx, server.URL+"/oauth2/token", "test-code", "test-verifier")

	require.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", idToken)
}

func TestExchangeCode_Error(t *testing.T) {
	// Mock Cognito token endpoint with error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		response := map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)

	client := NewAuthClient(serverURL.Host, "client123", "https://app.example.com/callback", "", "")

	ctx := context.Background()
	_, err := client.exchangeCodeWithURL(ctx, server.URL+"/oauth2/token", "invalid-code", "test-verifier")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange failed")
}

// buildTestToken creates a JWT with the given payload for testing ParseIDToken.
func buildTestToken(payload map[string]interface{}) string {
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(payloadJSON) +
		".fake-signature"
}

func TestParseIDToken(t *testing.T) {
	// Use empty poolID/region so iss/aud validation is skipped for this basic test
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "", "https://app.example.com/callback", "", "")

	payload := map[string]interface{}{
		"sub":            "12345678-1234-1234-1234-123456789012",
		"email":          "user@example.com",
		"email_verified": true,
		"given_name":     "John",
		"family_name":    "Doe",
		"cognito:groups": []interface{}{"admin"},
		"iat":            1516239022,
		"exp":            time.Now().Add(1 * time.Hour).Unix(),
		"token_use":      "id",
	}

	token := buildTestToken(payload)

	parsedPayload, err := client.ParseIDToken(token)

	require.NoError(t, err)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", parsedPayload["sub"])
	assert.Equal(t, "user@example.com", parsedPayload["email"])
	assert.Equal(t, true, parsedPayload["email_verified"])
	assert.Equal(t, "John", parsedPayload["given_name"])
	assert.Equal(t, "Doe", parsedPayload["family_name"])

	// Groups should be an array
	groups, ok := parsedPayload["cognito:groups"].([]interface{})
	require.True(t, ok)
	assert.Len(t, groups, 1)
	assert.Equal(t, "admin", groups[0])
}

func TestParseIDToken_InvalidFormat(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"single part", "onlyonepart"},
		{"two parts", "header.payload"},
		{"four parts", "header.payload.signature.extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.ParseIDToken(tt.token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid JWT format")
		})
	}
}

func TestParseIDToken_InvalidBase64(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	// Invalid base64 in payload
	token := "header.invalid@base64.signature"

	_, err := client.ParseIDToken(token)
	assert.Error(t, err)
}

func TestParseIDToken_InvalidJSON(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	// Valid base64 but invalid JSON
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{invalid json"))
	token := "header." + invalidJSON + ".signature"

	_, err := client.ParseIDToken(token)
	assert.Error(t, err)
}

func TestParseIDToken_ExpiredToken(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	// Token expired 10 minutes ago (well past the 5 min clock skew)
	payload := map[string]interface{}{
		"sub":       "user-1",
		"exp":       time.Now().Add(-10 * time.Minute).Unix(),
		"token_use": "id",
	}

	token := buildTestToken(payload)
	_, err := client.ParseIDToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")
}

func TestParseIDToken_WithinClockSkew(t *testing.T) {
	// Token expired 3 minutes ago -- within 5 min clock skew, should be accepted
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "", "https://app.example.com/callback", "", "")

	payload := map[string]interface{}{
		"sub":       "user-1",
		"exp":       time.Now().Add(-3 * time.Minute).Unix(),
		"token_use": "id",
	}

	token := buildTestToken(payload)
	_, err := client.ParseIDToken(token)
	assert.NoError(t, err)
}

func TestParseIDToken_WrongIssuer(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "eu-north-1_pool123", "eu-north-1")

	payload := map[string]interface{}{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_wrongPool",
		"aud":       "client123",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"token_use": "id",
	}

	token := buildTestToken(payload)
	_, err := client.ParseIDToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestParseIDToken_CorrectIssuer(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "eu-north-1_pool123", "eu-north-1")

	payload := map[string]interface{}{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_pool123",
		"aud":       "client123",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"token_use": "id",
	}

	token := buildTestToken(payload)
	_, err := client.ParseIDToken(token)
	assert.NoError(t, err)
}

func TestParseIDToken_WrongAudience(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	payload := map[string]interface{}{
		"sub":       "user-1",
		"aud":       "wrong-client-id",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"token_use": "id",
	}

	token := buildTestToken(payload)
	_, err := client.ParseIDToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience")
}

func TestParseIDToken_WrongTokenUse(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "", "https://app.example.com/callback", "", "")

	payload := map[string]interface{}{
		"sub":       "user-1",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"token_use": "access",
	}

	token := buildTestToken(payload)
	_, err := client.ParseIDToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token_use")
}

func TestNewAuthClientForSource(t *testing.T) {
	source := &tenant.IdentitySource{
		ID:          "src-123",
		TenantSlug:  "acme",
		DisplayName: "Acme Cognito",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Domain:      "acme.auth.eu-north-1.amazoncognito.com",
		ClientID:    "acme-client-id",
		Status:      "active",
	}

	client, err := NewAuthClientForSource(context.Background(), source, "https://idp.example.com/t/acme/saml/acs", NoSecretFetcher)
	require.NoError(t, err)
	require.NotNil(t, client)

	assert.Equal(t, "acme.auth.eu-north-1.amazoncognito.com", client.domain)
	assert.Equal(t, "acme-client-id", client.clientID)
	assert.Equal(t, "https://idp.example.com/t/acme/saml/acs", client.redirectURI)
	assert.Equal(t, "eu-north-1_abc123", client.poolID)
	assert.Equal(t, "eu-north-1", client.region)
	assert.NotNil(t, client.httpClient)

	// Verify the authorization URL uses the correct domain and client ID.
	authURL := client.AuthorizationURL("test-state", "test-challenge")
	parsedURL, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, "acme.auth.eu-north-1.amazoncognito.com", parsedURL.Host)
	assert.Equal(t, "acme-client-id", parsedURL.Query().Get("client_id"))
	assert.Equal(t, "https://idp.example.com/t/acme/saml/acs", parsedURL.Query().Get("redirect_uri"))
}

func TestIntegration_PKCEFlow(t *testing.T) {
	client := NewAuthClient("test.auth.eu-north-1.amazoncognito.com", "client123", "https://app.example.com/callback", "", "")

	// Generate PKCE
	verifier, challenge := client.GeneratePKCE()

	// Generate authorization URL
	state := "test-state"
	authURL := client.AuthorizationURL(state, challenge)

	// Verify the URL contains all necessary components
	parsedURL, err := url.Parse(authURL)
	require.NoError(t, err)

	query := parsedURL.Query()
	assert.Equal(t, challenge, query.Get("code_challenge"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.Equal(t, state, query.Get("state"))

	// Verify verifier is available for later exchange
	assert.NotEmpty(t, verifier)
}

func TestNewAuthClientForSource_LegacyPublicClient_NoAuthHeader(t *testing.T) {
	// Legacy source with no RoleArn/SecretArn → public-client PKCE path.
	// The SecretFetcher must NOT be called; clientSecret must be empty.
	fetcherCalled := false
	fetcher := func(ctx context.Context, src *tenant.IdentitySource) (string, error) {
		fetcherCalled = true
		return "UNEXPECTED-SECRET", nil
	}

	src := &tenant.IdentitySource{
		PoolID:   "eu-north-1_abc123",
		Region:   "eu-north-1",
		Domain:   "auth.example.com",
		ClientID: "client-id-123",
		// no RoleArn / SecretArn
	}

	client, err := NewAuthClientForSource(context.Background(), src, "https://gateway.example.com/cb", fetcher)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.False(t, fetcherCalled, "legacy path must not call the fetcher")
	assert.Empty(t, client.clientSecret.Raw(), "legacy path must have empty clientSecret")
}

func TestNewAuthClientForSource_ConfidentialClient_CallsFetcher(t *testing.T) {
	fetcherCalled := 0
	fetcher := func(ctx context.Context, src *tenant.IdentitySource) (string, error) {
		fetcherCalled++
		return "the-confidential-secret", nil
	}

	src := &tenant.IdentitySource{
		PoolID:     "eu-north-1_abc123",
		Region:     "eu-north-1",
		Domain:     "auth.example.com",
		ClientID:   "client-id-123",
		RoleArn:    "arn:aws:iam::123456789012:role/identity-gateway-acme",
		ExternalID: "EXT-123",
		SecretArn:  "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
	}

	client, err := NewAuthClientForSource(context.Background(), src, "https://gateway.example.com/cb", fetcher)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Equal(t, 1, fetcherCalled)
	assert.Equal(t, "the-confidential-secret", client.clientSecret.Raw())
}

func TestNewAuthClientForSource_FetcherErrorPropagates(t *testing.T) {
	fetcher := func(ctx context.Context, src *tenant.IdentitySource) (string, error) {
		return "", assert.AnError
	}

	src := &tenant.IdentitySource{
		PoolID:     "eu-north-1_abc123",
		Region:     "eu-north-1",
		Domain:     "auth.example.com",
		ClientID:   "client-id-123",
		RoleArn:    "arn:aws:iam::123456789012:role/identity-gateway-acme",
		ExternalID: "EXT-123",
		SecretArn:  "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
	}

	_, err := NewAuthClientForSource(context.Background(), src, "https://gateway.example.com/cb", fetcher)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cognito: fetch client secret")
}

func TestExchangeCode_ConfidentialClient_SendsBasicAuthHeader(t *testing.T) {
	// Spin up a fake token endpoint that inspects the Authorization header.
	var gotAuthHeader string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"header.eyJ0b2tlbl91c2UiOiJpZCJ9.sig","access_token":"a","refresh_token":"r","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	client := &AuthClient{
		domain:       strings.TrimPrefix(server.URL, "https://"),
		clientID:     "client-id-123",
		clientSecret: proxycrypto.RedactedString("the-secret"),
		redirectURI:  "https://gateway.example.com/cb",
		httpClient:   server.Client(),
	}

	_, err := client.exchangeCodeWithURL(context.Background(), server.URL, "AUTH-CODE", "CODE-VERIFIER")
	require.NoError(t, err)

	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-id-123:the-secret"))
	assert.Equal(t, expectedAuth, gotAuthHeader)
	assert.Contains(t, gotBody, "code_verifier=CODE-VERIFIER")
	assert.Contains(t, gotBody, "grant_type=authorization_code")
	assert.Contains(t, gotBody, "code=AUTH-CODE")
	assert.Contains(t, gotBody, "client_id=client-id-123", "client_id must remain in body on confidential path for debuggability")
}

func TestExchangeCode_LegacyPublicClient_NoAuthHeader(t *testing.T) {
	var gotAuthHeader string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"header.eyJ0b2tlbl91c2UiOiJpZCJ9.sig","access_token":"a","refresh_token":"r","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	client := &AuthClient{
		domain:      strings.TrimPrefix(server.URL, "https://"),
		clientID:    "client-id-123",
		redirectURI: "https://gateway.example.com/cb",
		httpClient:  server.Client(),
	}

	_, err := client.exchangeCodeWithURL(context.Background(), server.URL, "AUTH-CODE", "CODE-VERIFIER")
	require.NoError(t, err)

	assert.Empty(t, gotAuthHeader, "legacy path must not send an Authorization header")
	assert.Contains(t, gotBody, "client_id=client-id-123")
	assert.Contains(t, gotBody, "code_verifier=CODE-VERIFIER")
}

func TestNoSecretFetcher_RejectsConfidentialSource(t *testing.T) {
	src := &tenant.IdentitySource{
		ID:        "src-1",
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
	}
	_, err := NoSecretFetcher(context.Background(), src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NoSecretFetcher called for confidential source")
	// RoleArn must be redacted in the error message — a cross-account ARN in a
	// log sink lets an attacker enumerate customer account IDs.
	assert.NotContains(t, err.Error(), "123456789012", "RoleArn account ID must not appear verbatim")
	assert.NotContains(t, err.Error(), "identity-gateway-acme", "RoleArn suffix must not appear verbatim")
}

func TestNoSecretFetcher_AcceptsLegacySource(t *testing.T) {
	src := &tenant.IdentitySource{ID: "legacy", PoolID: "p", ClientID: "c"}
	got, err := NoSecretFetcher(context.Background(), src)
	require.NoError(t, err)
	assert.Empty(t, got)
}
