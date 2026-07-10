package cognito

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	proxycrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// AuthClient handles OAuth2 Authorization Code + PKCE flow with Cognito.
type AuthClient struct {
	domain       string // e.g. "test.auth.eu-north-1.amazoncognito.com"
	clientID     string
	clientSecret proxycrypto.RedactedString // empty for legacy public-client PKCE path; populated for confidential clients
	redirectURI  string
	poolID       string
	region       string
	httpClient   *http.Client
}

// IDTokenVerifier verifies a Cognito ID token's signature and claims, returning
// the validated claim set. *JWKSVerifier satisfies this interface. It is the
// exported seam callers use to inject a verifier (production uses a JWKS-backed
// verifier; tests may inject a stub).
type IDTokenVerifier interface {
	Verify(tokenString, expectedClientID string) (map[string]interface{}, error)
}

// PoolID returns the Cognito user pool ID bound to this client. It is needed to
// construct the JWKS issuer URL for in-process ID-token signature verification.
func (c *AuthClient) PoolID() string { return c.poolID }

// Region returns the AWS region of the bound Cognito user pool.
func (c *AuthClient) Region() string { return c.region }

// ClientID returns the Cognito app client ID, used as the expected `aud` claim
// when verifying ID tokens.
func (c *AuthClient) ClientID() string { return c.clientID }

// NewAuthClient creates a new Cognito OAuth2 client.
//
// poolID and region are used for JWT claim validation (iss, aud).
// For backwards compatibility, they may be empty strings -- in that case,
// iss/aud validation is skipped (but exp and token_use are still checked).
func NewAuthClient(domain, clientID, redirectURI, poolID, region string) *AuthClient {
	return &AuthClient{
		domain:      domain,
		clientID:    clientID,
		redirectURI: redirectURI,
		poolID:      poolID,
		region:      region,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SecretFetcher returns the Cognito app client_secret for a wizard-provisioned
// source. For legacy sources (no RoleArn / SecretArn), callers should pass
// NoSecretFetcher.
type SecretFetcher func(ctx context.Context, src *tenant.IdentitySource) (string, error)

// NoSecretFetcher is the default fetcher for legacy public-client sources. It
// asserts the source has no managed-secret fields — a caller that passes
// NoSecretFetcher but a source with RoleArn/SecretArn populated has a
// configuration bug that would otherwise manifest as an opaque "invalid_client"
// response from Cognito.
func NoSecretFetcher(ctx context.Context, src *tenant.IdentitySource) (string, error) {
	if src != nil && (src.RoleArn != "" || src.SecretArn != "") {
		// The RoleArn is a cross-account IAM ARN; redact in case the error
		// surfaces through a log sink, so enumeration of customer account IDs
		// from error logs is not possible.
		return "", fmt.Errorf("cognito: NoSecretFetcher called for confidential source %q (RoleArn=%s, SecretArn set=%v); pass a real SecretFetcher", src.ID, proxycrypto.RedactedString(src.RoleArn), src.SecretArn != "")
	}
	return "", nil
}

// NewAuthClientForSource creates an auth client for a specific Cognito pool
// identified by a tenant.IdentitySource.
//
// If the source has RoleArn and SecretArn set (wizard-provisioned), the fetcher
// is called to retrieve the client_secret from the customer's Secrets Manager.
// Otherwise the client is constructed as a public client (PKCE only), preserving
// backwards compatibility with Terraform-seeded tenants.
func NewAuthClientForSource(ctx context.Context, source *tenant.IdentitySource, redirectURI string, fetch SecretFetcher) (*AuthClient, error) {
	var secret string
	if source.RoleArn != "" && source.SecretArn != "" {
		if fetch == nil {
			return nil, fmt.Errorf("cognito: SecretFetcher is required when source has RoleArn and SecretArn")
		}
		s, err := fetch(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("cognito: fetch client secret: %w", err)
		}
		secret = s
	}
	return &AuthClient{
		domain:       source.Domain,
		clientID:     source.ClientID,
		clientSecret: proxycrypto.RedactedString(secret),
		redirectURI:  redirectURI,
		poolID:       source.PoolID,
		region:       source.Region,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// GeneratePKCE generates a PKCE code verifier and challenge.
// Returns (verifier, challenge).
func (c *AuthClient) GeneratePKCE() (string, string) {
	// Generate 32 random bytes for the verifier
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		panic(fmt.Sprintf("failed to generate PKCE verifier: %v", err))
	}

	// Base64url encode the verifier (without padding)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate challenge: SHA256(verifier) -> base64url
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge
}

// AuthorizationURL generates the Cognito authorization URL for the OAuth2 flow.
func (c *AuthClient) AuthorizationURL(state, codeChallenge string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.clientID)
	params.Set("redirect_uri", c.redirectURI)
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	return fmt.Sprintf("https://%s/oauth2/authorize?%s", c.domain, params.Encode())
}

// ExchangeCode exchanges an authorization code for an ID token.
func (c *AuthClient) ExchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth2/token", c.domain)
	return c.exchangeCodeWithURL(ctx, tokenURL, code, codeVerifier)
}

// exchangeCodeWithURL is an internal method that allows testing with a custom URL.
func (c *AuthClient) exchangeCodeWithURL(ctx context.Context, tokenURL, code, codeVerifier string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.redirectURI)
	data.Set("client_id", c.clientID)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.clientSecret.Raw() != "" {
		creds := c.clientID + ":" + c.clientSecret.Raw()
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResponse.IDToken == "" {
		return "", fmt.Errorf("no id_token in response")
	}

	return tokenResponse.IDToken, nil
}

// clockSkew is the maximum acceptable clock skew for token expiration checks.
const clockSkew = 5 * time.Minute

// ParseIDToken decodes a JWT ID token and validates its claims WITHOUT checking
// the signature. It is a claims-decoding helper only.
//
// Validated claims:
//   - iss: must match https://cognito-idp.<region>.amazonaws.com/<poolId>
//   - aud: must contain the configured client ID
//   - exp: must not be expired (with 5 minute clock skew)
//   - token_use: must equal "id"
//
// SECURITY: This does NOT verify the JWT signature. It must not be used on any
// authentication path. Callers that establish a session from an ID token
// (OAuth-code callback, direct bearer-token auth, custom login) MUST verify the
// signature and claims via a JWKSVerifier (see IDTokenVerifier), which protects
// against tokens minted by a compromised token endpoint or injected through
// other channels.
func (c *AuthClient) ParseIDToken(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload JSON: %w", err)
	}

	// Validate token_use claim
	if tokenUse, ok := payload["token_use"].(string); ok {
		if tokenUse != "id" {
			return nil, fmt.Errorf("invalid token_use: expected \"id\", got %q", tokenUse)
		}
	}

	// Validate exp claim
	if exp, ok := payload["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime.Add(clockSkew)) {
			return nil, fmt.Errorf("token expired at %v", expTime)
		}
	}

	// Validate iss claim (only if poolID and region are configured)
	if c.poolID != "" && c.region != "" {
		expectedIss := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", c.region, c.poolID)
		if iss, ok := payload["iss"].(string); ok {
			if iss != expectedIss {
				return nil, fmt.Errorf("invalid issuer: expected %q, got %q", expectedIss, iss)
			}
		}
	}

	// Validate aud claim (only if clientID is configured)
	if c.clientID != "" {
		if aud, ok := payload["aud"].(string); ok {
			if aud != c.clientID {
				return nil, fmt.Errorf("invalid audience: expected %q, got %q", c.clientID, aud)
			}
		}
	}

	return payload, nil
}
