package cognito

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/safehttp"
)

// poolIDRE matches valid Cognito user pool IDs: "<region-prefix>_<AlphaNum>".
// Example: "eu-north-1_AbCdEf012"
var poolIDRE = regexp.MustCompile(`^[a-z0-9-]+_[A-Za-z0-9]+$`)

// regionRE matches AWS region identifiers across all partitions:
//   - commercial:  "eu-north-1", "us-east-1", "ap-southeast-2"
//   - GovCloud:    "us-gov-east-1", "us-gov-west-1"
//   - China:       "cn-north-1", "cn-northwest-1"
//   - ISO:         "eu-iso-east-1", "eu-isob-east-1"
//
// Pattern: one or more lowercase words separated by hyphens, terminated by a
// single decimal digit. No dots, upper-case, digits in word segments, or other
// characters that could redirect the constructed JWKS URL to an attacker host.
var regionRE = regexp.MustCompile(`^[a-z]{1,12}(?:-[a-z]{1,12})*-[0-9]$`)

// ValidatePoolID returns an error when poolID does not match the expected
// Cognito pool-ID format. An invalid ID means the JWKS URL would contain an
// attacker-controlled string that may alter the resolved host or path.
func ValidatePoolID(poolID string) error {
	if !poolIDRE.MatchString(poolID) {
		return fmt.Errorf("invalid Cognito pool ID %q: must match %s", poolID, poolIDRE)
	}
	return nil
}

// ValidateRegion returns an error when region does not match the expected AWS
// region format. An invalid region allows host injection into the JWKS URL.
func ValidateRegion(region string) error {
	if !regionRE.MatchString(region) {
		return fmt.Errorf("invalid AWS region %q: must match %s", region, regionRE)
	}
	return nil
}

// jwksKey represents a single key from the JWKS endpoint.
type jwksKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

// jwksResponse represents the response from the JWKS endpoint.
type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

// JWKSVerifier fetches JWKS keys from a Cognito User Pool and verifies
// JWT signatures. Keys are cached for 1 hour to avoid repeated network calls.
type JWKSVerifier struct {
	poolID     string
	region     string
	jwksURL    string
	httpClient *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	cacheTTL  time.Duration
}

// NewJWKSVerifier creates a new JWKSVerifier for the given Cognito User Pool.
// It validates poolID and region against the expected AWS formats to prevent
// host injection via attacker-controlled tenant configuration (OWASP A10 SSRF /
// STRIDE Spoofing). Returns an error if either value fails validation.
//
// The underlying HTTP client is safehttp.TrustClient, which:
//   - Restricts connections to public IP addresses (blocks 169.254.x, 10.x, etc.)
//   - Requires HTTPS for the JWKS endpoint (no plaintext downgrade)
//   - Re-validates the destination IP at dial time (defeats DNS rebinding)
func NewJWKSVerifier(poolID, region string) (*JWKSVerifier, error) {
	if err := ValidatePoolID(poolID); err != nil {
		return nil, err
	}
	if err := ValidateRegion(region); err != nil {
		return nil, err
	}
	return &JWKSVerifier{
		poolID:     poolID,
		region:     region,
		jwksURL:    fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, poolID),
		httpClient: safehttp.TrustClient(10 * time.Second),
		keys:       make(map[string]*rsa.PublicKey),
		cacheTTL:   1 * time.Hour,
	}, nil
}


// Verify validates the JWT signature using JWKS and returns the parsed claims.
// It validates: kid match, RS256 signature, iss, aud, exp, and token_use claims.
func (v *JWKSVerifier) Verify(tokenString string, expectedClientID string) (map[string]interface{}, error) {
	// Ensure keys are loaded and fresh
	if err := v.ensureKeys(); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse the token with key lookup
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing algorithm
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing kid in JWT header")
		}

		key, err := v.getKey(kid)
		if err != nil {
			return nil, err
		}

		return key, nil
	}, jwt.WithExpirationRequired())

	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	// Validate iss
	expectedIss := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", v.region, v.poolID)
	if iss, ok := claims["iss"].(string); !ok || iss != expectedIss {
		return nil, fmt.Errorf("invalid issuer: expected %q, got %q", expectedIss, claims["iss"])
	}

	// Validate aud. An empty expectedClientID is treated as a hard error, never a
	// silently-skipped check: every deployed caller supplies the app-client
	// ID (config.Load makes PROXY_COGNITO_CLIENT_ID mandatory outside local dev), so
	// an empty value here means a misconfigured verifier. Skipping the check would
	// fail open — accepting an ID token minted for a *different* app client in the
	// same pool. Refuse to verify rather than accept an unbounded audience.
	if expectedClientID == "" {
		return nil, fmt.Errorf("cannot verify token: expected client ID (audience) is empty")
	}
	if aud, ok := claims["aud"].(string); !ok || aud != expectedClientID {
		return nil, fmt.Errorf("invalid audience: expected %q, got %q", expectedClientID, claims["aud"])
	}

	// Validate token_use
	if tokenUse, ok := claims["token_use"].(string); !ok || tokenUse != "id" {
		return nil, fmt.Errorf("invalid token_use: expected \"id\", got %q", claims["token_use"])
	}

	return claims, nil
}

// ensureKeys fetches JWKS if the cache is empty or stale.
func (v *JWKSVerifier) ensureKeys() error {
	v.mu.RLock()
	needsFetch := len(v.keys) == 0 || time.Since(v.fetchedAt) > v.cacheTTL
	v.mu.RUnlock()

	if !needsFetch {
		return nil
	}

	return v.fetchKeys()
}

// fetchKeys retrieves JWKS from the Cognito endpoint and updates the cache.
func (v *JWKSVerifier) fetchKeys() error {
	resp, err := v.httpClient.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		pubKey, err := parseRSAPublicKey(key)
		if err != nil {
			continue // skip malformed keys
		}

		keys[key.Kid] = pubKey
	}

	if len(keys) == 0 {
		return fmt.Errorf("no valid RSA signing keys found in JWKS")
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()

	return nil
}

// getKey returns the RSA public key for the given kid.
func (v *JWKSVerifier) getKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}

	return key, nil
}

// parseRSAPublicKey constructs an RSA public key from JWKS key parameters.
func parseRSAPublicKey(key jwksKey) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64URLDecode(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// base64URLDecode decodes a base64url-encoded string (with or without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.StdEncoding.DecodeString(s)
}
