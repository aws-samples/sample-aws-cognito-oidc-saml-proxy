package cognito

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newJWKSVerifierWithURL creates a JWKSVerifier with a custom JWKS URL for
// testing. It skips region/poolID validation and the SSRF guard so tests can
// point the verifier at an httptest.Server on loopback.
// This is intentionally a test-only helper; it must never be used in
// production code — the production constructor is NewJWKSVerifier which
// validates both inputs and uses safehttp.TrustClient.
func newJWKSVerifierWithURL(poolID, region, jwksURL string) *JWKSVerifier {
	return &JWKSVerifier{
		poolID:  poolID,
		region:  region,
		jwksURL: jwksURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		keys:     make(map[string]*rsa.PublicKey),
		cacheTTL: 1 * time.Hour,
	}
}

// testJWKSKey holds a test RSA key pair and its kid.
type testJWKSKey struct {
	kid        string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func generateTestJWKSKey(t *testing.T, kid string) *testJWKSKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &testJWKSKey{
		kid:        kid,
		privateKey: key,
		publicKey:  &key.PublicKey,
	}
}

// jwksJSON builds a JWKS JSON response containing the given keys.
func jwksJSON(keys ...*testJWKSKey) []byte {
	type jwkKey struct {
		Alg string `json:"alg"`
		E   string `json:"e"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		Use string `json:"use"`
	}

	var jwkKeys []jwkKey
	for _, k := range keys {
		jwkKeys = append(jwkKeys, jwkKey{
			Alg: "RS256",
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.publicKey.E)).Bytes()),
			Kid: k.kid,
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(k.publicKey.N.Bytes()),
			Use: "sig",
		})
	}

	resp := struct {
		Keys []jwkKey `json:"keys"`
	}{Keys: jwkKeys}

	data, _ := json.Marshal(resp)
	return data
}

// signTestJWT creates a signed JWT with the given claims and key.
func signTestJWT(t *testing.T, key *testJWKSKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.kid
	signed, err := token.SignedString(key.privateKey)
	require.NoError(t, err)
	return signed
}

func TestJWKSVerifier_FetchAndVerify(t *testing.T) {
	testKey := generateTestJWKSKey(t, "test-kid-1")
	poolID := "eu-north-1_TestPool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(testKey))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	// Create a valid signed JWT
	tokenStr := signTestJWT(t, testKey, jwt.MapClaims{
		"sub":       "user-123",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_TestPool",
		"aud":       "test-client-id",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "id",
		"email":     "user@example.com",
	})

	claims, err := verifier.Verify(tokenStr, "test-client-id")
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "user@example.com", claims["email"])
}

func TestJWKSVerifier_CachingDoesNotRefetch(t *testing.T) {
	testKey := generateTestJWKSKey(t, "cache-kid")
	poolID := "eu-north-1_CachePool"
	region := "eu-north-1"

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(testKey))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	claims := jwt.MapClaims{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_CachePool",
		"aud":       "client-1",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "id",
	}

	// First verification triggers a fetch
	tokenStr1 := signTestJWT(t, testKey, claims)
	_, err := verifier.Verify(tokenStr1, "client-1")
	require.NoError(t, err)
	assert.Equal(t, 1, fetchCount, "first call should fetch JWKS")

	// Second verification should use cached keys
	tokenStr2 := signTestJWT(t, testKey, claims)
	_, err = verifier.Verify(tokenStr2, "client-1")
	require.NoError(t, err)
	assert.Equal(t, 1, fetchCount, "second call should use cached JWKS")
}

func TestJWKSVerifier_ExpiredTokenRejected(t *testing.T) {
	testKey := generateTestJWKSKey(t, "exp-kid")
	poolID := "eu-north-1_ExpPool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(testKey))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	tokenStr := signTestJWT(t, testKey, jwt.MapClaims{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_ExpPool",
		"aud":       "client-1",
		"exp":       time.Now().Add(-10 * time.Minute).Unix(),
		"iat":       time.Now().Add(-20 * time.Minute).Unix(),
		"token_use": "id",
	})

	_, err := verifier.Verify(tokenStr, "client-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT validation failed")
}

func TestJWKSVerifier_WrongKidRejected(t *testing.T) {
	testKey := generateTestJWKSKey(t, "good-kid")
	wrongKey := generateTestJWKSKey(t, "wrong-kid")
	poolID := "eu-north-1_KidPool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Only serve good-kid
		_, _ = w.Write(jwksJSON(testKey))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	// Sign with wrong-kid that's not in the JWKS
	tokenStr := signTestJWT(t, wrongKey, jwt.MapClaims{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_KidPool",
		"aud":       "client-1",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "id",
	})

	_, err := verifier.Verify(tokenStr, "client-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong-kid")
}

func TestJWKSVerifier_WrongIssuerRejected(t *testing.T) {
	testKey := generateTestJWKSKey(t, "iss-kid")
	poolID := "eu-north-1_IssPool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(testKey))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	tokenStr := signTestJWT(t, testKey, jwt.MapClaims{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_WrongPool",
		"aud":       "client-1",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "id",
	})

	_, err := verifier.Verify(tokenStr, "client-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestJWKSVerifier_WrongTokenUseRejected(t *testing.T) {
	testKey := generateTestJWKSKey(t, "use-kid")
	poolID := "eu-north-1_UsePool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(testKey))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	tokenStr := signTestJWT(t, testKey, jwt.MapClaims{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_UsePool",
		"aud":       "client-1",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "access",
	})

	_, err := verifier.Verify(tokenStr, "client-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token_use")
}

func TestJWKSVerifier_JWKSEndpointError(t *testing.T) {
	poolID := "eu-north-1_ErrPool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	_, err := verifier.Verify("dummy.token.here", "client-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

func TestJWKSVerifier_MultipleKeys(t *testing.T) {
	key1 := generateTestJWKSKey(t, "kid-1")
	key2 := generateTestJWKSKey(t, "kid-2")
	poolID := "eu-north-1_MultiPool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(key1, key2))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	baseClaims := jwt.MapClaims{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_MultiPool",
		"aud":       "client-1",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "id",
	}

	// Both keys should work
	token1 := signTestJWT(t, key1, baseClaims)
	_, err := verifier.Verify(token1, "client-1")
	require.NoError(t, err)

	token2 := signTestJWT(t, key2, baseClaims)
	_, err = verifier.Verify(token2, "client-1")
	require.NoError(t, err)
}

// TestJWKSVerifier_EmptyClientIDRejected asserts that verifying with an empty
// expectedClientID is a hard error, never a silently-skipped aud check. An
// otherwise-valid token (good signature/iss/exp/token_use) must still be rejected
// so a misconfigured verifier can never accept an ID token for an arbitrary app
// client in the same pool.
func TestJWKSVerifier_EmptyClientIDRejected(t *testing.T) {
	testKey := generateTestJWKSKey(t, "aud-kid")
	poolID := "eu-north-1_AudPool"
	region := "eu-north-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(testKey))
	}))
	defer server.Close()

	verifier := newJWKSVerifierWithURL(poolID, region, server.URL)

	tokenStr := signTestJWT(t, testKey, jwt.MapClaims{
		"sub":       "user-1",
		"iss":       "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_AudPool",
		"aud":       "some-other-client",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "id",
	})

	_, err := verifier.Verify(tokenStr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected client ID (audience) is empty")
}

func TestNewJWKSVerifier_URLConstruction(t *testing.T) {
	verifier, err := NewJWKSVerifier("eu-north-1_TestPool", "eu-north-1")
	require.NoError(t, err)
	assert.Equal(t, "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_TestPool/.well-known/jwks.json", verifier.jwksURL)
	assert.Equal(t, 1*time.Hour, verifier.cacheTTL)
}

// TestNewJWKSVerifier_InvalidPoolID is the MF-6 regression: an unvalidated
// poolID can inject arbitrary hostnames into the JWKS URL. Confirm that
// non-compliant pool IDs are rejected at construction time.
func TestNewJWKSVerifier_InvalidPoolID(t *testing.T) {
	cases := []struct {
		poolID string
		desc   string
	}{
		{"", "empty"},
		{"eu-north-1-NoUnderscore", "missing underscore separator"},
		{"attacker.com/_leak", "dot in region prefix"},
		{"eu-north-1_has space", "space in pool suffix"},
		{"eu-north-1_has/slash", "slash in pool suffix"},
		{"eu-north-1_", "empty pool suffix"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := NewJWKSVerifier(tc.poolID, "eu-north-1")
			assert.Error(t, err, "poolID %q must be rejected", tc.poolID)
		})
	}
}

// TestNewJWKSVerifier_InvalidRegion is the MF-6 regression: an attacker-
// controlled region value can route the JWKS GET to an arbitrary host. Confirm
// that non-AWS region strings are rejected at construction time.
func TestNewJWKSVerifier_InvalidRegion(t *testing.T) {
	cases := []struct {
		region string
		desc   string
	}{
		{"", "empty"},
		{"us-east", "missing digit suffix"},
		{"attacker.com", "dots in region"},
		{"us-east-1.attacker.com", "trailing domain injection"},
		{"169.254.169.254", "IMDS IP literal"},
		{"../../../etc/passwd", "path traversal"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := NewJWKSVerifier("eu-north-1_TestPool", tc.region)
			assert.Error(t, err, "region %q must be rejected", tc.region)
		})
	}
}

// TestNewJWKSVerifier_ValidInputs confirms that well-formed pool IDs and
// regions across all major AWS partition naming patterns are accepted.
func TestNewJWKSVerifier_ValidInputs(t *testing.T) {
	cases := []struct {
		poolID string
		region string
		desc   string
	}{
		{"eu-north-1_AbCdEf012", "eu-north-1", "EU commercial"},
		{"us-east-1_TestPool99", "us-east-1", "US East"},
		{"ap-southeast-2_Xyz", "ap-southeast-2", "AP Southeast"},
		{"us-gov-east-1_GovPool", "us-gov-east-1", "GovCloud East"},
		{"cn-north-1_ChinaPool", "cn-north-1", "China North"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			v, err := NewJWKSVerifier(tc.poolID, tc.region)
			require.NoError(t, err, "poolID=%q region=%q", tc.poolID, tc.region)
			require.NotNil(t, v)
		})
	}
}
