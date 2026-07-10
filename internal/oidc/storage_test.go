package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	internalcrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
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

// newTestStorage creates a Storage backed by MemoryDB with a mock KMS signer.
func newTestStorage(t *testing.T) (*Storage, *store.AppStore, *store.ClaimStore, *store.SourceStore) {
	t.Helper()

	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	appStore := store.NewAppStore(configDB, "test")
	claimStore := store.NewClaimStore(configDB, "test")
	sourceStore := store.NewSourceStore(configDB, "test")

	mock := newMockKMSClient(t)
	joseSigner, err := internalcrypto.NewKMSJoseSigner("test-key-id", mock)
	require.NoError(t, err)

	s := NewStorage(appStore, claimStore, sourceStore, joseSigner, sessionDB, "test-key-id")
	return s, appStore, claimStore, sourceStore
}

func TestCreateAndGetAuthRequest(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		State:        "random-state",
		Nonce:        "random-nonce",
		ResponseType: oidc.ResponseTypeCode,
	}

	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)
	require.NotEmpty(t, authReq.GetID())

	assert.Equal(t, "test-client", authReq.GetClientID())
	assert.Equal(t, "https://app.example.com/callback", authReq.GetRedirectURI())
	assert.Equal(t, oidc.ResponseTypeCode, authReq.GetResponseType())
	assert.Equal(t, "random-state", authReq.GetState())
	assert.Equal(t, "random-nonce", authReq.GetNonce())
	assert.Contains(t, authReq.GetScopes(), "openid")
	assert.Contains(t, authReq.GetScopes(), "email")

	// Retrieve by ID
	retrieved, err := s.AuthRequestByID(ctx, authReq.GetID())
	require.NoError(t, err)
	assert.Equal(t, authReq.GetID(), retrieved.GetID())
	assert.Equal(t, authReq.GetClientID(), retrieved.GetClientID())
	assert.Equal(t, authReq.GetRedirectURI(), retrieved.GetRedirectURI())
}

func TestCreateAuthRequest_WithPKCE(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	req := &oidc.AuthRequest{
		ClientID:            "test-client",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              oidc.SpaceDelimitedArray{"openid"},
		ResponseType:        oidc.ResponseTypeCode,
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}

	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	// Verify PKCE challenge is stored
	retrieved, err := s.AuthRequestByID(ctx, authReq.GetID())
	require.NoError(t, err)

	challenge := retrieved.GetCodeChallenge()
	require.NotNil(t, challenge)
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge.Challenge)
	assert.Equal(t, oidc.CodeChallengeMethodS256, challenge.Method)
}

func TestSaveAndGetByCode(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	// Create an auth request first
	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}

	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	// Save auth code
	code := "test-auth-code-12345"
	err = s.SaveAuthCode(ctx, authReq.GetID(), code)
	require.NoError(t, err)

	// Retrieve by code
	retrieved, err := s.AuthRequestByCode(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, authReq.GetID(), retrieved.GetID())
	assert.Equal(t, authReq.GetClientID(), retrieved.GetClientID())
}

func TestDeleteAuthRequest(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}

	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	// Delete
	err = s.DeleteAuthRequest(ctx, authReq.GetID())
	require.NoError(t, err)

	// Verify it's gone
	_, err = s.AuthRequestByID(ctx, authReq.GetID())
	assert.Error(t, err)
}

func TestGetClient(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()

	// Create a tenant and OIDC app
	tenantSlug := "test-tenant"
	db := store.NewMemoryDB()
	tenantStore := store.NewTenantStore(db, "test")
	// Use the storage's db directly via appStore
	_ = tenantStore

	app := &tenant.Application{
		DisplayName: "OIDC Test App",
		Protocol:    "oidc",
		SourceID:    "src-1",
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
		TokenEndpointAuthMethod: "client_secret_basic",
		IDTokenLifetimeSec:      3600,
		AccessTokenLifetimeSec:  3600,
	}
	err = appStore.UpdateOIDCConfig(ctx, tenantSlug, appID, oidcCfg)
	require.NoError(t, err)

	// Look up the client
	client, err := s.GetClientByClientID(ctx, appID)
	require.NoError(t, err)

	assert.Equal(t, appID, client.GetID())
	assert.Equal(t, []string{"https://app.example.com/callback"}, client.RedirectURIs())
	assert.Equal(t, oidc.AuthMethodBasic, client.AuthMethod())
	assert.Equal(t, time.Hour, client.IDTokenLifetime())
}

func TestGetClient_NotFound(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, err := s.GetClientByClientID(ctx, "nonexistent-client")
	assert.Error(t, err)
}

// seedOIDCClient creates an active OIDC application under tenantSlug and returns
// its client ID (the app ID).
func seedOIDCClient(t *testing.T, appStore *store.AppStore, tenantSlug string) string {
	t.Helper()
	ctx := context.Background()
	app := &tenant.Application{
		DisplayName: "OIDC Client for " + tenantSlug,
		Protocol:    "oidc",
		SourceID:    "src-1",
		Status:      "active",
	}
	appID, err := appStore.Create(ctx, tenantSlug, app, nil)
	require.NoError(t, err)
	err = appStore.UpdateOIDCConfig(ctx, tenantSlug, appID, &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	require.NoError(t, err)
	return appID
}

// TestGetClient_CrossTenantIssuerRejected verifies that a client that
// belongs to tenant A must not be resolvable on tenant B's issuer path. The
// zitadel/oidc library resolves clients without a tenant argument, so the
// storage wrapper derives the tenant from the request issuer (set by the
// IssuerInterceptor) and fails closed on a mismatch.
func TestGetClient_CrossTenantIssuerRejected(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	clientID := seedOIDCClient(t, appStore, "tenant-a")

	// No issuer in context → guard is a no-op, client resolves.
	client, err := s.GetClientByClientID(context.Background(), clientID)
	require.NoError(t, err)
	assert.Equal(t, clientID, client.GetID())

	// Issuer on the owning tenant's path → resolves.
	ctxA := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-a/oidc")
	client, err = s.GetClientByClientID(ctxA, clientID)
	require.NoError(t, err)
	assert.Equal(t, clientID, client.GetID())

	// Issuer on a DIFFERENT tenant's path → rejected as not found.
	ctxB := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-b/oidc")
	_, err = s.GetClientByClientID(ctxB, clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant-b")

	// The same guard protects credential authorization, which delegates to
	// GetClientByClientID.
	err = s.AuthorizeClientIDSecret(ctxB, clientID, "irrelevant-secret")
	assert.Error(t, err)
}

func TestSigningKey(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	key, err := s.SigningKey(ctx)
	require.NoError(t, err)

	assert.Equal(t, "test-key-id", key.ID())
	assert.Equal(t, jose.RS256, key.SignatureAlgorithm())
	assert.NotNil(t, key.Key())
}

func TestKeySet(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	keys, err := s.KeySet(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	key := keys[0]
	assert.Equal(t, "test-key-id", key.ID())
	assert.Equal(t, jose.RS256, key.Algorithm())
	assert.Equal(t, "sig", key.Use())

	// Verify the key contains a valid RSA public key
	pubKey, ok := key.Key().(*rsa.PublicKey)
	require.True(t, ok, "Key should be an *rsa.PublicKey")
	assert.NotNil(t, pubKey.N, "Public key modulus should not be nil")
	assert.NotZero(t, pubKey.E, "Public key exponent should not be zero")
}

func TestSignatureAlgorithms(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	algs, err := s.SignatureAlgorithms(ctx)
	require.NoError(t, err)
	require.Len(t, algs, 1)
	assert.Equal(t, jose.RS256, algs[0])
}

func TestCreateAccessToken(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	// Create an auth request to use as TokenRequest
	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		ResponseType: oidc.ResponseTypeCode,
	}
	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	tokenID, expiration, err := s.CreateAccessToken(ctx, authReq)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenID)
	assert.True(t, expiration.After(time.Now()))
}

func TestHealth(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	err := s.Health(ctx)
	assert.NoError(t, err)
}

func TestStorageImplementsInterface(t *testing.T) {
	s, _, _, _ := newTestStorage(t)

	// Verify Storage satisfies op.Storage at compile time.
	var _ op.Storage = s
}

func TestSetUserinfoFromScopes(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	t.Run("without cached claims", func(t *testing.T) {
		userinfo := new(oidc.UserInfo)
		err := s.SetUserinfoFromScopes(ctx, userinfo, "user@example.com", "client-1", []string{"openid", "email", "profile"})
		require.NoError(t, err)

		assert.Equal(t, "user@example.com", userinfo.Subject)
		assert.Equal(t, "user@example.com", string(userinfo.Email))
		assert.Equal(t, "user@example.com", userinfo.PreferredUsername)
		// With no cached claims the fallback email is synthetic and
		// unverified, so email_verified must be false, never a hard-coded true.
		assert.False(t, bool(userinfo.EmailVerified))
	})

	t.Run("with cached Cognito claims", func(t *testing.T) {
		// Store Cognito claims in the cache (as would happen during
		// CompleteAuthRequest), keyed by (tenant, sub). The lookup derives the
		// tenant from the request issuer, so drive the call with a matching issuer.
		ctx := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-a/oidc")
		s.userClaims.Store(claimsKey("tenant-a", "cognito-user-sub-123"), &userClaims{
			Email:         "alice@example.com",
			GivenName:     "Alice",
			FamilyName:    "Smith",
			EmailVerified: true,
			Groups:        []string{"admins", "users"},
		})

		userinfo := new(oidc.UserInfo)
		err := s.SetUserinfoFromScopes(ctx, userinfo, "cognito-user-sub-123", "client-1", []string{"openid", "email", "profile"})
		require.NoError(t, err)

		// Verify all claims are populated from the cache.
		assert.Equal(t, "cognito-user-sub-123", userinfo.Subject)
		assert.Equal(t, "alice@example.com", string(userinfo.Email))
		assert.True(t, bool(userinfo.EmailVerified))
		assert.Equal(t, "Alice Smith", userinfo.Name)
		assert.Equal(t, "Alice", userinfo.GivenName)
		assert.Equal(t, "alice@example.com", userinfo.PreferredUsername)
	})
}
