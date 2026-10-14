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

// TestGetClient_DisabledAppRejected is the M-5 regression: an application whose
// status is not "active" must not resolve as an OIDC client, so authorize,
// token and credential checks all fail closed for a disabled app.
func TestGetClient_DisabledAppRejected(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	// Active → resolves.
	_, err := s.GetClientByClientID(ctx, clientID)
	require.NoError(t, err)

	require.NoError(t, appStore.SetStatus(ctx, "test-tenant", clientID, "disabled"))

	_, err = s.GetClientByClientID(ctx, clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")

	// Credential authorization delegates to GetClientByClientID and fails too.
	assert.Error(t, s.AuthorizeClientIDSecret(ctx, clientID, "irrelevant-secret"))
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

// TestCreateAccessToken_HonoursConfiguredLifetime is the M-8 regression: the
// access token expires after the client's AccessTokenLifetimeSec (bounded to
// [60s, 24h]; 0 = 1h default) instead of a hard-coded hour, and the stored
// record agrees with the returned expiry so introspection/userinfo cut off at
// the same instant.
func TestCreateAccessToken_HonoursConfiguredLifetime(t *testing.T) {
	cases := []struct {
		name string
		sec  int
		want time.Duration
	}{
		{"600 -> 10m", 600, 10 * time.Minute},
		{"0 -> default 1h", 0, time.Hour},
		{"5 -> clamped to 60s", 5, 60 * time.Second},
		{"999999 -> clamped to 24h", 999999, 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, appStore, _, _ := newTestStorage(t)
			ctx := context.Background()
			clientID := seedOIDCClient(t, appStore, "test-tenant")
			_, _, cfg, err := appStore.GetByClientID(ctx, clientID)
			require.NoError(t, err)
			cfg.AccessTokenLifetimeSec = tc.sec
			require.NoError(t, appStore.UpdateOIDCConfig(ctx, "test-tenant", clientID, cfg))

			authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
				ClientID:     clientID,
				RedirectURI:  "https://app.example.com/callback",
				Scopes:       oidc.SpaceDelimitedArray{"openid"},
				ResponseType: oidc.ResponseTypeCode,
			}, "")
			require.NoError(t, err)

			before := time.Now()
			tokenID, expiration, err := s.CreateAccessToken(ctx, authReq)
			require.NoError(t, err)
			assert.WithinDuration(t, before.Add(tc.want), expiration, 5*time.Second)

			var item accessTokenItem
			require.NoError(t, s.db.Get(ctx, oidcAccessTokenPK(tokenID), oidcAccessTokenSK(), &item))
			assert.True(t, item.ExpiresAt.Equal(expiration))
		})
	}

	t.Run("unknown client -> default 1h", func(t *testing.T) {
		s, _, _, _ := newTestStorage(t)
		ctx := context.Background()
		authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID: "no-such-client", RedirectURI: "https://app.example.com/callback",
			Scopes: oidc.SpaceDelimitedArray{"openid"}, ResponseType: oidc.ResponseTypeCode,
		}, "")
		require.NoError(t, err)
		_, expiration, err := s.CreateAccessToken(ctx, authReq)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(time.Hour), expiration, 5*time.Second)
	})
}

func TestHealth(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	err := s.Health(ctx)
	assert.NoError(t, err)
}

// Compile-time assertions: Storage implements the required op.Storage plus the
// optional request-aware claim hooks zitadel prefers when present. Without the
// two optional interfaces zitadel falls back to the (userID, clientID) hooks,
// which have no record to read claims from (finding M-2).
var (
	_ op.Storage                       = (*Storage)(nil)
	_ op.CanSetUserinfoFromRequest     = (*Storage)(nil)
	_ op.CanGetPrivateClaimsFromRequest = (*Storage)(nil)
)

func TestStorageImplementsInterface(t *testing.T) {
	s, _, _, _ := newTestStorage(t)

	// Verify Storage satisfies op.Storage at compile time.
	var _ op.Storage = s
	var _ op.CanSetUserinfoFromRequest = s
	var _ op.CanGetPrivateClaimsFromRequest = s
}

// TestSetUserinfoFromScopes: the deprecated (userID, clientID) hook only sets
// the subject. It has no record to read from, so it must never synthesise an
// email from the subject or claim the address is verified.
func TestSetUserinfoFromScopes(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	userinfo := new(oidc.UserInfo)
	err := s.SetUserinfoFromScopes(ctx, userinfo, "cognito-user-sub-123", "client-1", []string{"openid", "email", "profile"})
	require.NoError(t, err)

	assert.Equal(t, "cognito-user-sub-123", userinfo.Subject)
	assert.Empty(t, userinfo.Email, "subject must never be synthesised into email")
	assert.Empty(t, userinfo.PreferredUsername)
	assert.False(t, bool(userinfo.EmailVerified))
}

// aliceClaims is the rich Cognito claim set used by the split-Lambda tests.
func aliceClaims() SubjectClaims {
	return SubjectClaims{
		Sub:              "cognito-sub-alice",
		Email:            "alice@example.com",
		EmailVerified:    true,
		GivenName:        "Alice",
		FamilyName:       "Smith",
		Groups:           []string{"admins", "users"},
		CustomAttributes: map[string]string{"department": "engineering", "tenant_id": "t-42"},
	}
}

// assertAliceUserinfo checks that a userinfo carries Alice's real claims — the
// address (not the sub), the verified flag, the names and the groups.
func assertAliceUserinfo(t *testing.T, ui *oidc.UserInfo) {
	t.Helper()
	assert.Equal(t, "cognito-sub-alice", ui.Subject)
	assert.Equal(t, "alice@example.com", ui.Email, "email must be the real address, not the subject")
	assert.True(t, bool(ui.EmailVerified))
	assert.Equal(t, "Alice", ui.GivenName)
	assert.Equal(t, "Smith", ui.FamilyName)
	assert.Equal(t, "Alice Smith", ui.Name)
	assert.Equal(t, "alice@example.com", ui.PreferredUsername)
	assert.Equal(t, []string{"admins", "users"}, ui.Claims["groups"])
}

// newStorageOver creates a fresh Storage (as a cold Lambda would) sharing the
// given config and session databases with other instances.
func newStorageOver(t *testing.T, configDB, sessionDB *store.MemoryDB) *Storage {
	t.Helper()
	mock := newMockKMSClient(t)
	joseSigner, err := internalcrypto.NewKMSJoseSigner("test-key-id", mock)
	require.NoError(t, err)
	return NewStorage(
		store.NewAppStore(configDB, "test"),
		store.NewClaimStore(configDB, "test"),
		store.NewSourceStore(configDB, "test"),
		joseSigner, sessionDB, "test-key-id",
	)
}

// TestClaims_SurviveSplitLambda is the M-2 regression. Login (oidc-authorize),
// code exchange (oidc-token) and userinfo (oidc-discovery) run on separate
// Lambdas, so three independent Storage instances over one database must
// produce an ID token (code grant and refresh grant) and a userinfo response
// carrying the real Cognito claims. Before the fix the claims lived in a
// process-local cache and every other instance fell back to email = sub.
func TestClaims_SurviveSplitLambda(t *testing.T) {
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	ctx := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-a/oidc")

	// --- oidc-authorize: login completes the auth request and saves a code.
	storageA := newStorageOver(t, configDB, sessionDB)
	clientID := seedOIDCClient(t, storageA.appStore, "tenant-a")
	created, err := storageA.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email", "profile", "offline_access"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	require.NoError(t, err)
	require.NoError(t, storageA.CompleteAuthRequest(ctx, created.GetID(), aliceClaims()))
	const code = "split-lambda-code"
	require.NoError(t, storageA.SaveAuthCode(ctx, created.GetID(), code))

	// --- oidc-token: a fresh instance exchanges the code.
	storageB := newStorageOver(t, configDB, sessionDB)
	loaded, err := storageB.AuthRequestByCode(ctx, code)
	require.NoError(t, err)
	accessToken, refreshToken, _, err := storageB.CreateAccessAndRefreshTokens(ctx, loaded, "")
	require.NoError(t, err)

	idTokenInfo := new(oidc.UserInfo)
	require.NoError(t, storageB.SetUserinfoFromScopes(ctx, idTokenInfo, loaded.GetSubject(), clientID, loaded.GetScopes()))
	require.NoError(t, storageB.SetUserinfoFromRequest(ctx, idTokenInfo, loaded.(*AuthRequest), loaded.GetScopes()))
	assertAliceUserinfo(t, idTokenInfo)

	// --- oidc-discovery: a third instance serves userinfo from the bearer.
	storageC := newStorageOver(t, configDB, sessionDB)
	ui := new(oidc.UserInfo)
	require.NoError(t, storageC.SetUserinfoFromToken(ctx, ui, accessToken, "cognito-sub-alice", ""))
	assertAliceUserinfo(t, ui)

	// Introspection on the same instance reads the same record.
	intro := new(oidc.IntrospectionResponse)
	require.NoError(t, storageC.SetIntrospectionFromToken(ctx, intro, accessToken, "cognito-sub-alice", clientID))
	assert.True(t, intro.Active)
	assert.Equal(t, "alice@example.com", intro.Email)
	assert.Equal(t, "alice@example.com", intro.Username)
	assert.True(t, bool(intro.EmailVerified))
	assert.Equal(t, "Alice Smith", intro.Name)
	assert.Equal(t, "Alice", intro.GivenName)
	assert.Equal(t, "Smith", intro.FamilyName)

	// --- oidc-token again: refresh grant on an instance that never saw login.
	rr, err := storageB.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	refreshInfo := new(oidc.UserInfo)
	require.NoError(t, storageB.SetUserinfoFromScopes(ctx, refreshInfo, rr.GetSubject(), clientID, rr.GetScopes()))
	require.NoError(t, storageB.SetUserinfoFromRequest(ctx, refreshInfo, rr.(*refreshTokenRequest), rr.GetScopes()))
	assertAliceUserinfo(t, refreshInfo)

	// The rotated pair carries the claims too — userinfo for the new access
	// token on yet another fresh instance.
	newAccess, _, _, err := storageB.CreateAccessAndRefreshTokens(ctx, rr.(*refreshTokenRequest), refreshToken)
	require.NoError(t, err)
	ui2 := new(oidc.UserInfo)
	require.NoError(t, newStorageOver(t, configDB, sessionDB).SetUserinfoFromToken(ctx, ui2, newAccess, "cognito-sub-alice", ""))
	assertAliceUserinfo(t, ui2)
}

// TestUserinfo_NoEmailClaim_OmitsEmail: when Cognito supplies no email the
// claim is omitted — the subject is never substituted for it and the address
// is never advertised as verified.
func TestUserinfo_NoEmailClaim_OmitsEmail(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "tenant-a")

	created, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email", "profile"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	require.NoError(t, err)
	require.NoError(t, s.CompleteAuthRequest(ctx, created.GetID(), SubjectClaims{
		Sub: "sub-no-email", GivenName: "No", FamilyName: "Mail",
	}))
	loaded, err := s.AuthRequestByID(ctx, created.GetID())
	require.NoError(t, err)

	// ID-token path.
	ui := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromScopes(ctx, ui, "sub-no-email", clientID, loaded.GetScopes()))
	require.NoError(t, s.SetUserinfoFromRequest(ctx, ui, loaded.(*AuthRequest), loaded.GetScopes()))
	assert.Equal(t, "sub-no-email", ui.Subject)
	assert.Empty(t, ui.Email)
	assert.False(t, bool(ui.EmailVerified))
	assert.Empty(t, ui.PreferredUsername)
	assert.Equal(t, "No Mail", ui.Name)

	// Userinfo + introspection path.
	accessToken, _, err := s.CreateAccessToken(ctx, loaded)
	require.NoError(t, err)
	ui2 := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, ui2, accessToken, "sub-no-email", ""))
	assert.Empty(t, ui2.Email)
	assert.False(t, bool(ui2.EmailVerified))
	assert.Empty(t, ui2.PreferredUsername)

	intro := new(oidc.IntrospectionResponse)
	require.NoError(t, s.SetIntrospectionFromToken(ctx, intro, accessToken, "sub-no-email", clientID))
	assert.Empty(t, intro.Email)
	assert.Empty(t, intro.Username)
	assert.False(t, bool(intro.EmailVerified))
}

// TestClaimMappings_AppliedToIDTokenAndUserinfo: the per-app claim and role
// mappings (previously only honoured by the SAML assertion maker) are emitted
// under their target names in the ID token, userinfo and JWT private claims,
// and a mapping that targets a standard claim is ignored.
func TestClaimMappings_AppliedToIDTokenAndUserinfo(t *testing.T) {
	s, appStore, claimStore, _ := newTestStorage(t)
	ctx := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-a/oidc")
	clientID := seedOIDCClient(t, appStore, "tenant-a")

	require.NoError(t, claimStore.PutClaimMappings(ctx, "tenant-a", clientID, []tenant.ClaimMapping{
		{Name: "dept", SourceType: "cognito", SourceAttribute: "department", TargetAttribute: "department"},
		{Name: "tenant", SourceType: "attribute", SourceAttribute: "custom:tenant_id", TargetAttribute: "tenant_id"},
		{Name: "roles", SourceType: "groupMapping", SourceAttribute: "groups", TargetAttribute: "roles"},
		{Name: "env", SourceType: "static", DefaultValue: "production", TargetAttribute: "environment"},
		{Name: "full", SourceType: "cognito", SourceAttribute: "name", TargetAttribute: "display_name"},
		{Name: "missing", SourceType: "cognito", SourceAttribute: "cost_center", TargetAttribute: "cost_center", DefaultValue: "unassigned"},
		{Name: "absent", SourceType: "cognito", SourceAttribute: "nothing", TargetAttribute: "nothing"},
		// Hostile: must not be able to overwrite standard claims.
		{Name: "evil-email", SourceType: "cognito", SourceAttribute: "department", TargetAttribute: "email"},
		{Name: "evil-sub", SourceType: "static", DefaultValue: "someone-else", TargetAttribute: "sub"},
		{Name: "evil-verified", SourceType: "static", DefaultValue: "true", TargetAttribute: "email_verified"},
	}))
	require.NoError(t, claimStore.PutRoleMappings(ctx, "tenant-a", clientID, []tenant.RoleMapping{
		{CognitoGroup: "admins", MappedValue: "app-admin"},
		{CognitoGroup: "unrelated", MappedValue: "never"},
	}))

	created, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email", "profile"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	require.NoError(t, err)
	require.NoError(t, s.CompleteAuthRequest(ctx, created.GetID(), aliceClaims()))
	loaded, err := s.AuthRequestByID(ctx, created.GetID())
	require.NoError(t, err)

	assertMapped := func(t *testing.T, claims map[string]any) {
		t.Helper()
		assert.Equal(t, "engineering", claims["department"])
		assert.Equal(t, "t-42", claims["tenant_id"])
		assert.Equal(t, []string{"app-admin"}, claims["roles"])
		assert.Equal(t, "production", claims["environment"])
		assert.Equal(t, "Alice Smith", claims["display_name"])
		assert.Equal(t, "unassigned", claims["cost_center"])
		assert.NotContains(t, claims, "nothing")
		assert.Equal(t, []string{"admins", "users"}, claims["groups"])
		// Reserved targets are skipped.
		assert.NotContains(t, claims, "email")
		assert.NotContains(t, claims, "sub")
		assert.NotContains(t, claims, "email_verified")
	}

	// ID token.
	ui := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromRequest(ctx, ui, loaded.(*AuthRequest), loaded.GetScopes()))
	assertMapped(t, ui.Claims)
	assert.Equal(t, "alice@example.com", ui.Email, "standard email is untouched by the hostile mapping")
	assert.True(t, bool(ui.EmailVerified))

	// Userinfo from the access token.
	accessToken, _, err := s.CreateAccessToken(ctx, loaded)
	require.NoError(t, err)
	ui2 := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, ui2, accessToken, "cognito-sub-alice", ""))
	assertMapped(t, ui2.Claims)

	// JWT access-token private claims.
	priv, err := s.GetPrivateClaimsFromRequest(ctx, loaded, []string{"openid"})
	require.NoError(t, err)
	assertMapped(t, priv)

	// Deprecated scope-based hook contributes nothing.
	legacy, err := s.GetPrivateClaimsFromScopes(ctx, "cognito-sub-alice", clientID, []string{"openid"})
	require.NoError(t, err)
	assert.Nil(t, legacy)
}

// TestClaimMappings_NoneConfigured: an app without mappings still gets groups
// and nothing else; a subject without groups gets no private claims at all.
func TestClaimMappings_NoneConfigured(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-a/oidc")
	clientID := seedOIDCClient(t, appStore, "tenant-a")

	created, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: clientID, RedirectURI: "https://app.example.com/callback",
		Scopes: oidc.SpaceDelimitedArray{"openid"}, ResponseType: oidc.ResponseTypeCode,
	}, "")
	require.NoError(t, err)
	require.NoError(t, s.CompleteAuthRequest(ctx, created.GetID(), aliceClaims()))
	loaded, err := s.AuthRequestByID(ctx, created.GetID())
	require.NoError(t, err)

	priv, err := s.GetPrivateClaimsFromRequest(ctx, loaded, []string{"openid"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"groups": []string{"admins", "users"}}, priv)

	// No groups → nil.
	ar := loaded.(*AuthRequest)
	ar.CognitoGroups = nil
	priv, err = s.GetPrivateClaimsFromRequest(ctx, ar, []string{"openid"})
	require.NoError(t, err)
	assert.Nil(t, priv)

	// An unrelated request type carries nothing.
	assert.NoError(t, s.SetUserinfoFromRequest(ctx, new(oidc.UserInfo), plainTokenRequest{}, []string{"email"}))
}

// plainTokenRequest is an op.IDTokenRequest of a type the storage does not
// know; it must be ignored rather than mistaken for a claim-bearing request.
type plainTokenRequest struct{}

func (plainTokenRequest) GetAMR() []string       { return nil }
func (plainTokenRequest) GetAudience() []string  { return nil }
func (plainTokenRequest) GetAuthTime() time.Time { return time.Time{} }
func (plainTokenRequest) GetClientID() string    { return "" }
func (plainTokenRequest) GetScopes() []string    { return nil }
func (plainTokenRequest) GetSubject() string     { return "anon" }
