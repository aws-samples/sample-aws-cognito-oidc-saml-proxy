package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestCreateAccessAndRefreshTokens(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "offline_access"},
		ResponseType: oidc.ResponseTypeCode,
	}
	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	accessTokenID, refreshToken, expiration, err := s.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)
	assert.NotEmpty(t, accessTokenID)
	assert.NotEmpty(t, refreshToken)
	assert.False(t, expiration.IsZero())

	// The issued refresh token must be resolvable back to its request.
	rr, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, "test-client", rr.GetClientID())
}

func TestTokenRequestByRefreshToken(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	// An unknown refresh token yields an invalid-grant error.
	_, err := s.TokenRequestByRefreshToken(ctx, "some-refresh-token")
	require.Error(t, err)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

func TestTerminateSession(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	// A session with no outstanding tokens terminates cleanly.
	err := s.TerminateSession(ctx, "user-123", "client-456")
	assert.NoError(t, err)
}

// TestTerminateSession_RevokesTokens is the MF-4 regression: RP-initiated
// logout (end_session → TerminateSession) must actually revoke the outstanding
// access and refresh tokens, not just return nil. Before the fix a refresh
// token stayed valid for up to 30 days after logout and could keep minting
// access tokens.
func TestTerminateSession_RevokesTokens(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	accessToken, refreshToken := issueRefreshToken(t, s, "client-abc")

	// Both tokens are live before logout.
	_, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	userinfo := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, userinfo, accessToken, "user@example.com", ""))

	// End the session for this (user, client).
	require.NoError(t, s.TerminateSession(ctx, "user@example.com", "client-abc"))

	// The refresh token can no longer mint tokens.
	_, err = s.TokenRequestByRefreshToken(ctx, refreshToken)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)

	// The access token is revoked too — userinfo must reject it.
	err = s.SetUserinfoFromToken(ctx, new(oidc.UserInfo), accessToken, "user@example.com", "")
	assert.Error(t, err)
}

// TestTerminateSession_TenantScoped proves the logout sweep is scoped to the
// issuer's tenant: ending a session under a different tenant's issuer must not
// revoke another tenant's tokens, even when the subject and client id collide.
func TestTerminateSession_TenantScoped(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctxA := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-a/oidc")
	ctxB := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-b/oidc")

	// Mint a refresh token for tenant A.
	req := &oidc.AuthRequest{
		ClientID:     "shared-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "offline_access"},
		ResponseType: oidc.ResponseTypeCode,
	}
	authReq, err := s.CreateAuthRequest(ctxA, req, "")
	require.NoError(t, err)
	ar := authReq.(*AuthRequest)
	ar.UserID = "collide@example.com"
	ar.IsDone = true
	ar.AuthTime = time.Now()
	_, refreshToken, _, err := s.CreateAccessAndRefreshTokens(ctxA, ar, "")
	require.NoError(t, err)

	// A logout on tenant B for the same subject+client must not touch tenant A.
	require.NoError(t, s.TerminateSession(ctxB, "collide@example.com", "shared-client"))
	_, err = s.TokenRequestByRefreshToken(ctxA, refreshToken)
	require.NoError(t, err, "tenant B logout must not revoke tenant A's token")

	// The correct tenant's logout does revoke it.
	require.NoError(t, s.TerminateSession(ctxA, "collide@example.com", "shared-client"))
	_, err = s.TokenRequestByRefreshToken(ctxA, refreshToken)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

func TestRevokeToken(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	oidcErr := s.RevokeToken(ctx, "token-id", "user-123", "client-456")
	assert.Nil(t, oidcErr)
}

func TestGetRefreshTokenInfo(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, _, err := s.GetRefreshTokenInfo(ctx, "client-1", "some-token")
	assert.Error(t, err)
}

func TestSetUserinfoFromToken(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	// userinfo requires a live access-token record: mint one first.
	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		ResponseType: oidc.ResponseTypeCode,
	}
	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)
	ar := authReq.(*AuthRequest)
	ar.UserID = "user@example.com"
	ar.IsDone = true
	tokenID, _, err := s.CreateAccessToken(ctx, ar)
	require.NoError(t, err)

	userinfo := new(oidc.UserInfo)
	err = s.SetUserinfoFromToken(ctx, userinfo, tokenID, "user@example.com", "https://origin.example.com")
	require.NoError(t, err)

	assert.Equal(t, "user@example.com", userinfo.Subject)
	assert.Equal(t, "user@example.com", string(userinfo.Email))
}

func TestGetPrivateClaimsFromScopes(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	t.Run("without cached claims", func(t *testing.T) {
		claims, err := s.GetPrivateClaimsFromScopes(ctx, "user-1", "client-1", []string{"openid"})
		require.NoError(t, err)
		assert.Nil(t, claims)
	})

	t.Run("with cached groups", func(t *testing.T) {
		// Store user claims with groups. The lookup derives the tenant from the
		// issuer; a background ctx yields the empty tenant, so key on it here.
		s.userClaims.Store(claimsKey("", "user-with-groups"), &userClaims{
			Email:      "bob@example.com",
			GivenName:  "Bob",
			FamilyName: "Jones",
			Groups:     []string{"developers", "reviewers"},
		})

		claims, err := s.GetPrivateClaimsFromScopes(ctx, "user-with-groups", "client-1", []string{"openid"})
		require.NoError(t, err)
		require.NotNil(t, claims)

		// Verify groups are included as a private claim.
		groups, ok := claims["groups"].([]string)
		require.True(t, ok, "groups claim should be a []string")
		assert.Equal(t, []string{"developers", "reviewers"}, groups)
	})

	t.Run("without groups", func(t *testing.T) {
		// Store user claims without groups (empty tenant to match the ctx issuer).
		s.userClaims.Store(claimsKey("", "user-no-groups"), &userClaims{
			Email:      "carol@example.com",
			GivenName:  "Carol",
			FamilyName: "White",
			Groups:     []string{},
		})

		claims, err := s.GetPrivateClaimsFromScopes(ctx, "user-no-groups", "client-1", []string{"openid"})
		require.NoError(t, err)
		assert.Nil(t, claims, "should return nil when no private claims are present")
	})
}

func TestGetKeyByIDAndClientID(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, err := s.GetKeyByIDAndClientID(ctx, "key-1", "client-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestValidateJWTProfileScopes(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	scopes, err := s.ValidateJWTProfileScopes(ctx, "user-1", []string{"openid", "profile"})
	require.NoError(t, err)
	assert.Equal(t, []string{"openid", "profile"}, scopes)
}

func TestSetIntrospectionFromToken_NotFound(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	resp := new(oidc.IntrospectionResponse)
	err := s.SetIntrospectionFromToken(ctx, resp, "nonexistent-token", "user-1", "client-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token not found")
}

func TestSetIntrospectionFromToken_Found(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	// Create an access token first
	req := &oidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email"},
		ResponseType: oidc.ResponseTypeCode,
	}
	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	// Complete the request by setting a subject
	ar := authReq.(*AuthRequest)
	ar.UserID = "user@example.com"
	ar.IsDone = true

	tokenID, _, err := s.CreateAccessToken(ctx, ar)
	require.NoError(t, err)

	resp := new(oidc.IntrospectionResponse)
	err = s.SetIntrospectionFromToken(ctx, resp, tokenID, "user@example.com", "test-client")
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "user@example.com", resp.Subject)
}

func TestAuthorizeClientIDSecret_ClientNotFound(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	err := s.AuthorizeClientIDSecret(ctx, "nonexistent", "secret")
	assert.Error(t, err)
}

// TestClaimsCacheTenantIsolation verifies that claims cached during one
// tenant's login must not be served on another tenant's issuer path, even when
// the Cognito subject value collides across pools.
func TestClaimsCacheTenantIsolation(t *testing.T) {
	s, _, _, _ := newTestStorage(t)

	const sub = "cognito-sub-collision"
	// Simulate tenant-a completing a login for `sub`.
	s.userClaims.Store(claimsKey("tenant-a", sub), &userClaims{
		Email:         "alice@tenant-a.example.com",
		EmailVerified: true,
		Groups:        []string{"tenant-a-admins"},
	})

	ctxA := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-a/oidc")
	ctxB := op.ContextWithIssuer(context.Background(), "https://idp.example.com/t/tenant-b/oidc")

	// Tenant A sees its own claims.
	uiA := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromScopes(ctxA, uiA, sub, "client-a", []string{"openid", "email"}))
	assert.Equal(t, "alice@tenant-a.example.com", string(uiA.Email))
	assert.True(t, bool(uiA.EmailVerified))

	// Tenant B, with the SAME sub, must NOT read tenant A's claims. The cache
	// misses, so the email falls back to the raw subject and email_verified is
	// false — no cross-tenant contamination.
	uiB := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromScopes(ctxB, uiB, sub, "client-b", []string{"openid", "email"}))
	assert.Equal(t, sub, string(uiB.Email))
	assert.False(t, bool(uiB.EmailVerified))

	// Private (groups) claims are likewise isolated.
	groupsA, err := s.GetPrivateClaimsFromScopes(ctxA, sub, "client-a", []string{"openid"})
	require.NoError(t, err)
	require.NotNil(t, groupsA)
	assert.Equal(t, []string{"tenant-a-admins"}, groupsA["groups"])

	groupsB, err := s.GetPrivateClaimsFromScopes(ctxB, sub, "client-b", []string{"openid"})
	require.NoError(t, err)
	assert.Nil(t, groupsB, "tenant B must not inherit tenant A's groups")
}

// putAccessToken stores an access-token record directly with the given client and
// expiry, bypassing CreateAccessToken so tests can forge expired tokens.
func putAccessToken(t *testing.T, s *Storage, tokenID, subject, clientID string, expiresAt time.Time) {
	t.Helper()
	item := accessTokenItem{
		PK:        oidcAccessTokenPK(tokenID),
		SK:        oidcAccessTokenSK(),
		TokenID:   tokenID,
		Subject:   subject,
		Scopes:    []string{"openid"},
		ClientID:  clientID,
		ExpiresAt: expiresAt,
	}
	require.NoError(t, s.db.Put(context.Background(), &item))
}

// TestExpiredAccessTokenRejected verifies that an expired access token
// must introspect as inactive and must not be served by userinfo (RFC 7662 §2.2).
func TestExpiredAccessTokenRejected(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	const tokenID = "expired-token-id"
	putAccessToken(t, s, tokenID, "user@example.com", "client-a", time.Now().Add(-time.Minute))

	// Introspection: the zitadel/oidc handler forces Active=true on a nil return,
	// so an expired token MUST surface an error (leaving Active=false) and MUST
	// NOT populate identifying fields.
	resp := new(oidc.IntrospectionResponse)
	err := s.SetIntrospectionFromToken(ctx, resp, tokenID, "user@example.com", "client-a")
	require.Error(t, err)
	assert.False(t, resp.Active)
	assert.Empty(t, resp.Subject)
	assert.Empty(t, resp.ClientID)

	// Userinfo must refuse to serve an expired token.
	ui := new(oidc.UserInfo)
	err = s.SetUserinfoFromToken(ctx, ui, tokenID, "user@example.com", "")
	require.Error(t, err)

	// A live token, by contrast, introspects active and userinfo serves it.
	const liveID = "live-token-id"
	putAccessToken(t, s, liveID, "user@example.com", "client-a", time.Now().Add(time.Hour))

	liveResp := new(oidc.IntrospectionResponse)
	require.NoError(t, s.SetIntrospectionFromToken(ctx, liveResp, liveID, "user@example.com", "client-a"))
	assert.True(t, liveResp.Active)
	assert.Equal(t, "user@example.com", liveResp.Subject)

	liveUI := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, liveUI, liveID, "user@example.com", ""))
	assert.Equal(t, "user@example.com", liveUI.Subject)
}

// TestRevokeToken_WrongClientCannotRevoke verifies that a client may
// only revoke its own tokens (RFC 7009 §2.1). Client B presenting client A's
// token must be a no-op that leaves the token intact.
func TestRevokeToken_WrongClientCannotRevoke(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	const tokenID = "client-a-token"
	putAccessToken(t, s, tokenID, "user@example.com", "client-a", time.Now().Add(time.Hour))

	// Client B tries to revoke client A's token: RFC 7009 says treat as
	// already-invalid — return success without deleting another client's token.
	oidcErr := s.RevokeToken(ctx, tokenID, "user@example.com", "client-b")
	assert.Nil(t, oidcErr)

	var still accessTokenItem
	require.NoError(t, s.db.Get(ctx, oidcAccessTokenPK(tokenID), oidcAccessTokenSK(), &still),
		"client B must NOT have deleted client A's token")
	assert.Equal(t, "client-a", still.ClientID)

	// The owning client can revoke it.
	oidcErr = s.RevokeToken(ctx, tokenID, "user@example.com", "client-a")
	assert.Nil(t, oidcErr)

	var gone accessTokenItem
	err := s.db.Get(ctx, oidcAccessTokenPK(tokenID), oidcAccessTokenSK(), &gone)
	assert.Error(t, err, "owning client should have deleted the token")
}

// TestAuthorizeClientIDSecret_EmptyStoredSecretRejected verifies that a
// confidential client (client_secret_basic/post) with an empty stored secret must
// not authenticate with an empty presented secret. ConstantTimeCompare("","")==1
// would otherwise let anyone in.
func TestAuthorizeClientIDSecret_EmptyStoredSecretRejected(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()

	// seedOIDCClient registers a client_secret_basic client with NO stored secret.
	clientID := seedOIDCClient(t, appStore, "tenant-a")

	// Empty presented secret must be rejected (fail closed), not accepted.
	err := s.AuthorizeClientIDSecret(ctx, clientID, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no configured secret")

	// A non-empty guess is also rejected.
	err = s.AuthorizeClientIDSecret(ctx, clientID, "anything")
	assert.Error(t, err)
}
