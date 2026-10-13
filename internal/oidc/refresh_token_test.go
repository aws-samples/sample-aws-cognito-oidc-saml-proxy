package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// issueRefreshToken performs the initial authorization-code exchange path:
// completes an auth request with Cognito claims, then mints an access +
// refresh token pair. Returns the access token ID and the refresh token.
func issueRefreshToken(t *testing.T, s *Storage, clientID string) (accessToken, refreshToken string) {
	t.Helper()
	ctx := context.Background()

	req := &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       oidc.SpaceDelimitedArray{"openid", "email", "profile", "offline_access"},
		ResponseType: oidc.ResponseTypeCode,
	}
	authReq, err := s.CreateAuthRequest(ctx, req, "")
	require.NoError(t, err)

	ar := authReq.(*AuthRequest)
	ar.UserID = "user@example.com"
	ar.IsDone = true
	ar.AuthTime = time.Now()
	ar.CognitoEmail = "user@example.com"
	ar.CognitoEmailVerified = true
	ar.CognitoGivenName = "Ada"
	ar.CognitoFamilyName = "Lovelace"
	ar.CognitoGroups = []string{"engineers"}
	ar.CognitoCustomAttributes = map[string]string{"department": "maths"}

	accessToken, refreshToken, _, err = s.CreateAccessAndRefreshTokens(ctx, ar, "")
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	return accessToken, refreshToken
}

func TestRefreshToken_IssueAndResolve(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	_, refreshToken := issueRefreshToken(t, s, clientID)

	rr, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, clientID, rr.GetClientID())
	assert.Equal(t, "user@example.com", rr.GetSubject())
	assert.Equal(t, []string{clientID}, rr.GetAudience())
	assert.Contains(t, rr.GetScopes(), "offline_access")
	assert.False(t, rr.GetAuthTime().IsZero())
}

func TestRefreshToken_PreservesCognitoClaims(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	accessToken, refreshToken := issueRefreshToken(t, s, clientID)

	// The refresh request rebuilt from the stored item carries the full claim
	// set, so the re-issued ID token is populated without any process state.
	rr, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	rtr := rr.(*refreshTokenRequest)
	assert.Equal(t, SubjectClaims{
		Sub:              "user@example.com",
		Email:            "user@example.com",
		EmailVerified:    true,
		GivenName:        "Ada",
		FamilyName:       "Lovelace",
		Groups:           []string{"engineers"},
		CustomAttributes: map[string]string{"department": "maths"},
	}, rtr.claims)

	idTokenInfo := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromRequest(ctx, idTokenInfo, rtr, rr.GetScopes()))
	assert.Equal(t, "user@example.com", idTokenInfo.Email)
	assert.True(t, bool(idTokenInfo.EmailVerified))
	assert.Equal(t, "Ada", idTokenInfo.GivenName)
	assert.Equal(t, []string{"engineers"}, idTokenInfo.Claims["groups"])

	// userinfo is served against the live access token minted above, from the
	// claims persisted on that record.
	userinfo := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, userinfo, accessToken, "user@example.com", ""))
	assert.Equal(t, "user@example.com", string(userinfo.Email))
	assert.True(t, bool(userinfo.EmailVerified))
	assert.Equal(t, "Ada", userinfo.GivenName)
	assert.Equal(t, "Lovelace", userinfo.FamilyName)
	assert.Equal(t, []string{"engineers"}, userinfo.Claims["groups"])
}

func TestRefreshToken_RotationRevokesOld(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	_, oldToken := issueRefreshToken(t, s, clientID)

	// Resolve the original request, then rotate (as the token endpoint does).
	rr, err := s.TokenRequestByRefreshToken(ctx, oldToken)
	require.NoError(t, err)

	_, newToken, _, err := s.CreateAccessAndRefreshTokens(ctx, rr.(*refreshTokenRequest), oldToken)
	require.NoError(t, err)
	require.NotEmpty(t, newToken)
	assert.NotEqual(t, oldToken, newToken)

	// Old token is now invalid (single-use rotation).
	_, err = s.TokenRequestByRefreshToken(ctx, oldToken)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)

	// New token still works and preserves claims/subject.
	rr2, err := s.TokenRequestByRefreshToken(ctx, newToken)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", rr2.GetSubject())
	assert.Equal(t, clientID, rr2.GetClientID())
}

func TestRefreshToken_RotationCarriesClaimsForward(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	_, oldToken := issueRefreshToken(t, s, clientID)
	rr, err := s.TokenRequestByRefreshToken(ctx, oldToken)
	require.NoError(t, err)
	newAccessToken, newToken, _, err := s.CreateAccessAndRefreshTokens(ctx, rr.(*refreshTokenRequest), oldToken)
	require.NoError(t, err)

	// The rotated refresh token record carries the claims forward.
	rr2, err := s.TokenRequestByRefreshToken(ctx, newToken)
	require.NoError(t, err)
	assert.Equal(t, rr.(*refreshTokenRequest).claims, rr2.(*refreshTokenRequest).claims)

	// userinfo is served against the live access token minted by the rotation.
	userinfo := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, userinfo, newAccessToken, "user@example.com", ""))
	assert.Equal(t, "user@example.com", userinfo.Email)
	assert.Equal(t, "Ada", userinfo.GivenName)
	assert.Equal(t, []string{"engineers"}, userinfo.Claims["groups"])
}

func TestRefreshToken_Expired(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	// Store an already-expired refresh token directly.
	expired := refreshTokenItem{
		PK:        oidcRefreshTokenPK("expired-token"),
		SK:        oidcRefreshTokenSK(),
		Token:     "expired-token",
		Subject:   "user@example.com",
		ClientID:  "client-abc",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, s.db.Put(ctx, &expired))

	_, err := s.TokenRequestByRefreshToken(ctx, "expired-token")
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

func TestRefreshToken_GetRefreshTokenInfo(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	_, refreshToken := issueRefreshToken(t, s, clientID)

	t.Run("valid token", func(t *testing.T) {
		subject, tokenID, err := s.GetRefreshTokenInfo(ctx, clientID, refreshToken)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", subject)
		assert.Equal(t, refreshToken, tokenID)
	})

	t.Run("client mismatch", func(t *testing.T) {
		_, _, err := s.GetRefreshTokenInfo(ctx, "other-client", refreshToken)
		assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	})

	t.Run("unknown token", func(t *testing.T) {
		_, _, err := s.GetRefreshTokenInfo(ctx, clientID, "nope")
		assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	})
}

func TestRefreshToken_Revoke(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	_, refreshToken := issueRefreshToken(t, s, clientID)

	oidcErr := s.RevokeToken(ctx, refreshToken, "user@example.com", clientID)
	assert.Nil(t, oidcErr)

	// After revocation the token is no longer resolvable.
	_, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

// TestRefreshToken_DisabledAppRejected is the M-5 regression: a refresh token
// issued while the application was active must stop working the moment the
// app is disabled, and the stored token must be dropped so re-enabling the app
// does not resurrect it.
func TestRefreshToken_DisabledAppRejected(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, appStore, "test-tenant")

	_, refreshToken := issueRefreshToken(t, s, clientID)
	_, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)

	require.NoError(t, appStore.SetStatus(ctx, "test-tenant", clientID, "disabled"))

	_, err = s.TokenRequestByRefreshToken(ctx, refreshToken)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)

	// Re-enabling the app must not bring the token back.
	require.NoError(t, appStore.SetStatus(ctx, "test-tenant", clientID, "active"))
	_, err = s.TokenRequestByRefreshToken(ctx, refreshToken)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

// TestRefreshToken_DeletedAppRejected covers the sibling case where the owning
// application no longer exists at all.
func TestRefreshToken_DeletedAppRejected(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, refreshToken := issueRefreshToken(t, s, "no-such-client")

	_, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

func TestRefreshToken_PerClientLifetimeOverride(t *testing.T) {
	s, appStore, _, _ := newTestStorage(t)
	ctx := context.Background()

	// Register an app/client with a short refresh-token lifetime override.
	appID, err := appStore.Create(ctx, "test", &tenant.Application{
		DisplayName: "rt-app",
		Protocol:    "oidc",
	}, nil)
	require.NoError(t, err)
	require.NoError(t, appStore.UpdateOIDCConfig(ctx, "test", appID, &tenant.OIDCConfig{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "offline_access"},
		RefreshTokenLifetimeSec: 60,
	}))

	got := s.refreshTokenLifetime(ctx, appID)
	assert.Equal(t, 60*time.Second, got)

	// Unknown client falls back to the default.
	assert.Equal(t, defaultRefreshTokenLifetime, s.refreshTokenLifetime(ctx, "unknown-client"))
}
