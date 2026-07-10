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
	ar.CognitoGivenName = "Ada"
	ar.CognitoFamilyName = "Lovelace"
	ar.CognitoGroups = []string{"engineers"}

	accessToken, refreshToken, _, err = s.CreateAccessAndRefreshTokens(ctx, ar, "")
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	return accessToken, refreshToken
}

func TestRefreshToken_IssueAndResolve(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, refreshToken := issueRefreshToken(t, s, "client-abc")

	rr, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, "client-abc", rr.GetClientID())
	assert.Equal(t, "user@example.com", rr.GetSubject())
	assert.Equal(t, []string{"client-abc"}, rr.GetAudience())
	assert.Contains(t, rr.GetScopes(), "offline_access")
	assert.False(t, rr.GetAuthTime().IsZero())
}

func TestRefreshToken_PreservesCognitoClaims(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	accessToken, refreshToken := issueRefreshToken(t, s, "client-abc")

	// Simulate a fresh Lambda invocation with an empty in-memory cache.
	s.userClaims.Range(func(k, _ any) bool {
		s.userClaims.Delete(k)
		return true
	})

	// Resolving the refresh token must repopulate the claims cache so the
	// re-issued ID token / userinfo stays fully populated.
	_, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)

	// userinfo is served against the live access token minted above.
	userinfo := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, userinfo, accessToken, "user@example.com", ""))
	assert.Equal(t, "user@example.com", string(userinfo.Email))
	assert.Equal(t, "Ada", userinfo.GivenName)
	assert.Equal(t, "Lovelace", userinfo.FamilyName)
}

func TestRefreshToken_RotationRevokesOld(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, oldToken := issueRefreshToken(t, s, "client-abc")

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
	assert.Equal(t, "client-abc", rr2.GetClientID())
}

func TestRefreshToken_RotationCarriesClaimsForward(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, oldToken := issueRefreshToken(t, s, "client-abc")
	rr, err := s.TokenRequestByRefreshToken(ctx, oldToken)
	require.NoError(t, err)
	newAccessToken, newToken, _, err := s.CreateAccessAndRefreshTokens(ctx, rr.(*refreshTokenRequest), oldToken)
	require.NoError(t, err)

	// Clear cache to prove the claims came from the persisted rotated token.
	s.userClaims.Range(func(k, _ any) bool {
		s.userClaims.Delete(k)
		return true
	})

	_, err = s.TokenRequestByRefreshToken(ctx, newToken)
	require.NoError(t, err)

	// userinfo is served against the live access token minted by the rotation.
	userinfo := new(oidc.UserInfo)
	require.NoError(t, s.SetUserinfoFromToken(ctx, userinfo, newAccessToken, "user@example.com", ""))
	assert.Equal(t, "Ada", userinfo.GivenName)
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
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, refreshToken := issueRefreshToken(t, s, "client-abc")

	t.Run("valid token", func(t *testing.T) {
		subject, tokenID, err := s.GetRefreshTokenInfo(ctx, "client-abc", refreshToken)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", subject)
		assert.Equal(t, refreshToken, tokenID)
	})

	t.Run("client mismatch", func(t *testing.T) {
		_, _, err := s.GetRefreshTokenInfo(ctx, "other-client", refreshToken)
		assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	})

	t.Run("unknown token", func(t *testing.T) {
		_, _, err := s.GetRefreshTokenInfo(ctx, "client-abc", "nope")
		assert.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	})
}

func TestRefreshToken_Revoke(t *testing.T) {
	s, _, _, _ := newTestStorage(t)
	ctx := context.Background()

	_, refreshToken := issueRefreshToken(t, s, "client-abc")

	oidcErr := s.RevokeToken(ctx, refreshToken, "user@example.com", "client-abc")
	assert.Nil(t, oidcErr)

	// After revocation the token is no longer resolvable.
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
