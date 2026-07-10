package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func newTestAuthRequest() *AuthRequest {
	return &AuthRequest{
		ID:           "req-001",
		ClientID:     "client-abc",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "profile"},
		State:        "state-xyz",
		Nonce:        "nonce-123",
		ResponseType: oidc.ResponseTypeCode,
		ResponseMode: "query",
		AuthTime:     time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC),
		UserID:       "user-789",
		IsDone:       false,
	}
}

func TestAuthRequest_GetACR(t *testing.T) {
	ar := newTestAuthRequest()
	assert.Equal(t, "0", ar.GetACR())
}

func TestAuthRequest_GetAMR(t *testing.T) {
	ar := newTestAuthRequest()
	assert.Equal(t, []string{"pwd"}, ar.GetAMR())
}

func TestAuthRequest_GetAuthTime(t *testing.T) {
	ar := newTestAuthRequest()
	expected := time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, ar.GetAuthTime())
}

func TestAuthRequest_GetResponseMode(t *testing.T) {
	ar := newTestAuthRequest()
	assert.Equal(t, oidc.ResponseMode("query"), ar.GetResponseMode())
}

func TestAuthRequest_Done(t *testing.T) {
	ar := newTestAuthRequest()
	assert.False(t, ar.Done())

	ar.IsDone = true
	assert.True(t, ar.Done())
}
