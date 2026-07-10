package store

import (
	"context"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnboardingStateStore_PutAndGet(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewOnboardingStateStore(ms, "test-table")

	state := &domain.OnboardingState{
		TenantSlug:   "acme",
		CurrentStep:  2,
		Capabilities: []string{"core", "user_directory"},
		ExternalID:   "EXT-abc123",
		IaCVersion:   1,
	}
	require.NoError(t, s.Put(ctx, state))

	got, err := s.Get(ctx, "acme")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "acme", got.TenantSlug)
	assert.Equal(t, 2, got.CurrentStep)
	assert.Equal(t, []string{"core", "user_directory"}, got.Capabilities)
	assert.Equal(t, "EXT-abc123", got.ExternalID)
	assert.Equal(t, 1, got.IaCVersion)
	assert.False(t, got.UpdatedAt.IsZero(), "Put must set UpdatedAt")
}

func TestOnboardingStateStore_GetMissingReturnsError(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewOnboardingStateStore(ms, "test-table")

	_, err := s.Get(ctx, "nonexistent")
	require.Error(t, err)
}

func TestOnboardingStateStore_Delete(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewOnboardingStateStore(ms, "test-table")

	state := &domain.OnboardingState{TenantSlug: "acme", CurrentStep: 1}
	require.NoError(t, s.Put(ctx, state))

	require.NoError(t, s.Delete(ctx, "acme"))

	_, err := s.Get(ctx, "acme")
	require.Error(t, err, "deleted state must not be retrievable")
}

func TestOnboardingStateStore_PutUpdatesTimestamp(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewOnboardingStateStore(ms, "test-table")

	state := &domain.OnboardingState{TenantSlug: "acme", CurrentStep: 1}
	require.NoError(t, s.Put(ctx, state))
	first, err := s.Get(ctx, "acme")
	require.NoError(t, err)

	time.Sleep(2 * time.Millisecond)

	state.CurrentStep = 2
	require.NoError(t, s.Put(ctx, state))
	second, err := s.Get(ctx, "acme")
	require.NoError(t, err)

	assert.True(t, second.UpdatedAt.After(first.UpdatedAt), "Put must advance UpdatedAt")
	assert.Equal(t, 2, second.CurrentStep)
}

func TestOnboardingStateStore_IsolatedByTenant(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewOnboardingStateStore(ms, "test-table")

	require.NoError(t, s.Put(ctx, &domain.OnboardingState{TenantSlug: "acme", CurrentStep: 1}))
	require.NoError(t, s.Put(ctx, &domain.OnboardingState{TenantSlug: "beta", CurrentStep: 5}))

	acme, err := s.Get(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, 1, acme.CurrentStep)

	beta, err := s.Get(ctx, "beta")
	require.NoError(t, err)
	assert.Equal(t, 5, beta.CurrentStep)
}
