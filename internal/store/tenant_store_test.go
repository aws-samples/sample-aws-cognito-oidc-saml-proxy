package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantStore_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	tn := &tenant.Tenant{
		Slug:             "acme",
		DisplayName:      "Acme Corp",
		Plan:             "pro",
		Domain:           "acme.example.com",
		Status:           "active",
		MaxApps:          10,
		MaxAuthsPerMonth: 10000,
	}

	err := s.Create(ctx, tn)
	require.NoError(t, err)

	got, err := s.Get(ctx, "acme")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "acme", got.Slug)
	assert.Equal(t, "Acme Corp", got.DisplayName)
	assert.Equal(t, "pro", got.Plan)
	assert.Equal(t, "acme.example.com", got.Domain)
	assert.Equal(t, "active", got.Status)
	assert.Equal(t, 10, got.MaxApps)
	assert.Equal(t, 10000, got.MaxAuthsPerMonth)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestTenantStore_CreateDuplicateFails(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	tn := &tenant.Tenant{Slug: "dup", DisplayName: "Dup", Plan: "free", Status: "active"}
	require.NoError(t, s.Create(ctx, tn))

	tn2 := &tenant.Tenant{Slug: "dup", DisplayName: "Dup2", Plan: "free", Status: "active"}
	err := s.Create(ctx, tn2)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantExists)

	// The first tenant's config must be intact — a duplicate Create must not
	// overwrite it.
	got, err := s.Get(ctx, "dup")
	require.NoError(t, err)
	assert.Equal(t, "Dup", got.DisplayName)
}

// TestTenantStore_CreateIsAtomic is the MF-10 regression: Create must enforce
// slug uniqueness with a single atomic conditional write, not a
// read-then-write. Many concurrent Creates for the same slug must yield exactly
// one winner; every loser must observe ErrTenantExists, and the winner's config
// must survive untouched (no last-writer-wins overwrite of RoleArn/PoolID/etc.).
func TestTenantStore_CreateIsAtomic(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	const n = 25
	var wg sync.WaitGroup
	results := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each racer proposes a DISTINCT config for the same slug, so a
			// non-atomic overwrite would be observable in the surviving row.
			tn := &tenant.Tenant{
				Slug:        "race",
				DisplayName: fmt.Sprintf("Racer-%d", i),
				Plan:        "free",
				Status:      "active",
				MaxApps:     i + 1,
			}
			<-start
			results[i] = s.Create(ctx, tn)
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
			continue
		}
		assert.ErrorIs(t, err, ErrTenantExists, "a losing Create must fail with ErrTenantExists, never fail open")
	}
	assert.Equal(t, 1, winners, "exactly one concurrent Create must win")

	// Exactly one row exists.
	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "race", list[0].Slug)
}

func TestTenantStore_List(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	require.NoError(t, s.Create(ctx, &tenant.Tenant{Slug: "t1", DisplayName: "T1", Plan: "free", Status: "active"}))
	require.NoError(t, s.Create(ctx, &tenant.Tenant{Slug: "t2", DisplayName: "T2", Plan: "pro", Status: "active"}))
	require.NoError(t, s.Create(ctx, &tenant.Tenant{Slug: "t3", DisplayName: "T3", Plan: "enterprise", Status: "active"}))

	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 3)

	slugs := map[string]bool{}
	for _, tn := range list {
		slugs[tn.Slug] = true
	}
	assert.True(t, slugs["t1"])
	assert.True(t, slugs["t2"])
	assert.True(t, slugs["t3"])
}

func TestTenantStore_Update(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	tn := &tenant.Tenant{Slug: "upd", DisplayName: "Original", Plan: "free", Status: "active"}
	require.NoError(t, s.Create(ctx, tn))

	original, err := s.Get(ctx, "upd")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	tn.DisplayName = "Updated"
	tn.Plan = "pro"
	require.NoError(t, s.Update(ctx, tn))

	updated, err := s.Get(ctx, "upd")
	require.NoError(t, err)
	assert.Equal(t, "Updated", updated.DisplayName)
	assert.Equal(t, "pro", updated.Plan)
	assert.Equal(t, original.CreatedAt, updated.CreatedAt)
	assert.True(t, updated.UpdatedAt.After(original.UpdatedAt))
}

func TestTenantStore_GetNotFound(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	_, err := s.Get(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTenantStore_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	require.NoError(t, s.Create(ctx, &tenant.Tenant{Slug: "iso-a", DisplayName: "Tenant A", Plan: "pro", Status: "active"}))
	require.NoError(t, s.Create(ctx, &tenant.Tenant{Slug: "iso-b", DisplayName: "Tenant B", Plan: "free", Status: "active"}))

	a, err := s.Get(ctx, "iso-a")
	require.NoError(t, err)
	assert.Equal(t, "Tenant A", a.DisplayName)

	b, err := s.Get(ctx, "iso-b")
	require.NoError(t, err)
	assert.Equal(t, "Tenant B", b.DisplayName)

	// Slug-based lookup is inherently isolated — verify they don't interfere.
	assert.NotEqual(t, a.DisplayName, b.DisplayName)
}

func TestTenantStore_OnboardingFieldsRoundtrip(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	tt := &tenant.Tenant{
		Slug:             "acme",
		DisplayName:      "Acme Inc",
		Plan:             "standard",
		Status:           "pending",
		MaxApps:          10,
		MaxAuthsPerMonth: 10000,
		OnboardingState:  "in_progress",
		CapabilityMap:    map[string]bool{"core": true, "user_directory": false},
	}

	require.NoError(t, s.Create(ctx, tt))

	got, err := s.Get(ctx, "acme")
	require.NoError(t, err)

	assert.Equal(t, "in_progress", got.OnboardingState)
	assert.Equal(t, true, got.CapabilityMap["core"])
	assert.Equal(t, false, got.CapabilityMap["user_directory"])
	_, userLifecycleKeyExists := got.CapabilityMap["user_lifecycle"]
	assert.False(t, userLifecycleKeyExists, "unset capability keys should be absent from the map")
}

func TestTenantStore_LegacyTenantHasEmptyOnboardingFields(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	// Legacy tenant seeded by Terraform has no onboarding fields.
	tt := &tenant.Tenant{Slug: "legacy", DisplayName: "Legacy", Plan: "standard", Status: "active"}
	require.NoError(t, s.Create(ctx, tt))

	got, err := s.Get(ctx, "legacy")
	require.NoError(t, err)

	assert.Empty(t, got.OnboardingState)
	assert.Nil(t, got.CapabilityMap, "nil map = all capabilities enabled per spec")
}

func TestTenantStore_Delete(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	require.NoError(t, s.Create(ctx, &tenant.Tenant{Slug: "acme", DisplayName: "Acme", Status: "active"}))

	require.NoError(t, s.Delete(ctx, "acme"))

	_, err := s.Get(ctx, "acme")
	assert.Error(t, err, "tenant should be gone after delete")
}

func TestTenantStore_EnsureTenant_Idempotent(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewTenantStore(ms, "test-table")

	def := tenant.NewDefaultTenant()
	require.NoError(t, s.EnsureTenant(ctx, def))

	// Mutate and persist so we can prove a second Ensure does not overwrite it.
	got, err := s.Get(ctx, tenant.DefaultSlug)
	require.NoError(t, err)
	got.DisplayName = "Renamed"
	require.NoError(t, s.Update(ctx, got))

	// Second Ensure is a no-op — the edited tenant is preserved.
	require.NoError(t, s.EnsureTenant(ctx, tenant.NewDefaultTenant()))
	after, err := s.Get(ctx, tenant.DefaultSlug)
	require.NoError(t, err)
	assert.Equal(t, "Renamed", after.DisplayName)
}
