package store

import (
	"context"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSource() *tenant.IdentitySource {
	return &tenant.IdentitySource{
		DisplayName: "Main Pool",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Domain:      "auth.example.com",
		ClientID:    "client-id-123",
		Status:      "active",
	}
}

func TestSourceStore_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	src := newTestSource()
	id, err := s.Create(ctx, "acme", src)
	require.NoError(t, err)
	require.NotEmpty(t, id)
	assert.Equal(t, id, src.ID)

	got, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, id, got.ID)
	assert.Equal(t, "acme", got.TenantSlug)
	assert.Equal(t, "Main Pool", got.DisplayName)
	assert.Equal(t, "cognito", got.Type)
	assert.Equal(t, "eu-north-1_abc123", got.PoolID)
	assert.Equal(t, "eu-north-1", got.Region)
	assert.Equal(t, "auth.example.com", got.Domain)
	assert.Equal(t, "client-id-123", got.ClientID)
	assert.Equal(t, "active", got.Status)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestSourceStore_List(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	src1 := &tenant.IdentitySource{DisplayName: "Pool 1", Type: "cognito", PoolID: "p1", Region: "eu-north-1", Domain: "d1", ClientID: "c1", Status: "active"}
	src2 := &tenant.IdentitySource{DisplayName: "Pool 2", Type: "cognito", PoolID: "p2", Region: "eu-north-1", Domain: "d2", ClientID: "c2", Status: "active"}

	_, err := s.Create(ctx, "acme", src1)
	require.NoError(t, err)
	_, err = s.Create(ctx, "acme", src2)
	require.NoError(t, err)

	list, err := s.List(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, list, 2)

	names := map[string]bool{}
	for _, src := range list {
		names[src.DisplayName] = true
	}
	assert.True(t, names["Pool 1"])
	assert.True(t, names["Pool 2"])
}

func TestSourceStore_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	srcA := &tenant.IdentitySource{DisplayName: "A Pool", Type: "cognito", PoolID: "pa", Region: "eu-north-1", Domain: "da", ClientID: "ca", Status: "active"}
	srcB := &tenant.IdentitySource{DisplayName: "B Pool", Type: "cognito", PoolID: "pb", Region: "eu-north-1", Domain: "db", ClientID: "cb", Status: "active"}

	idA, err := s.Create(ctx, "tenant-a", srcA)
	require.NoError(t, err)
	idB, err := s.Create(ctx, "tenant-b", srcB)
	require.NoError(t, err)

	// Tenant A can see its own source.
	gotA, err := s.Get(ctx, "tenant-a", idA)
	require.NoError(t, err)
	assert.Equal(t, "A Pool", gotA.DisplayName)

	// Tenant A cannot see tenant B's source.
	_, err = s.Get(ctx, "tenant-a", idB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Tenant B cannot see tenant A's source.
	_, err = s.Get(ctx, "tenant-b", idA)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// List is scoped to tenant.
	listA, err := s.List(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Len(t, listA, 1)
	assert.Equal(t, "A Pool", listA[0].DisplayName)

	listB, err := s.List(ctx, "tenant-b")
	require.NoError(t, err)
	assert.Len(t, listB, 1)
	assert.Equal(t, "B Pool", listB[0].DisplayName)
}

func TestSourceStore_Update(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	src := newTestSource()
	id, err := s.Create(ctx, "acme", src)
	require.NoError(t, err)

	original, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	src.DisplayName = "Updated Pool"
	require.NoError(t, s.Update(ctx, "acme", src))

	updated, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)
	assert.Equal(t, "Updated Pool", updated.DisplayName)
	assert.Equal(t, original.CreatedAt, updated.CreatedAt)
	assert.True(t, updated.UpdatedAt.After(original.UpdatedAt))
}

func TestSourceStore_Delete(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	src := newTestSource()
	id, err := s.Create(ctx, "acme", src)
	require.NoError(t, err)

	// Verify it exists.
	_, err = s.Get(ctx, "acme", id)
	require.NoError(t, err)

	// Delete.
	require.NoError(t, s.Delete(ctx, "acme", id))

	// Verify gone.
	_, err = s.Get(ctx, "acme", id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSourceStore_DeleteNotFound(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	err := s.Delete(ctx, "acme", "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSourceStore_CrossAccountFieldsRoundtrip(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	src := &tenant.IdentitySource{
		DisplayName: "Managed Pool",
		Type:        "cognito",
		PoolID:      "eu-north-1_xyz999",
		Region:      "eu-north-1",
		Domain:      "auth.example.com",
		ClientID:    "client-id-999",
		Status:      "active",
		RoleArn:     "arn:aws:iam::123456789012:role/identity-gateway-acme",
		ExternalID:  "EXT-ID-ABCDEF0123456789",
		SecretArn:   "arn:aws:secretsmanager:eu-north-1:123456789012:secret:cognito-client-secret-xyz-AB12CD",
	}

	id, err := s.Create(ctx, "acme", src)
	require.NoError(t, err)

	got, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)

	assert.Equal(t, "arn:aws:iam::123456789012:role/identity-gateway-acme", got.RoleArn)
	assert.Equal(t, "EXT-ID-ABCDEF0123456789", got.ExternalID)
	assert.Equal(t, "arn:aws:secretsmanager:eu-north-1:123456789012:secret:cognito-client-secret-xyz-AB12CD", got.SecretArn)
}

func TestSourceStore_LegacySourceHasEmptyCrossAccountFields(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewSourceStore(ms, "test-table")

	// Legacy sources (created before the wizard) have no cross-account fields.
	src := newTestSource()
	id, err := s.Create(ctx, "acme", src)
	require.NoError(t, err)

	got, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)

	assert.Empty(t, got.RoleArn, "legacy sources must have empty RoleArn")
	assert.Empty(t, got.ExternalID, "legacy sources must have empty ExternalID")
	assert.Empty(t, got.SecretArn, "legacy sources must have empty SecretArn")
}
