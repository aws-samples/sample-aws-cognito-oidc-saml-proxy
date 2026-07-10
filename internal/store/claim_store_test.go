package store

import (
	"context"
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimStore_PutAndGetClaimMappings(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewClaimStore(ms, "test-table")

	mappings := []tenant.ClaimMapping{
		{Name: "email", SourceType: "jwt", SourceAttribute: "email", TargetAttribute: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Required: true},
		{Name: "name", SourceType: "jwt", SourceAttribute: "name", TargetAttribute: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", Required: false, DefaultValue: "Unknown"},
	}

	require.NoError(t, s.PutClaimMappings(ctx, "acme", "app-1", mappings))

	got, err := s.GetClaimMappings(ctx, "acme", "app-1")
	require.NoError(t, err)
	require.Len(t, got, 2)

	names := map[string]tenant.ClaimMapping{}
	for _, m := range got {
		names[m.Name] = m
	}

	assert.Equal(t, "email", names["email"].SourceAttribute)
	assert.True(t, names["email"].Required)
	assert.Equal(t, "Unknown", names["name"].DefaultValue)
}

func TestClaimStore_PutClaimMappings_ReplaceExisting(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewClaimStore(ms, "test-table")

	// Write initial.
	initial := []tenant.ClaimMapping{
		{Name: "email", SourceType: "jwt", SourceAttribute: "email", TargetAttribute: "email", Required: true},
		{Name: "role", SourceType: "jwt", SourceAttribute: "cognito:groups", TargetAttribute: "role", Required: false},
	}
	require.NoError(t, s.PutClaimMappings(ctx, "acme", "app-1", initial))

	// Replace with different set.
	replacement := []tenant.ClaimMapping{
		{Name: "sub", SourceType: "jwt", SourceAttribute: "sub", TargetAttribute: "nameId", Required: true},
	}
	require.NoError(t, s.PutClaimMappings(ctx, "acme", "app-1", replacement))

	got, err := s.GetClaimMappings(ctx, "acme", "app-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "sub", got[0].Name)
}

func TestClaimStore_PutAndGetRoleMappings(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewClaimStore(ms, "test-table")

	mappings := []tenant.RoleMapping{
		{CognitoGroup: "admins", MappedValue: "arn:aws:iam::111122223333:role/Admin"},
		{CognitoGroup: "editors", MappedValue: "arn:aws:iam::111122223333:role/Editor"},
	}

	require.NoError(t, s.PutRoleMappings(ctx, "acme", "app-1", mappings))

	got, err := s.GetRoleMappings(ctx, "acme", "app-1")
	require.NoError(t, err)
	require.Len(t, got, 2)

	groups := map[string]string{}
	for _, m := range got {
		groups[m.CognitoGroup] = m.MappedValue
	}
	assert.Equal(t, "arn:aws:iam::111122223333:role/Admin", groups["admins"])
	assert.Equal(t, "arn:aws:iam::111122223333:role/Editor", groups["editors"])
}

func TestClaimStore_PutRoleMappings_ReplaceExisting(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewClaimStore(ms, "test-table")

	initial := []tenant.RoleMapping{
		{CognitoGroup: "admins", MappedValue: "admin-role"},
		{CognitoGroup: "users", MappedValue: "user-role"},
	}
	require.NoError(t, s.PutRoleMappings(ctx, "acme", "app-1", initial))

	replacement := []tenant.RoleMapping{
		{CognitoGroup: "viewers", MappedValue: "viewer-role"},
	}
	require.NoError(t, s.PutRoleMappings(ctx, "acme", "app-1", replacement))

	got, err := s.GetRoleMappings(ctx, "acme", "app-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "viewers", got[0].CognitoGroup)
}

func TestClaimStore_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewClaimStore(ms, "test-table")

	claimsA := []tenant.ClaimMapping{
		{Name: "email-a", SourceType: "jwt", SourceAttribute: "email", TargetAttribute: "email", Required: true},
	}
	claimsB := []tenant.ClaimMapping{
		{Name: "email-b", SourceType: "jwt", SourceAttribute: "email", TargetAttribute: "mail", Required: false},
	}

	require.NoError(t, s.PutClaimMappings(ctx, "tenant-a", "app-1", claimsA))
	require.NoError(t, s.PutClaimMappings(ctx, "tenant-b", "app-1", claimsB))

	gotA, err := s.GetClaimMappings(ctx, "tenant-a", "app-1")
	require.NoError(t, err)
	require.Len(t, gotA, 1)
	assert.Equal(t, "email-a", gotA[0].Name)

	gotB, err := s.GetClaimMappings(ctx, "tenant-b", "app-1")
	require.NoError(t, err)
	require.Len(t, gotB, 1)
	assert.Equal(t, "email-b", gotB[0].Name)

	// Role mappings isolation.
	rolesA := []tenant.RoleMapping{{CognitoGroup: "group-a", MappedValue: "role-a"}}
	rolesB := []tenant.RoleMapping{{CognitoGroup: "group-b", MappedValue: "role-b"}}
	require.NoError(t, s.PutRoleMappings(ctx, "tenant-a", "app-1", rolesA))
	require.NoError(t, s.PutRoleMappings(ctx, "tenant-b", "app-1", rolesB))

	gotRA, err := s.GetRoleMappings(ctx, "tenant-a", "app-1")
	require.NoError(t, err)
	require.Len(t, gotRA, 1)
	assert.Equal(t, "group-a", gotRA[0].CognitoGroup)

	gotRB, err := s.GetRoleMappings(ctx, "tenant-b", "app-1")
	require.NoError(t, err)
	require.Len(t, gotRB, 1)
	assert.Equal(t, "group-b", gotRB[0].CognitoGroup)
}

func TestClaimStore_EmptyMappings(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewClaimStore(ms, "test-table")

	claims, err := s.GetClaimMappings(ctx, "acme", "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, claims)

	roles, err := s.GetRoleMappings(ctx, "acme", "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestClaimStore_AppIsolation(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewClaimStore(ms, "test-table")

	// Same tenant, different apps.
	claims1 := []tenant.ClaimMapping{
		{Name: "email", SourceType: "jwt", SourceAttribute: "email", TargetAttribute: "email", Required: true},
	}
	claims2 := []tenant.ClaimMapping{
		{Name: "sub", SourceType: "jwt", SourceAttribute: "sub", TargetAttribute: "nameId", Required: true},
	}

	require.NoError(t, s.PutClaimMappings(ctx, "acme", "app-1", claims1))
	require.NoError(t, s.PutClaimMappings(ctx, "acme", "app-2", claims2))

	got1, err := s.GetClaimMappings(ctx, "acme", "app-1")
	require.NoError(t, err)
	require.Len(t, got1, 1)
	assert.Equal(t, "email", got1[0].Name)

	got2, err := s.GetClaimMappings(ctx, "acme", "app-2")
	require.NoError(t, err)
	require.Len(t, got2, 1)
	assert.Equal(t, "sub", got2[0].Name)
}
