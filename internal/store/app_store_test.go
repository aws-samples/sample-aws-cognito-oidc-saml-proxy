package store

import (
	"context"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestApp() *tenant.Application {
	return &tenant.Application{
		DisplayName: "My SAML App",
		Protocol:    "saml",
		SourceID:    "src-123",
		Status:      "active",
	}
}

func newTestSAMLConfig() *tenant.SAMLConfig {
	return &tenant.SAMLConfig{
		EntityID:           "https://app.example.com/saml",
		AcsURL:             "https://app.example.com/saml/acs",
		AcsURLs:            []string{"https://app.example.com/saml/acs"},
		MetadataURL:        "https://app.example.com/saml/metadata",
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:       "email",
		SignResponse:       true,
		SignAssertion:      true,
		EncryptAssertion:   false,
		SessionDurationSec: 3600,
		ClockSkewSec:       300,
	}
}

func TestAppStore_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()

	id, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)
	require.NotEmpty(t, id)
	assert.Equal(t, id, app.ID)

	got, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, id, got.ID)
	assert.Equal(t, "acme", got.TenantSlug)
	assert.Equal(t, "My SAML App", got.DisplayName)
	assert.Equal(t, "saml", got.Protocol)
	assert.Equal(t, "src-123", got.SourceID)
	assert.Equal(t, "active", got.Status)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestAppStore_GetSAMLConfig(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()

	id, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)

	got, err := s.GetSAMLConfig(ctx, "acme", id)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "https://app.example.com/saml", got.EntityID)
	assert.Equal(t, "https://app.example.com/saml/acs", got.AcsURL)
	assert.Equal(t, []string{"https://app.example.com/saml/acs"}, got.AcsURLs)
	assert.Equal(t, "https://app.example.com/saml/metadata", got.MetadataURL)
	assert.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", got.NameIDFormat)
	assert.Equal(t, "email", got.NameIDSource)
	assert.True(t, got.SignResponse)
	assert.True(t, got.SignAssertion)
	assert.False(t, got.EncryptAssertion)
	assert.Equal(t, 3600, got.SessionDurationSec)
	assert.Equal(t, 300, got.ClockSkewSec)
}

func TestAppStore_GetByTenantEntityID(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()

	id, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)

	gotApp, gotSAML, err := s.GetByTenantEntityID(ctx, "acme", "https://app.example.com/saml")
	require.NoError(t, err)
	assert.Equal(t, id, gotApp.ID)
	assert.Equal(t, "My SAML App", gotApp.DisplayName)
	require.NotNil(t, gotSAML)
	assert.Equal(t, "https://app.example.com/saml", gotSAML.EntityID)
}

func TestAppStore_GetByTenantEntityID_NotFound(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	_, _, err := s.GetByTenantEntityID(ctx, "acme", "https://nonexistent.example.com/saml")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestAppStore_GetByTenantEntityID_WrongTenant verifies that an entityID
// registered under one tenant cannot be resolved through another tenant, even
// when both tenants exist. This is the read-time half of the (tenant, entityID)
// isolation boundary.
func TestAppStore_GetByTenantEntityID_WrongTenant(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()
	_, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)

	// Same entityID, different tenant → must not resolve.
	_, _, err = s.GetByTenantEntityID(ctx, "other", "https://app.example.com/saml")
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestAppStore_Create_DuplicateEntityID_SameTenant verifies that registering
// the same entityID twice within one tenant is rejected atomically,
// while a different tenant may still register that entityID.
func TestAppStore_Create_DuplicateEntityID_SameTenant(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	saml := newTestSAMLConfig()
	_, err := s.Create(ctx, "acme", newTestApp(), saml)
	require.NoError(t, err)

	// Second create with the same entityID in the same tenant is rejected.
	dupSAML := newTestSAMLConfig()
	_, err = s.Create(ctx, "acme", newTestApp(), dupSAML)
	assert.ErrorIs(t, err, ErrDuplicateEntityID)

	// A different tenant may register the same entityID.
	otherSAML := newTestSAMLConfig()
	_, err = s.Create(ctx, "other", newTestApp(), otherSAML)
	require.NoError(t, err)
}

func TestAppStore_List(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app1 := &tenant.Application{DisplayName: "App 1", Protocol: "saml", SourceID: "s1", Status: "active"}
	app2 := &tenant.Application{DisplayName: "App 2", Protocol: "saml", SourceID: "s1", Status: "active"}
	saml1 := &tenant.SAMLConfig{EntityID: "https://app1.example.com/saml", AcsURL: "https://app1.example.com/acs", AcsURLs: []string{"https://app1.example.com/acs"}, NameIDFormat: "email", NameIDSource: "email"}
	saml2 := &tenant.SAMLConfig{EntityID: "https://app2.example.com/saml", AcsURL: "https://app2.example.com/acs", AcsURLs: []string{"https://app2.example.com/acs"}, NameIDFormat: "email", NameIDSource: "email"}

	_, err := s.Create(ctx, "acme", app1, saml1)
	require.NoError(t, err)
	_, err = s.Create(ctx, "acme", app2, saml2)
	require.NoError(t, err)

	list, err := s.List(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, list, 2)

	names := map[string]bool{}
	for _, app := range list {
		names[app.DisplayName] = true
	}
	assert.True(t, names["App 1"])
	assert.True(t, names["App 2"])
}

func TestAppStore_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	appA := &tenant.Application{DisplayName: "Tenant A App", Protocol: "saml", SourceID: "s1", Status: "active"}
	samlA := &tenant.SAMLConfig{EntityID: "https://a.example.com/saml", AcsURL: "https://a.example.com/acs", AcsURLs: []string{"https://a.example.com/acs"}, NameIDFormat: "email", NameIDSource: "email"}

	appB := &tenant.Application{DisplayName: "Tenant B App", Protocol: "saml", SourceID: "s2", Status: "active"}
	samlB := &tenant.SAMLConfig{EntityID: "https://b.example.com/saml", AcsURL: "https://b.example.com/acs", AcsURLs: []string{"https://b.example.com/acs"}, NameIDFormat: "email", NameIDSource: "email"}

	idA, err := s.Create(ctx, "tenant-a", appA, samlA)
	require.NoError(t, err)
	idB, err := s.Create(ctx, "tenant-b", appB, samlB)
	require.NoError(t, err)

	// Tenant A can see its own app.
	gotA, err := s.Get(ctx, "tenant-a", idA)
	require.NoError(t, err)
	assert.Equal(t, "Tenant A App", gotA.DisplayName)

	// Tenant A cannot see tenant B's app.
	_, err = s.Get(ctx, "tenant-a", idB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Tenant B cannot see tenant A's app.
	_, err = s.Get(ctx, "tenant-b", idA)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// List is scoped.
	listA, err := s.List(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Len(t, listA, 1)
	assert.Equal(t, "Tenant A App", listA[0].DisplayName)

	listB, err := s.List(ctx, "tenant-b")
	require.NoError(t, err)
	assert.Len(t, listB, 1)
	assert.Equal(t, "Tenant B App", listB[0].DisplayName)
}

func TestAppStore_Update(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()
	id, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)

	original, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	app.DisplayName = "Updated App"
	require.NoError(t, s.Update(ctx, "acme", app))

	updated, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)
	assert.Equal(t, "Updated App", updated.DisplayName)
	assert.Equal(t, original.CreatedAt, updated.CreatedAt)
	assert.True(t, updated.UpdatedAt.After(original.UpdatedAt))
}

func TestAppStore_UpdateSAMLConfig(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()
	id, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)

	// Update SAML config.
	saml.AcsURL = "https://app.example.com/saml/acs/v2"
	saml.EntityID = "https://app.example.com/saml/v2"
	require.NoError(t, s.UpdateSAMLConfig(ctx, "acme", id, saml))

	got, err := s.GetSAMLConfig(ctx, "acme", id)
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com/saml/acs/v2", got.AcsURL)
	assert.Equal(t, "https://app.example.com/saml/v2", got.EntityID)

	// Verify GSI updated — should be findable by new entity ID within the tenant.
	gotApp, _, err := s.GetByTenantEntityID(ctx, "acme", "https://app.example.com/saml/v2")
	require.NoError(t, err)
	assert.Equal(t, id, gotApp.ID)

	// Old entity ID must no longer resolve after the update released its marker.
	_, _, err = s.GetByTenantEntityID(ctx, "acme", "https://app.example.com/saml")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestAppStore_Delete(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()
	id, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)

	// Verify exists.
	_, err = s.Get(ctx, "acme", id)
	require.NoError(t, err)
	_, err = s.GetSAMLConfig(ctx, "acme", id)
	require.NoError(t, err)

	// Delete.
	require.NoError(t, s.Delete(ctx, "acme", id))

	// Both app and SAML config gone.
	_, err = s.Get(ctx, "acme", id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	_, err = s.GetSAMLConfig(ctx, "acme", id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAppStore_SetStatus(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := newTestApp()
	saml := newTestSAMLConfig()
	id, err := s.Create(ctx, "acme", app, saml)
	require.NoError(t, err)

	require.NoError(t, s.SetStatus(ctx, "acme", id, "disabled"))

	got, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)
	assert.Equal(t, "disabled", got.Status)
}

func TestAppStore_CreateWithNilSAML(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	s := NewAppStore(ms, "test-table")

	app := &tenant.Application{DisplayName: "OIDC App", Protocol: "oidc", SourceID: "s1", Status: "active"}

	id, err := s.Create(ctx, "acme", app, nil)
	require.NoError(t, err)
	require.NotEmpty(t, id)

	got, err := s.Get(ctx, "acme", id)
	require.NoError(t, err)
	assert.Equal(t, "OIDC App", got.DisplayName)

	// SAML config should not exist.
	_, err = s.GetSAMLConfig(ctx, "acme", id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
