package store

import (
	"context"
	"fmt"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// sourceItem wraps tenant.IdentitySource with DynamoDB key fields.
type sourceItem struct {
	PK string `dynamo:"PK,hash" json:"-"`
	SK string `dynamo:"SK,range" json:"-"`
	tenant.IdentitySource
}

// SourceStore provides CRUD operations for IdentitySource configurations.
type SourceStore struct {
	db TableAPI
}

// Compile-time check: SourceStore implements domain.SourceRepository.
var _ domain.SourceRepository = (*SourceStore)(nil)

// NewSourceStore creates a new SourceStore.
func NewSourceStore(db TableAPI, tableName string) *SourceStore {
	return &SourceStore{db: db}
}

func sourceSK(id string) string { return fmt.Sprintf("SOURCE#%s", id) }

// Create stores a new IdentitySource and returns the generated ID.
func (s *SourceStore) Create(ctx context.Context, tenantSlug string, src *tenant.IdentitySource) (string, error) {
	id, err := generateID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	src.ID = id
	src.TenantSlug = tenantSlug
	src.CreatedAt = now
	src.UpdatedAt = now

	item := sourceItem{
		PK:             tenantPK(tenantSlug),
		SK:             sourceSK(id),
		IdentitySource: *src,
	}
	if err := s.db.Put(ctx, &item); err != nil {
		return "", fmt.Errorf("failed to create identity source: %w", err)
	}
	return id, nil
}

// Get retrieves an IdentitySource by tenant slug and source ID.
func (s *SourceStore) Get(ctx context.Context, tenantSlug, sourceID string) (*tenant.IdentitySource, error) {
	var item sourceItem
	if err := s.db.Get(ctx, tenantPK(tenantSlug), sourceSK(sourceID), &item); err != nil {
		return nil, fmt.Errorf("failed to get identity source %q: %w", sourceID, err)
	}
	item.TenantSlug = tenantSlug
	return &item.IdentitySource, nil
}

// List returns all IdentitySources for a tenant.
func (s *SourceStore) List(ctx context.Context, tenantSlug string) ([]*tenant.IdentitySource, error) {
	pk := tenantPK(tenantSlug)
	var items []sourceItem
	if err := s.db.Query(ctx, pk, "SOURCE#", &items); err != nil {
		return nil, fmt.Errorf("failed to list identity sources: %w", err)
	}

	sources := make([]*tenant.IdentitySource, 0, len(items))
	for _, item := range items {
		src := item.IdentitySource
		src.TenantSlug = tenantSlug
		sources = append(sources, &src)
	}
	return sources, nil
}

// Update updates an existing IdentitySource.
func (s *SourceStore) Update(ctx context.Context, tenantSlug string, src *tenant.IdentitySource) error {
	if src.ID == "" {
		return fmt.Errorf("identity source ID is required for update")
	}

	existing, err := s.Get(ctx, tenantSlug, src.ID)
	if err != nil {
		return fmt.Errorf("failed to get existing identity source: %w", err)
	}

	src.TenantSlug = tenantSlug
	src.CreatedAt = existing.CreatedAt
	src.UpdatedAt = time.Now()

	item := sourceItem{
		PK:             tenantPK(tenantSlug),
		SK:             sourceSK(src.ID),
		IdentitySource: *src,
	}
	if err := s.db.Put(ctx, &item); err != nil {
		return fmt.Errorf("failed to update identity source: %w", err)
	}
	return nil
}

// Delete removes an IdentitySource.
func (s *SourceStore) Delete(ctx context.Context, tenantSlug, sourceID string) error {
	// Verify it exists.
	if _, err := s.Get(ctx, tenantSlug, sourceID); err != nil {
		return fmt.Errorf("failed to get identity source for deletion: %w", err)
	}
	if err := s.db.Delete(ctx, tenantPK(tenantSlug), sourceSK(sourceID)); err != nil {
		return fmt.Errorf("failed to delete identity source: %w", err)
	}
	return nil
}
