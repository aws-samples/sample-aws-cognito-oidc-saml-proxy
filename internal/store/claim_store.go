package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// claimItem wraps tenant.ClaimMapping with DynamoDB key fields.
type claimItem struct {
	PK string `dynamo:"PK,hash" json:"-"`
	SK string `dynamo:"SK,range" json:"-"`
	tenant.ClaimMapping
}

// roleItem wraps tenant.RoleMapping with DynamoDB key fields.
type roleItem struct {
	PK string `dynamo:"PK,hash" json:"-"`
	SK string `dynamo:"SK,range" json:"-"`
	tenant.RoleMapping
}

// ClaimStore provides operations for ClaimMapping and RoleMapping.
type ClaimStore struct {
	db TableAPI
}

// Compile-time check: ClaimStore implements domain.ClaimRepository.
var _ domain.ClaimRepository = (*ClaimStore)(nil)

// NewClaimStore creates a new ClaimStore.
func NewClaimStore(db TableAPI, tableName string) *ClaimStore {
	return &ClaimStore{db: db}
}

func claimSK(appID, name string) string { return fmt.Sprintf("APP#%s#CLAIM#%s", appID, name) }
func roleSK(appID, group string) string { return fmt.Sprintf("APP#%s#ROLE#%s", appID, group) }
func claimPrefix(appID string) string   { return fmt.Sprintf("APP#%s#CLAIM#", appID) }
func rolePrefix(appID string) string    { return fmt.Sprintf("APP#%s#ROLE#", appID) }

// PutClaimMappings replaces all claim mappings for an app.
// It deletes existing mappings first, then writes the new set.
func (s *ClaimStore) PutClaimMappings(ctx context.Context, tenantSlug, appID string, mappings []tenant.ClaimMapping) error {
	pk := tenantPK(tenantSlug)

	// Delete existing claim mappings for this app.
	prefix := claimPrefix(appID)
	var existing []claimItem
	if err := s.db.Query(ctx, pk, prefix, &existing); err != nil && err != ErrNotFound {
		return fmt.Errorf("failed to query existing claim mappings: %w", err)
	}
	for _, item := range existing {
		if strings.HasPrefix(item.SK, prefix) {
			_ = s.db.Delete(ctx, pk, item.SK)
		}
	}

	// Write new mappings.
	for _, m := range mappings {
		item := claimItem{
			PK:           pk,
			SK:           claimSK(appID, m.Name),
			ClaimMapping: m,
		}
		if err := s.db.Put(ctx, &item); err != nil {
			return fmt.Errorf("failed to put claim mapping %q: %w", m.Name, err)
		}
	}
	return nil
}

// GetClaimMappings retrieves all claim mappings for an app.
func (s *ClaimStore) GetClaimMappings(ctx context.Context, tenantSlug, appID string) ([]tenant.ClaimMapping, error) {
	pk := tenantPK(tenantSlug)
	prefix := claimPrefix(appID)

	var items []claimItem
	if err := s.db.Query(ctx, pk, prefix, &items); err != nil && err != ErrNotFound {
		return nil, fmt.Errorf("failed to query claim mappings: %w", err)
	}

	mappings := make([]tenant.ClaimMapping, 0, len(items))
	for _, item := range items {
		mappings = append(mappings, item.ClaimMapping)
	}
	return mappings, nil
}

// PutRoleMappings replaces all role mappings for an app.
func (s *ClaimStore) PutRoleMappings(ctx context.Context, tenantSlug, appID string, mappings []tenant.RoleMapping) error {
	pk := tenantPK(tenantSlug)

	// Delete existing role mappings for this app.
	prefix := rolePrefix(appID)
	var existing []roleItem
	if err := s.db.Query(ctx, pk, prefix, &existing); err != nil && err != ErrNotFound {
		return fmt.Errorf("failed to query existing role mappings: %w", err)
	}
	for _, item := range existing {
		if strings.HasPrefix(item.SK, prefix) {
			_ = s.db.Delete(ctx, pk, item.SK)
		}
	}

	// Write new mappings.
	for _, m := range mappings {
		item := roleItem{
			PK:          pk,
			SK:          roleSK(appID, m.CognitoGroup),
			RoleMapping: m,
		}
		if err := s.db.Put(ctx, &item); err != nil {
			return fmt.Errorf("failed to put role mapping %q: %w", m.CognitoGroup, err)
		}
	}
	return nil
}

// GetRoleMappings retrieves all role mappings for an app.
func (s *ClaimStore) GetRoleMappings(ctx context.Context, tenantSlug, appID string) ([]tenant.RoleMapping, error) {
	pk := tenantPK(tenantSlug)
	prefix := rolePrefix(appID)

	var items []roleItem
	if err := s.db.Query(ctx, pk, prefix, &items); err != nil && err != ErrNotFound {
		return nil, fmt.Errorf("failed to query role mappings: %w", err)
	}

	mappings := make([]tenant.RoleMapping, 0, len(items))
	for _, item := range items {
		mappings = append(mappings, item.RoleMapping)
	}
	return mappings, nil
}
