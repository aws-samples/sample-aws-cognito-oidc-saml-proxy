package store

import (
	"context"
	"fmt"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
)

// onboardingStateItem wraps domain.OnboardingState with DynamoDB key fields.
// The SK is a fixed literal so the tenant slug alone identifies the state row.
// TTL is a unix timestamp (seconds) — the DynamoDB session table has TTL enabled.
type onboardingStateItem struct {
	PK  string `dynamo:"PK,hash" json:"-"`
	SK  string `dynamo:"SK,range" json:"-"`
	TTL int64  `dynamo:"ttl" json:"-"`
	domain.OnboardingState
}

// OnboardingStateStore persists wizard state in the session table with a 7-day TTL.
type OnboardingStateStore struct {
	db TableAPI
}

// Compile-time check that OnboardingStateStore implements the domain interface.
var _ domain.OnboardingStateRepository = (*OnboardingStateStore)(nil)

// NewOnboardingStateStore returns a store backed by the session table.
// Pass a TableAPI wired to the session table (not the config table).
func NewOnboardingStateStore(db TableAPI, tableName string) *OnboardingStateStore {
	return &OnboardingStateStore{db: db}
}

// onboardingStateSK is a fixed SK — one state row per tenant.
const onboardingStateSK = "ONBOARDING#STATE"

// onboardingStateTTL is the wizard's self-expiry. Abandoned wizards auto-clean.
const onboardingStateTTL = 7 * 24 * time.Hour

// Get returns the onboarding state for a tenant or an error if none exists.
func (s *OnboardingStateStore) Get(ctx context.Context, tenantSlug string) (*domain.OnboardingState, error) {
	var item onboardingStateItem
	if err := s.db.Get(ctx, tenantPK(tenantSlug), onboardingStateSK, &item); err != nil {
		return nil, fmt.Errorf("failed to get onboarding state for %q: %w", tenantSlug, err)
	}
	item.TenantSlug = tenantSlug
	return &item.OnboardingState, nil
}

// Put writes the onboarding state, advancing UpdatedAt and refreshing the TTL.
func (s *OnboardingStateStore) Put(ctx context.Context, state *domain.OnboardingState) error {
	if state == nil || state.TenantSlug == "" {
		return fmt.Errorf("onboarding state must have a tenant slug")
	}
	state.UpdatedAt = time.Now()
	item := onboardingStateItem{
		PK:              tenantPK(state.TenantSlug),
		SK:              onboardingStateSK,
		TTL:             time.Now().Add(onboardingStateTTL).Unix(),
		OnboardingState: *state,
	}
	if err := s.db.Put(ctx, &item); err != nil {
		return fmt.Errorf("failed to put onboarding state: %w", err)
	}
	return nil
}

// Delete removes the onboarding state row — called on wizard completion.
func (s *OnboardingStateStore) Delete(ctx context.Context, tenantSlug string) error {
	if err := s.db.Delete(ctx, tenantPK(tenantSlug), onboardingStateSK); err != nil {
		return fmt.Errorf("failed to delete onboarding state for %q: %w", tenantSlug, err)
	}
	return nil
}
