package domain

import (
	"context"
	"time"
)

// OnboardingState is the server-side wizard session for a single tenant.
// Lives in the session table with a 7-day TTL so abandoned wizards auto-clean.
// Deleted when the tenant completes onboarding.
type OnboardingState struct {
	TenantSlug    string          `dynamo:"tenantSlug" json:"tenantSlug"`
	CurrentStep   int             `dynamo:"currentStep" json:"currentStep"`
	Capabilities  []string        `dynamo:"capabilities,omitempty" json:"capabilities,omitempty"`
	ExternalID    string          `dynamo:"externalId,omitempty" json:"-"` // SaaS-generated; never returned in list/get
	IaCVersion    int             `dynamo:"iacVersion,omitempty" json:"iacVersion,omitempty"`
	CapabilityMap map[string]bool `dynamo:"capabilityMap,omitempty" json:"capabilityMap,omitempty"`
	UpdatedAt     time.Time       `dynamo:"updatedAt" json:"updatedAt"`
}

// OnboardingStateRepository persists wizard state for a tenant.
type OnboardingStateRepository interface {
	Get(ctx context.Context, tenantSlug string) (*OnboardingState, error)
	Put(ctx context.Context, state *OnboardingState) error
	Delete(ctx context.Context, tenantSlug string) error
}
