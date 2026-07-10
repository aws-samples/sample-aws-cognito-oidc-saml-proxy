package store

import (
	"context"
	"fmt"
	"time"
)

// PendingLogin captures the original SSO request context while a user
// authenticates at a custom login page. It is keyed by an opaque, single-use
// flow ID and stored on the session table with a TTL. Storing this server-side
// (rather than in a cookie) avoids SameSite issues on the cross-origin POST the
// custom login page makes back to the gateway's session-establish endpoint.
type PendingLogin struct {
	PK       string `dynamo:"PK,hash" json:"-"`
	SK       string `dynamo:"SK,range" json:"-"`
	FlowID   string `dynamo:"flowId" json:"flowId"`
	Protocol string `dynamo:"protocol" json:"protocol"` // "saml" | "oidc"

	TenantSlug string `dynamo:"tenantSlug" json:"tenantSlug"`
	SourceID   string `dynamo:"sourceId" json:"sourceId"`
	AppID      string `dynamo:"appId" json:"appId"`

	// SAML resume context.
	SAMLRequestB64 string `dynamo:"samlRequestB64,omitempty" json:"samlRequestB64,omitempty"`
	RelayState     string `dynamo:"relayState,omitempty" json:"relayState,omitempty"`
	SPEntityID     string `dynamo:"spEntityId,omitempty" json:"spEntityId,omitempty"`

	// OIDC resume context.
	AuthRequestID string `dynamo:"authRequestId,omitempty" json:"authRequestId,omitempty"`

	CreatedAt time.Time `dynamo:"createdAt" json:"createdAt"`
	// ExpiresAtEpoch is the expiry as Unix epoch seconds. DynamoDB TTL only reaps
	// items whose TTL attribute is a Number; a time.Time marshals to an RFC3339
	// string that TTL silently ignores, so these pending-login rows would never
	// expire. Keep this int64 (set via time.Time.Unix()) so TTL fires. The
	// attribute name must match the DynamoDB TTL attribute "ttl".
	ExpiresAtEpoch int64 `dynamo:"ttl" json:"expiresAt"`
}

// PendingLoginStore persists pending custom-login flows on the session table.
type PendingLoginStore struct {
	db TableAPI
}

// NewPendingLoginStore creates a new PendingLoginStore.
func NewPendingLoginStore(db TableAPI, tableName string) *PendingLoginStore {
	return &PendingLoginStore{db: db}
}

func pendingLoginPK(flowID string) string { return fmt.Sprintf("PENDINGLOGIN#%s", flowID) }

// Create stores a pending login with the given TTL.
func (s *PendingLoginStore) Create(ctx context.Context, pl *PendingLogin, ttl time.Duration) error {
	if pl.FlowID == "" {
		return fmt.Errorf("pending login requires a flow ID")
	}
	now := time.Now()
	pl.PK = pendingLoginPK(pl.FlowID)
	pl.SK = "_"
	pl.CreatedAt = now
	pl.ExpiresAtEpoch = now.Add(ttl).Unix()
	if err := s.db.Put(ctx, pl); err != nil {
		return fmt.Errorf("failed to store pending login: %w", err)
	}
	return nil
}

// Get retrieves a pending login by flow ID. Returns ErrNotFound if missing or
// expired.
func (s *PendingLoginStore) Get(ctx context.Context, flowID string) (*PendingLogin, error) {
	var pl PendingLogin
	if err := s.db.Get(ctx, pendingLoginPK(flowID), "_", &pl); err != nil {
		return nil, err
	}
	if time.Now().Unix() > pl.ExpiresAtEpoch {
		return nil, ErrNotFound
	}
	return &pl, nil
}

// Delete removes a pending login (single-use: call after consuming it).
func (s *PendingLoginStore) Delete(ctx context.Context, flowID string) error {
	return s.db.Delete(ctx, pendingLoginPK(flowID), "_")
}
