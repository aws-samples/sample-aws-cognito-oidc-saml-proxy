package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
)

// ReplayStore provides protection against AuthnRequest replay attacks.
type ReplayStore struct {
	db TableAPI
}

// Compile-time check: ReplayStore implements domain.ReplayRepository.
var _ domain.ReplayRepository = (*ReplayStore)(nil)

// ReplayRecord tracks seen AuthnRequest IDs with a DynamoDB TTL.
type ReplayRecord struct {
	PK        string    `dynamo:"PK,hash" json:"-"`
	SK        string    `dynamo:"SK,range" json:"-"`
	RequestID string    `dynamo:"requestId" json:"requestId"`
	SeenAt    time.Time `dynamo:"seenAt" json:"seenAt"`
	// ExpiresAtEpoch is the expiry as Unix epoch seconds. DynamoDB's TTL feature
	// only reaps items whose TTL attribute is a Number; guregu marshals a
	// time.Time as an RFC3339 string, which TTL silently ignores — leaving these
	// rows to grow without bound. Keep this int64 (set via time.Time.Unix()) so
	// the rows actually expire. The attribute name must match the Terraform
	// ttl_attribute_name = "ttl".
	ExpiresAtEpoch int64 `dynamo:"ttl" json:"expiresAt"`
}

// NewReplayStore creates a new ReplayStore.
func NewReplayStore(db TableAPI, tableName string) *ReplayStore {
	return &ReplayStore{db: db}
}

// MarkSeen atomically records an AuthnRequest ID as seen with the specified
// TTL. It uses a conditional write (attribute_not_exists) so that the first
// caller for a given ID succeeds and any concurrent or subsequent caller
// observes ErrConditionFailed. This closes the check-then-act (TOCTOU) window
// that an IsSeen-then-Put sequence leaves open: replay detection is the write
// itself, not a preceding read.
//
// Callers MUST treat ErrConditionFailed as "already seen -> reject" and any
// other non-nil error as a hard failure (fail closed), never as a reason to
// continue the flow.
func (r *ReplayStore) MarkSeen(ctx context.Context, authnRequestID string, ttl time.Duration) error {
	now := time.Now()
	expiresAt := now.Add(ttl)

	record := &ReplayRecord{
		PK:             fmt.Sprintf("REPLAY#%s", authnRequestID),
		SK:             "_",
		RequestID:      authnRequestID,
		SeenAt:         now,
		ExpiresAtEpoch: expiresAt.Unix(),
	}

	if err := r.db.PutIfNotExists(ctx, record); err != nil {
		if errors.Is(err, ErrConditionFailed) {
			return ErrConditionFailed
		}
		return fmt.Errorf("failed to mark request as seen: %w", err)
	}

	return nil
}

// IsSeen checks if an AuthnRequest ID has been seen before.
func (r *ReplayStore) IsSeen(ctx context.Context, authnRequestID string) (bool, error) {
	pk := fmt.Sprintf("REPLAY#%s", authnRequestID)
	sk := "_"

	var record ReplayRecord
	err := r.db.Get(ctx, pk, sk, &record)
	if err == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check if request was seen: %w", err)
	}

	// Check if expired (in real DynamoDB, TTL would auto-delete, but we check manually).
	if time.Now().Unix() > record.ExpiresAtEpoch {
		return false, nil
	}

	return true, nil
}
