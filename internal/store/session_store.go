package store

import (
	"context"
	"fmt"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
)

// SessionStore tracks SLO session participants across multiple SPs.
type SessionStore struct {
	db TableAPI
}

// Compile-time check: SessionStore implements domain.SessionRepository.
var _ domain.SessionRepository = (*SessionStore)(nil)

// SessionParticipant is an alias for domain.SessionParticipant for backward compatibility.
type SessionParticipant = domain.SessionParticipant

// sessionParticipantItem wraps domain.SessionParticipant with DynamoDB key fields.
type sessionParticipantItem struct {
	PK  string `dynamo:"PK,hash" json:"-"`
	SK  string `dynamo:"SK,range" json:"-"`
	TTL int64  `dynamo:"ttl" json:"-"` // DynamoDB TTL — auto-delete after session expiry + buffer
	domain.SessionParticipant
}

// revokedSessionTTL is how long a revocation marker is retained. It must safely
// exceed the maximum gateway session lifetime (8h) plus clock-skew and
// cookie-max-age headroom, so a copied session cookie replayed at any point
// before its own expiry still finds the marker. Once the underlying session can
// no longer be valid, DynamoDB reaps the marker.
const revokedSessionTTL = 9 * time.Hour

// revokedSessionItem is a per-session revocation marker. It shares the session
// partition (PK: SESSION#<index>) with participant rows but uses a fixed range
// key so a single Get resolves it. ExpiresAtEpoch is Unix epoch seconds under
// the "ttl" attribute (an RFC3339 string would be ignored by DynamoDB TTL — see
// ReplayRecord), so the marker expires on its own once the session cannot be.
type revokedSessionItem struct {
	PK             string    `dynamo:"PK,hash" json:"-"`
	SK             string    `dynamo:"SK,range" json:"-"`
	SessionIndex   string    `dynamo:"sessionIndex" json:"sessionIndex"`
	RevokedAt      time.Time `dynamo:"revokedAt" json:"revokedAt"`
	ExpiresAtEpoch int64     `dynamo:"ttl" json:"expiresAt"`
}

// revokedSessionSK is the fixed range key for a session's revocation marker.
const revokedSessionSK = "REVOKED"

// NewSessionStore creates a new SessionStore.
func NewSessionStore(db TableAPI, tableName string) *SessionStore {
	return &SessionStore{db: db}
}

// AddParticipant adds an SP to a SAML session.
func (s *SessionStore) AddParticipant(ctx context.Context, sessionIndex, spEntityID, userID, nameID string, expiry time.Time) error {
	now := time.Now()

	participant := &sessionParticipantItem{
		PK:  fmt.Sprintf("SESSION#%s", sessionIndex),
		SK:  fmt.Sprintf("SP#%s", spEntityID),
		TTL: expiry.Add(1 * time.Hour).Unix(), // Auto-delete 1h after session expiry
		SessionParticipant: domain.SessionParticipant{
			SessionIndex: sessionIndex,
			SPEntityID:   spEntityID,
			UserID:       userID,
			NameID:       nameID,
			CreatedAt:    now,
			ExpiresAt:    expiry,
		},
	}

	if err := s.db.Put(ctx, participant); err != nil {
		return fmt.Errorf("failed to add session participant: %w", err)
	}

	return nil
}

// GetParticipants retrieves all SPs participating in a session.
func (s *SessionStore) GetParticipants(ctx context.Context, sessionIndex string) ([]domain.SessionParticipant, error) {
	pk := fmt.Sprintf("SESSION#%s", sessionIndex)

	var items []sessionParticipantItem
	if err := s.db.Query(ctx, pk, "SP#", &items); err != nil && err != ErrNotFound {
		return nil, fmt.Errorf("failed to query session participants: %w", err)
	}

	// Filter out expired participants (DynamoDB would auto-delete via TTL).
	participants := make([]domain.SessionParticipant, 0, len(items))
	now := time.Now()
	for _, item := range items {
		if now.After(item.ExpiresAt) {
			continue
		}
		participants = append(participants, item.SessionParticipant)
	}

	return participants, nil
}

// RevokeSession writes a durable revocation marker for a SAML session. The
// write is unconditional (revocation is idempotent): a repeated LogoutRequest
// for the same session simply refreshes the marker. An empty sessionIndex is a
// no-op — there is nothing to key the marker on.
func (s *SessionStore) RevokeSession(ctx context.Context, sessionIndex string) error {
	if sessionIndex == "" {
		return nil
	}

	now := time.Now()
	marker := &revokedSessionItem{
		PK:             fmt.Sprintf("SESSION#%s", sessionIndex),
		SK:             revokedSessionSK,
		SessionIndex:   sessionIndex,
		RevokedAt:      now,
		ExpiresAtEpoch: now.Add(revokedSessionTTL).Unix(),
	}

	if err := s.db.Put(ctx, marker); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	return nil
}

// IsSessionRevoked reports whether a live revocation marker exists for
// sessionIndex. A missing marker means "not revoked"; an expired marker is
// treated the same (the underlying session can no longer be valid). An empty
// sessionIndex cannot be revoked and reports false.
func (s *SessionStore) IsSessionRevoked(ctx context.Context, sessionIndex string) (bool, error) {
	if sessionIndex == "" {
		return false, nil
	}

	pk := fmt.Sprintf("SESSION#%s", sessionIndex)

	var marker revokedSessionItem
	err := s.db.Get(ctx, pk, revokedSessionSK, &marker)
	if err == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check session revocation: %w", err)
	}

	// Manual expiry check — DynamoDB TTL reaping is eventual, not immediate.
	if time.Now().Unix() > marker.ExpiresAtEpoch {
		return false, nil
	}

	return true, nil
}
