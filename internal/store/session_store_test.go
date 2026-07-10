package store

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/guregu/dynamo/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStore_AddParticipant(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	err := sessionStore.AddParticipant(
		context.Background(),
		"session-001",
		"https://sp1.example.com",
		"user-123",
		"user@example.com",
		time.Now().Add(1*time.Hour),
	)
	require.NoError(t, err)
}

func TestSessionStore_GetParticipants(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	expiry := time.Now().Add(1 * time.Hour)

	err := sessionStore.AddParticipant(context.Background(), "session-002", "https://sp1.example.com", "user-123", "user@example.com", expiry)
	require.NoError(t, err)

	err = sessionStore.AddParticipant(context.Background(), "session-002", "https://sp2.example.com", "user-123", "user@example.com", expiry)
	require.NoError(t, err)

	participants, err := sessionStore.GetParticipants(context.Background(), "session-002")
	require.NoError(t, err)
	assert.Len(t, participants, 2)
}

func TestSessionStore_GetParticipants_Empty(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	participants, err := sessionStore.GetParticipants(context.Background(), "nonexistent-session")
	require.NoError(t, err)
	assert.Empty(t, participants)
}

func TestSessionStore_GetParticipants_FiltersExpired(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	// Add one valid and one expired participant
	err := sessionStore.AddParticipant(context.Background(), "session-003", "https://sp-active.example.com", "user-123", "user@example.com", time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	err = sessionStore.AddParticipant(context.Background(), "session-003", "https://sp-expired.example.com", "user-123", "user@example.com", time.Now().Add(-1*time.Second))
	require.NoError(t, err)

	participants, err := sessionStore.GetParticipants(context.Background(), "session-003")
	require.NoError(t, err)
	assert.Len(t, participants, 1)
	assert.Equal(t, "https://sp-active.example.com", participants[0].SPEntityID)
}

// TestSessionStore_IsSessionRevoked_NotRevoked asserts that a session with no
// revocation marker reports not-revoked, so a live session cookie is honoured.
func TestSessionStore_IsSessionRevoked_NotRevoked(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	revoked, err := sessionStore.IsSessionRevoked(context.Background(), "_session_never_revoked")
	require.NoError(t, err)
	assert.False(t, revoked)
}

// TestSessionStore_RevokeSession_ThenRevoked asserts that after RevokeSession,
// IsSessionRevoked reports true for that SessionIndex — the marker GetSession
// consults to reject a replayed cookie after logout.
func TestSessionStore_RevokeSession_ThenRevoked(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	require.NoError(t, sessionStore.RevokeSession(context.Background(), "_session_revoked"))

	revoked, err := sessionStore.IsSessionRevoked(context.Background(), "_session_revoked")
	require.NoError(t, err)
	assert.True(t, revoked, "a revoked session must report revoked")

	// A different session is unaffected — revocation is keyed by SessionIndex.
	other, err := sessionStore.IsSessionRevoked(context.Background(), "_session_other")
	require.NoError(t, err)
	assert.False(t, other)
}

// TestSessionStore_RevokeSession_EmptyIndex_NoOp asserts that an empty
// SessionIndex cannot be keyed, so RevokeSession is a no-op and IsSessionRevoked
// reports false rather than revoking every empty-index lookup.
func TestSessionStore_RevokeSession_EmptyIndex_NoOp(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	require.NoError(t, sessionStore.RevokeSession(context.Background(), ""))

	revoked, err := sessionStore.IsSessionRevoked(context.Background(), "")
	require.NoError(t, err)
	assert.False(t, revoked)
}

// TestSessionStore_IsSessionRevoked_ExpiredMarker asserts that a revocation
// marker whose TTL has already passed is treated as not-revoked — by then the
// underlying 8h session can no longer be valid on its own.
func TestSessionStore_IsSessionRevoked_ExpiredMarker(t *testing.T) {
	db := NewMemoryDB()
	sessionStore := NewSessionStore(db, "test")

	// Write a marker directly with an already-past epoch so the manual expiry
	// check in IsSessionRevoked fires (MemoryDB does not run a TTL reaper).
	past := time.Now().Add(-1 * time.Minute)
	marker := &revokedSessionItem{
		PK:             "SESSION#_session_expired",
		SK:             revokedSessionSK,
		SessionIndex:   "_session_expired",
		RevokedAt:      past,
		ExpiresAtEpoch: past.Unix(),
	}
	require.NoError(t, db.Put(context.Background(), marker))

	revoked, err := sessionStore.IsSessionRevoked(context.Background(), "_session_expired")
	require.NoError(t, err)
	assert.False(t, revoked, "an expired revocation marker must report not-revoked")
}

// TestRevokedSessionItem_TTLMarshalsAsNumber guards that the revocation
// marker's ttl attribute must marshal as a DynamoDB Number (epoch seconds), not
// an RFC3339 string, or the TTL reaper never fires and markers accumulate.
func TestRevokedSessionItem_TTLMarshalsAsNumber(t *testing.T) {
	expiresAt := time.Now().Add(revokedSessionTTL)
	marker := &revokedSessionItem{
		PK:             "SESSION#_session_ttl",
		SK:             revokedSessionSK,
		SessionIndex:   "_session_ttl",
		RevokedAt:      time.Now(),
		ExpiresAtEpoch: expiresAt.Unix(),
	}

	item, err := dynamo.MarshalItem(marker)
	require.NoError(t, err)

	ttlAttr, ok := item["ttl"]
	require.True(t, ok, "marker must carry a ttl attribute")

	num, ok := ttlAttr.(*types.AttributeValueMemberN)
	require.Truef(t, ok, "ttl must be a DynamoDB Number, got %T", ttlAttr)
	assert.Equal(t, strconv.FormatInt(expiresAt.Unix(), 10), num.Value)
}
