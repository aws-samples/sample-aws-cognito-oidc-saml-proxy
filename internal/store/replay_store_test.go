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

func TestReplayStore_MarkSeen(t *testing.T) {
	db := NewMemoryDB()
	replayStore := NewReplayStore(db, "test")

	err := replayStore.MarkSeen(context.Background(), "request-001", 5*time.Minute)
	require.NoError(t, err)
}

func TestReplayStore_IsSeen_NotSeen(t *testing.T) {
	db := NewMemoryDB()
	replayStore := NewReplayStore(db, "test")

	seen, err := replayStore.IsSeen(context.Background(), "request-never-seen")
	require.NoError(t, err)
	assert.False(t, seen)
}

func TestReplayStore_IsSeen_AfterMark(t *testing.T) {
	db := NewMemoryDB()
	replayStore := NewReplayStore(db, "test")

	err := replayStore.MarkSeen(context.Background(), "request-002", 5*time.Minute)
	require.NoError(t, err)

	seen, err := replayStore.IsSeen(context.Background(), "request-002")
	require.NoError(t, err)
	assert.True(t, seen)
}

func TestReplayStore_IsSeen_Expired(t *testing.T) {
	db := NewMemoryDB()
	replayStore := NewReplayStore(db, "test")

	// Mark with a TTL that has already expired (negative duration)
	err := replayStore.MarkSeen(context.Background(), "request-expired", -1*time.Second)
	require.NoError(t, err)

	seen, err := replayStore.IsSeen(context.Background(), "request-expired")
	require.NoError(t, err)
	assert.False(t, seen, "expired request should not be seen")
}

// TestReplayRecord_TTLMarshalsAsNumber guards the ttl marshaling contract: the
// ttl attribute must marshal as a DynamoDB Number (epoch seconds), not an
// RFC3339 string, or the TTL reaper never fires and the replay table grows
// without bound.
func TestReplayRecord_TTLMarshalsAsNumber(t *testing.T) {
	expiresAt := time.Now().Add(5 * time.Minute)
	record := &ReplayRecord{
		PK:             "REPLAY#request-ttl",
		SK:             "_",
		RequestID:      "request-ttl",
		SeenAt:         time.Now(),
		ExpiresAtEpoch: expiresAt.Unix(),
	}

	item, err := dynamo.MarshalItem(record)
	require.NoError(t, err)

	ttlAttr, ok := item["ttl"]
	require.True(t, ok, "record must carry a ttl attribute")

	num, ok := ttlAttr.(*types.AttributeValueMemberN)
	require.Truef(t, ok, "ttl must be a DynamoDB Number, got %T", ttlAttr)
	assert.Equal(t, strconv.FormatInt(expiresAt.Unix(), 10), num.Value)
}

// TestReplayStore_IsSeen_Live confirms the epoch comparison still reports a
// live (unexpired) record as seen — the flip side of the expired case.
func TestReplayStore_IsSeen_Live(t *testing.T) {
	db := NewMemoryDB()
	replayStore := NewReplayStore(db, "test")

	require.NoError(t, replayStore.MarkSeen(context.Background(), "request-live", 5*time.Minute))

	seen, err := replayStore.IsSeen(context.Background(), "request-live")
	require.NoError(t, err)
	assert.True(t, seen, "live request within TTL must still be seen")
}
