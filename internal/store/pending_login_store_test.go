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

func TestPendingLoginStore_CreateAndGet(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")
	ctx := context.Background()

	pl := &PendingLogin{
		FlowID:         "flow-1",
		Protocol:       "saml",
		TenantSlug:     "acme",
		SourceID:       "src-1",
		AppID:          "app-1",
		SAMLRequestB64: "PHNhbWw+",
		RelayState:     "rs-123",
		SPEntityID:     "https://sp.example.com/saml",
	}
	require.NoError(t, s.Create(ctx, pl, 10*time.Minute))

	got, err := s.Get(ctx, "flow-1")
	require.NoError(t, err)
	assert.Equal(t, "saml", got.Protocol)
	assert.Equal(t, "acme", got.TenantSlug)
	assert.Equal(t, "src-1", got.SourceID)
	assert.Equal(t, "PHNhbWw+", got.SAMLRequestB64)
	assert.Equal(t, "rs-123", got.RelayState)
	assert.Equal(t, "https://sp.example.com/saml", got.SPEntityID)
}

func TestPendingLoginStore_Get_NotFound(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")

	_, err := s.Get(context.Background(), "missing")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPendingLoginStore_Delete_SingleUse(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")
	ctx := context.Background()

	require.NoError(t, s.Create(ctx, &PendingLogin{FlowID: "flow-2", Protocol: "oidc", AuthRequestID: "ar-9"}, 5*time.Minute))
	require.NoError(t, s.Delete(ctx, "flow-2"))

	_, err := s.Get(ctx, "flow-2")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPendingLoginStore_Get_Expired(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")
	ctx := context.Background()

	// Negative TTL -> already expired.
	require.NoError(t, s.Create(ctx, &PendingLogin{FlowID: "flow-3", Protocol: "saml"}, -1*time.Second))

	_, err := s.Get(ctx, "flow-3")
	assert.ErrorIs(t, err, ErrNotFound, "expired pending login should be treated as not found")
}

func TestPendingLoginStore_Create_RequiresFlowID(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")

	err := s.Create(context.Background(), &PendingLogin{Protocol: "saml"}, time.Minute)
	assert.Error(t, err)
}

// TestPendingLogin_TTLMarshalsAsNumber verifies the ttl attribute marshals as a
// DynamoDB Number (epoch seconds), not an RFC3339 string, or the TTL reaper
// never fires and pending-login rows accumulate without bound.
func TestPendingLogin_TTLMarshalsAsNumber(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")

	pl := &PendingLogin{FlowID: "flow-ttl", Protocol: "saml"}
	require.NoError(t, s.Create(context.Background(), pl, 10*time.Minute))
	require.NotZero(t, pl.ExpiresAtEpoch, "Create must set the epoch TTL")

	item, err := dynamo.MarshalItem(pl)
	require.NoError(t, err)

	ttlAttr, ok := item["ttl"]
	require.True(t, ok, "pending login must carry a ttl attribute")

	num, ok := ttlAttr.(*types.AttributeValueMemberN)
	require.Truef(t, ok, "ttl must be a DynamoDB Number, got %T", ttlAttr)
	assert.Equal(t, strconv.FormatInt(pl.ExpiresAtEpoch, 10), num.Value)
}

// TestPendingLoginStore_Get_Live confirms the epoch comparison still returns a
// live (unexpired) pending login — the flip side of the expired case.
func TestPendingLoginStore_Get_Live(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")
	ctx := context.Background()

	require.NoError(t, s.Create(ctx, &PendingLogin{FlowID: "flow-live", Protocol: "saml"}, 10*time.Minute))

	got, err := s.Get(ctx, "flow-live")
	require.NoError(t, err, "live pending login within TTL must be retrievable")
	assert.Equal(t, "saml", got.Protocol)
}

func TestPendingLoginStore_OIDC_RoundTrip(t *testing.T) {
	db := NewMemoryDB()
	s := NewPendingLoginStore(db, "test")
	ctx := context.Background()

	require.NoError(t, s.Create(ctx, &PendingLogin{
		FlowID:        "flow-4",
		Protocol:      "oidc",
		TenantSlug:    "acme",
		SourceID:      "src-2",
		AppID:         "app-2",
		AuthRequestID: "ar-42",
	}, 10*time.Minute))

	got, err := s.Get(ctx, "flow-4")
	require.NoError(t, err)
	assert.Equal(t, "oidc", got.Protocol)
	assert.Equal(t, "ar-42", got.AuthRequestID)
}
