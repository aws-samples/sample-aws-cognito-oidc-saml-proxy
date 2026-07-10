package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditStore_LogStep(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")

	err := auditStore.LogStep(context.Background(), "tenant-a", "flow-001", "authn-request", "https://sp.example.com", "user-123", map[string]string{
		"binding": "HTTP-POST",
	})
	require.NoError(t, err)
}

func TestAuditStore_GetFlow(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")

	// Log multiple steps
	err := auditStore.LogStep(context.Background(), "tenant-a", "flow-002", "authn-request", "https://sp.example.com", "user-456", nil)
	require.NoError(t, err)

	err = auditStore.LogStep(context.Background(), "tenant-a", "flow-002", "assertion-issued", "https://sp.example.com", "user-456", map[string]string{
		"nameId": "user-456",
	})
	require.NoError(t, err)

	steps, err := auditStore.GetFlow(context.Background(), "tenant-a", "flow-002")
	require.NoError(t, err)
	assert.Len(t, steps, 2)
}

func TestAuditStore_GetFlow_Empty(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")

	steps, err := auditStore.GetFlow(context.Background(), "tenant-a", "nonexistent-flow")
	require.NoError(t, err)
	assert.Empty(t, steps)
}

// TestAuditStore_GetFlow_CrossTenantIsolation verifies that a flow logged under
// one tenant is never returned when queried under another tenant's slug — the
// flowID alone cannot reach across tenants because each tenant's steps live in a
// separate partition.
func TestAuditStore_GetFlow_CrossTenantIsolation(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")
	ctx := context.Background()

	// Both tenants happen to use the same flowID.
	require.NoError(t, auditStore.LogStep(ctx, "tenant-a", "shared-flow", "sso_initiated", "https://sp.example.com", "user-a", nil))
	require.NoError(t, auditStore.LogStep(ctx, "tenant-b", "shared-flow", "sso_initiated", "https://sp.example.com", "user-b", nil))

	aSteps, err := auditStore.GetFlow(ctx, "tenant-a", "shared-flow")
	require.NoError(t, err)
	require.Len(t, aSteps, 1)
	assert.Equal(t, "user-a", aSteps[0].UserID, "tenant-a must see only its own step")

	bSteps, err := auditStore.GetFlow(ctx, "tenant-b", "shared-flow")
	require.NoError(t, err)
	require.Len(t, bSteps, 1)
	assert.Equal(t, "user-b", bSteps[0].UserID, "tenant-b must see only its own step")

	// A tenant that never logged this flow gets nothing.
	other, err := auditStore.GetFlow(ctx, "tenant-c", "shared-flow")
	require.NoError(t, err)
	assert.Empty(t, other)
}

func TestAuditStore_SequenceIncrement(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")

	// Log three steps in the same flow
	for i := 0; i < 3; i++ {
		err := auditStore.LogStep(context.Background(), "tenant-a", "flow-seq", "step", "https://sp.example.com", "user", nil)
		require.NoError(t, err)
	}

	steps, err := auditStore.GetFlow(context.Background(), "tenant-a", "flow-seq")
	require.NoError(t, err)
	assert.Len(t, steps, 3)

	// Verify sequences are unique and increasing
	seen := make(map[uint64]bool)
	for _, s := range steps {
		assert.False(t, seen[s.Sequence], "duplicate sequence number")
		seen[s.Sequence] = true
	}
}

// TestAuditStore_LogStep_ColdInstancesDoNotOverwrite simulates two Lambda cold
// starts writing steps for the SAME stable flowID. A sort key derived from an
// in-process atomic counter resets to 0 on every cold start, so both instances
// would produce STEP#0000000001 and the second Put would overwrite the first at
// the same (PK,SK) — losing an audit record. The timestamp+random sort key gives
// the two writers distinct sort keys, so both steps survive.
func TestAuditStore_LogStep_ColdInstancesDoNotOverwrite(t *testing.T) {
	// A single shared backing store represents the shared DynamoDB table; the two
	// AuditStore instances are the two cold Lambda processes, each with its own
	// freshly-zeroed seqNum counter.
	db := NewMemoryDB()
	cold1 := NewAuditStore(db, "test")
	cold2 := NewAuditStore(db, "test")
	ctx := context.Background()

	require.NoError(t, cold1.LogStep(ctx, "tenant-a", "shared-flow", "sso_initiated", "https://sp.example.com", "user-1", nil))
	require.NoError(t, cold2.LogStep(ctx, "tenant-a", "shared-flow", "sso_complete", "https://sp.example.com", "user-1", nil))

	// Both cold writers start their counter at zero, so a counter-derived sort key
	// would collide on STEP#0000000001 and only one step would remain.
	steps, err := cold1.GetFlow(ctx, "tenant-a", "shared-flow")
	require.NoError(t, err)
	assert.Len(t, steps, 2, "both cold-instance steps must survive — no (PK,SK) overwrite")
}

// TestStepSortKey_UniqueAndTimeOrdered verifies the sort key is collision-free
// across processes (each call yields a distinct key even at the same instant),
// keeps the STEP# prefix so existing prefix queries work, and sorts
// lexicographically in timestamp order.
func TestStepSortKey_UniqueAndTimeOrdered(t *testing.T) {
	now := time.Now()

	// Many keys stamped at the exact same instant must all differ (the random
	// suffix breaks ties — an in-process counter would repeat across cold starts).
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		sk := stepSortKey(now)
		assert.True(t, strings.HasPrefix(sk, "STEP#"), "sort key must keep STEP# prefix for prefix queries")
		assert.False(t, seen[sk], "sort keys must be collision-free even at an identical timestamp")
		seen[sk] = true
	}

	// A later timestamp must sort lexicographically after an earlier one so
	// prefix queries return steps in chronological order.
	earlier := stepSortKey(now)
	later := stepSortKey(now.Add(time.Millisecond))
	assert.Less(t, earlier, later, "later timestamps must sort after earlier ones lexicographically")
}

func TestAuditStore_GetRecentSteps(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")

	// Log steps in multiple flows with different timestamps
	ctx := context.Background()
	err := auditStore.LogStep(ctx, "tenant-a", "flow-001", "sso_initiated", "https://sp1.example.com", "", nil)
	require.NoError(t, err)

	err = auditStore.LogStep(ctx, "tenant-a", "flow-002", "sso_initiated", "https://sp2.example.com", "", nil)
	require.NoError(t, err)

	err = auditStore.LogStep(ctx, "tenant-a", "flow-001", "sso_complete", "https://sp1.example.com", "user@example.com", map[string]string{
		"status": "success",
	})
	require.NoError(t, err)

	// Get recent steps (limit 2)
	steps, err := auditStore.GetRecentSteps(ctx, "tenant-a", 2)
	require.NoError(t, err)
	assert.Len(t, steps, 2)

	// Verify the most recent step is first
	assert.Equal(t, "sso_complete", steps[0].StepType)

	// Get all steps (limit 10)
	allSteps, err := auditStore.GetRecentSteps(ctx, "tenant-a", 10)
	require.NoError(t, err)
	assert.Len(t, allSteps, 3)
}

// TestAuditStore_GetRecentSteps_CrossTenantIsolation verifies that the recent-
// steps scan is bounded to the caller's tenant partition and never surfaces
// another tenant's activity.
func TestAuditStore_GetRecentSteps_CrossTenantIsolation(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")
	ctx := context.Background()

	require.NoError(t, auditStore.LogStep(ctx, "tenant-a", "flow-a1", "sso_initiated", "https://sp.example.com", "", nil))
	require.NoError(t, auditStore.LogStep(ctx, "tenant-a", "flow-a2", "sso_initiated", "https://sp.example.com", "", nil))
	require.NoError(t, auditStore.LogStep(ctx, "tenant-b", "flow-b1", "sso_initiated", "https://sp.example.com", "", nil))

	aSteps, err := auditStore.GetRecentSteps(ctx, "tenant-a", 100)
	require.NoError(t, err)
	assert.Len(t, aSteps, 2, "tenant-a must see only its own two steps")

	bSteps, err := auditStore.GetRecentSteps(ctx, "tenant-b", 100)
	require.NoError(t, err)
	assert.Len(t, bSteps, 1, "tenant-b must see only its own step")
	assert.Equal(t, "flow-b1", bSteps[0].FlowID)
}

func TestAuditStore_GetRecentSteps_Empty(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")

	steps, err := auditStore.GetRecentSteps(context.Background(), "tenant-a", 10)
	require.NoError(t, err)
	assert.Empty(t, steps)
}

// nonScannableDB implements TableAPI but NOT ScanByPKPrefix, to exercise the
// error path of GetRecentSteps for a store that cannot be scanned.
type nonScannableDB struct{}

func (nonScannableDB) Put(context.Context, interface{}) error            { return nil }
func (nonScannableDB) PutIfNotExists(context.Context, interface{}) error { return nil }
func (nonScannableDB) Get(context.Context, string, string, interface{}) error {
	return ErrNotFound
}
func (nonScannableDB) Query(context.Context, string, string, interface{}) error    { return nil }
func (nonScannableDB) QueryGSI(context.Context, string, string, interface{}) error { return nil }
func (nonScannableDB) Delete(context.Context, string, string) error                { return nil }

func TestAuditStore_GetRecentSteps_NonScannable(t *testing.T) {
	auditStore := NewAuditStore(nonScannableDB{}, "test")

	_, err := auditStore.GetRecentSteps(context.Background(), "tenant-a", 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scannable store")
}

func TestAuditStore_GetRecentSteps_ZeroLimit(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")
	require.NoError(t, auditStore.LogStep(context.Background(), "tenant-a", "flow-1", "sso_initiated", "sp", "", nil))

	steps, err := auditStore.GetRecentSteps(context.Background(), "tenant-a", 0)
	require.NoError(t, err)
	assert.Empty(t, steps)
}

// TestAuditStore_GetRecentSteps_TieBreakBySequence verifies that when two steps
// carry the same timestamp, the one with the higher sequence sorts first, so
// ordering is deterministic for sub-millisecond bursts.
func TestAuditStore_GetRecentSteps_TieBreakBySequence(t *testing.T) {
	db := NewMemoryDB()
	auditStore := NewAuditStore(db, "test")
	ctx := context.Background()

	ts := time.Now()
	// Insert two flow steps with identical timestamps but different sequences.
	// The partition key must be tenant-qualified so GetRecentSteps' tenant-scoped
	// scan finds them.
	lower := &flowStepItem{
		PK:  flowPK("tenant-a", "tie"),
		SK:  "STEP#0000000005",
		TTL: ts.Add(24 * time.Hour).Unix(),
		FlowStep: domain.FlowStep{
			FlowID: "tie", Sequence: 5, StepType: "first", Timestamp: ts,
		},
	}
	higher := &flowStepItem{
		PK:  flowPK("tenant-a", "tie"),
		SK:  "STEP#0000000007",
		TTL: ts.Add(24 * time.Hour).Unix(),
		FlowStep: domain.FlowStep{
			FlowID: "tie", Sequence: 7, StepType: "second", Timestamp: ts,
		},
	}
	require.NoError(t, db.Put(ctx, lower))
	require.NoError(t, db.Put(ctx, higher))

	steps, err := auditStore.GetRecentSteps(ctx, "tenant-a", 10)
	require.NoError(t, err)
	require.Len(t, steps, 2)
	assert.Equal(t, uint64(7), steps[0].Sequence, "higher sequence must sort first on timestamp tie")
	assert.Equal(t, uint64(5), steps[1].Sequence)
}
