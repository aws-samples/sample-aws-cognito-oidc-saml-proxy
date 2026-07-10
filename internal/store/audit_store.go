package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
)

// AuditStore provides flow tracing and audit logging.
type AuditStore struct {
	db TableAPI
	// seqNum is a process-local counter that populates FlowStep.Sequence, used
	// only as a secondary tie-break when two steps share a timestamp in the
	// recent-steps view. It deliberately does NOT drive the DynamoDB sort key
	// (see stepSortKey) — an in-process counter resets on every cold start and
	// would collide across instances.
	seqNum atomic.Uint64
}

// Compile-time check: AuditStore implements domain.AuditRepository.
var _ domain.AuditRepository = (*AuditStore)(nil)

// FlowStep is an alias for domain.FlowStep for backward compatibility.
type FlowStep = domain.FlowStep

// flowStepItem wraps domain.FlowStep with DynamoDB key fields.
type flowStepItem struct {
	PK     string `dynamo:"PK,hash" json:"-"`
	SK     string `dynamo:"SK,range" json:"-"`
	TTL    int64  `dynamo:"ttl" json:"-"` // DynamoDB TTL — 24h cache; permanent record in CloudWatch Logs
	GSI2PK string `dynamo:"GSI2PK" json:"-"`
	GSI2SK string `dynamo:"GSI2SK" json:"-"`
	domain.FlowStep
}

// NewAuditStore creates a new AuditStore.
func NewAuditStore(db TableAPI, tableName string) *AuditStore {
	return &AuditStore{db: db}
}

// flowPK builds the tenant-qualified partition key for a flow's steps. Scoping
// the partition to the tenant is what makes cross-tenant reads impossible: a
// query for tenant A's flow never touches tenant B's items. Tenant slugs
// match ^[a-z][a-z0-9-]{2,30}$ so they never contain the '#' delimiter.
func flowPK(tenantSlug, flowID string) string {
	return fmt.Sprintf("TENANT#%s#FLOW#%s", tenantSlug, flowID)
}

// flowPKPrefix builds the partition-key prefix that matches every flow of a
// single tenant, used to bound the recent-steps scan to that tenant.
func flowPKPrefix(tenantSlug string) string {
	return fmt.Sprintf("TENANT#%s#FLOW#", tenantSlug)
}

// stepSortKeyTimeLayout is an RFC3339 layout with a FIXED-WIDTH nanosecond
// fraction. time.RFC3339Nano trims trailing zeros, which breaks lexicographic
// ordering (".12Z" would sort before ".1Z" because '2' < 'Z'); zero-padding to
// nine digits keeps string order identical to chronological order.
const stepSortKeyTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// stepSortKey builds a process-independent, monotonic sort key for a flow step.
// A key based on an in-process atomic counter (STEP#<counter>) is unsafe here:
// the counter resets to 0 on every Lambda cold start, so two cold instances
// writing the same stable flowID would reuse STEP#0000000001... and silently
// overwrite each other at the same (PK,SK), losing audit records. Instead we
// key on the event timestamp at nanosecond precision — the fixed-width RFC3339
// layout sorts lexicographically in time order, so prefix queries still return
// steps oldest-first — plus a random suffix that breaks ties when two writers
// stamp the same instant. The STEP# prefix is kept so prefix queries ("STEP#")
// keep working.
func stepSortKey(now time.Time) string {
	var b [8]byte
	// crypto/rand.Read never returns a short read; on the practically
	// impossible error path fall back to the nanosecond count so the key stays
	// collision-resistant rather than empty.
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("STEP#%s#%016x", now.UTC().Format(stepSortKeyTimeLayout), uint64(now.UnixNano()))
	}
	return fmt.Sprintf("STEP#%s#%s", now.UTC().Format(stepSortKeyTimeLayout), hex.EncodeToString(b[:]))
}

// LogStep logs a step in a SAML flow under the given tenant.
func (a *AuditStore) LogStep(ctx context.Context, tenantSlug, flowID, stepType, spEntityID, userID string, payload map[string]string) error {
	now := time.Now()
	seq := a.seqNum.Add(1)

	step := &flowStepItem{
		PK:     flowPK(tenantSlug, flowID),
		SK:     stepSortKey(now),               // Timestamp + random suffix: monotonic and collision-free across processes
		TTL:    now.Add(24 * time.Hour).Unix(), // 24h DynamoDB cache; permanent record in CloudWatch Logs
		GSI2PK: fmt.Sprintf("USER#%s", userID),
		GSI2SK: fmt.Sprintf("FLOW#%s", flowID),
		FlowStep: domain.FlowStep{
			FlowID:     flowID,
			Sequence:   seq,
			StepType:   stepType,
			SPEntityID: spEntityID,
			UserID:     userID,
			Timestamp:  now,
			Payload:    payload,
		},
	}

	if err := a.db.Put(ctx, step); err != nil {
		return fmt.Errorf("failed to log flow step: %w", err)
	}

	return nil
}

// GetFlow retrieves all steps for a given flow ID within the caller's tenant,
// ordered by sequence. A flow owned by another tenant lives under a different
// partition key and therefore resolves as empty — the flowID alone can never
// reach across tenants.
func (a *AuditStore) GetFlow(ctx context.Context, tenantSlug, flowID string) ([]domain.FlowStep, error) {
	pk := flowPK(tenantSlug, flowID)

	var items []flowStepItem
	if err := a.db.Query(ctx, pk, "STEP#", &items); err != nil && err != ErrNotFound {
		return nil, fmt.Errorf("failed to query flow steps: %w", err)
	}

	steps := make([]domain.FlowStep, len(items))
	for i, item := range items {
		steps[i] = item.FlowStep
	}

	return steps, nil
}

// GetRecentSteps retrieves the most recent flow steps for a single tenant,
// sorted by timestamp descending, limited to the specified count.
//
// The scan is bounded to the tenant's own partition-key prefix
// (TENANT#<slug>#FLOW#), so it can never surface another tenant's activity.
// Both MemoryDB and the production DynamoDB store implement ScanByPKPrefix, so
// a single path serves both. There is no efficient time-ordered access pattern
// without a dedicated GSI on timestamp; the session table's 24h TTL keeps the
// scanned set bounded, which is acceptable for the admin "recent activity"
// view. A time-ordered GSI would be the path to scale this further.
func (a *AuditStore) GetRecentSteps(ctx context.Context, tenantSlug string, limit int) ([]domain.FlowStep, error) {
	if limit <= 0 {
		return []domain.FlowStep{}, nil
	}

	scanner, ok := a.db.(interface {
		ScanByPKPrefix(ctx context.Context, prefix string, out interface{}) error
	})
	if !ok {
		return nil, fmt.Errorf("audit: recent-steps query requires a scannable store (got %T)", a.db)
	}

	var items []flowStepItem
	if err := scanner.ScanByPKPrefix(ctx, flowPKPrefix(tenantSlug), &items); err != nil {
		return nil, fmt.Errorf("failed to scan flow steps: %w", err)
	}

	all := make([]domain.FlowStep, len(items))
	for i, item := range items {
		all[i] = item.FlowStep
	}

	// Most recent first. Timestamp ties are broken by the monotonic per-flow
	// sequence so ordering is deterministic even for sub-millisecond bursts.
	sort.Slice(all, func(i, j int) bool {
		if all[i].Timestamp.Equal(all[j].Timestamp) {
			return all[i].Sequence > all[j].Sequence
		}
		return all[i].Timestamp.After(all[j].Timestamp)
	})

	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}
