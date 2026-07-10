package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCWLogsClient records calls to PutLogEvents and CreateLogStream.
type mockCWLogsClient struct {
	putCalls    []cloudwatchlogs.PutLogEventsInput
	streamCalls []cloudwatchlogs.CreateLogStreamInput
	putErr      error
	streamErr   error
}

func (m *mockCWLogsClient) PutLogEvents(_ context.Context, params *cloudwatchlogs.PutLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	m.putCalls = append(m.putCalls, *params)
	return &cloudwatchlogs.PutLogEventsOutput{}, m.putErr
}

func (m *mockCWLogsClient) CreateLogStream(_ context.Context, params *cloudwatchlogs.CreateLogStreamInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	m.streamCalls = append(m.streamCalls, *params)
	return &cloudwatchlogs.CreateLogStreamOutput{}, m.streamErr
}

func TestLogger_Log_WritesBothDestinations(t *testing.T) {
	cwMock := &mockCWLogsClient{}
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(cwMock, ddbStore, "/test/audit")

	err := logger.LogStep(context.Background(),
		"acme", "flow-001", "sso_initiated", "https://sp.example.com", "user-123",
		map[string]string{"tenant": "acme", "binding": "HTTP-POST"},
	)
	require.NoError(t, err)

	// Verify CW Logs received the event
	require.Len(t, cwMock.putCalls, 1)
	assert.Equal(t, "/test/audit", *cwMock.putCalls[0].LogGroupName)
	require.Len(t, cwMock.putCalls[0].LogEvents, 1)

	// Verify the CW message is valid JSON with expected fields
	var event Event
	err = json.Unmarshal([]byte(*cwMock.putCalls[0].LogEvents[0].Message), &event)
	require.NoError(t, err)
	assert.Equal(t, "acme", event.Tenant)
	assert.Equal(t, "flow-001", event.FlowID)
	assert.Equal(t, "sso_initiated", event.Step)
	assert.Equal(t, "user-123", event.User)
	assert.Equal(t, "https://sp.example.com", event.Application)

	// Verify DynamoDB received the event (via GetFlow)
	steps, err := logger.GetFlow(context.Background(), "acme", "flow-001")
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "sso_initiated", steps[0].StepType)
	assert.Equal(t, "user-123", steps[0].UserID)
}

func TestLogger_Log_CWLogsFails_StillWritesDDB(t *testing.T) {
	cwMock := &mockCWLogsClient{putErr: errors.New("throttled")}
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(cwMock, ddbStore, "/test/audit")

	// CW Logs fails, but LogStep should still succeed (best effort for CW)
	err := logger.LogStep(context.Background(),
		"tenant-a", "flow-002", "assertion_issued", "https://sp.example.com", "user-456",
		map[string]string{"status": "success"},
	)
	require.NoError(t, err)

	// CW was attempted
	assert.Len(t, cwMock.putCalls, 1)

	// DDB still has the step
	steps, err := logger.GetFlow(context.Background(), "tenant-a", "flow-002")
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "assertion_issued", steps[0].StepType)
}

func TestLogger_LogStep_CompatInterface(t *testing.T) {
	cwMock := &mockCWLogsClient{}
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(cwMock, ddbStore, "/test/audit")

	// Empty slug exercises the payload["tenant"] fallback: the record is still
	// tenant-tagged (and partitioned) as "beta" from the payload.
	err := logger.LogStep(context.Background(),
		"", "flow-003", "slo_request", "https://sp2.example.com", "user-789",
		map[string]string{"tenant": "beta", "reason": "user-initiated"},
	)
	require.NoError(t, err)

	// Verify via GetFlow
	steps, err := logger.GetFlow(context.Background(), "beta", "flow-003")
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "slo_request", steps[0].StepType)
	assert.Equal(t, "https://sp2.example.com", steps[0].SPEntityID)

	// Verify CW log contains tenant from payload
	var event Event
	err = json.Unmarshal([]byte(*cwMock.putCalls[0].LogEvents[0].Message), &event)
	require.NoError(t, err)
	assert.Equal(t, "beta", event.Tenant)
}

func TestLogger_GetRecentSteps(t *testing.T) {
	cwMock := &mockCWLogsClient{}
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(cwMock, ddbStore, "/test/audit")

	ctx := context.Background()

	// Log several steps
	require.NoError(t, logger.LogStep(ctx, "tenant-a", "flow-a", "sso_initiated", "https://sp1.example.com", "", nil))
	require.NoError(t, logger.LogStep(ctx, "tenant-a", "flow-b", "sso_initiated", "https://sp2.example.com", "", nil))
	require.NoError(t, logger.LogStep(ctx, "tenant-a", "flow-a", "sso_complete", "https://sp1.example.com", "user@example.com",
		map[string]string{"status": "success"}))

	// GetRecentSteps delegates to the DDB store
	steps, err := logger.GetRecentSteps(ctx, "tenant-a", 2)
	require.NoError(t, err)
	assert.Len(t, steps, 2)
	// Most recent first
	assert.Equal(t, "sso_complete", steps[0].StepType)
}

func TestLogger_NilCWClient(t *testing.T) {
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(nil, ddbStore, "")

	// Should work fine without CW client
	err := logger.LogStep(context.Background(),
		"tenant-a", "flow-nil", "test_step", "https://sp.example.com", "user", nil)
	require.NoError(t, err)

	steps, err := logger.GetFlow(context.Background(), "tenant-a", "flow-nil")
	require.NoError(t, err)
	assert.Len(t, steps, 1)
}

func TestLogger_NilDDBStore(t *testing.T) {
	cwMock := &mockCWLogsClient{}
	logger := NewLoggerForTest(cwMock, nil, "/test/audit")

	// CW writes succeed, DDB is nil — should not panic
	err := logger.LogStep(context.Background(),
		"tenant-a", "flow-nodb", "test_step", "https://sp.example.com", "user", nil)
	require.NoError(t, err)

	// CW received the event
	assert.Len(t, cwMock.putCalls, 1)

	// GetFlow/GetRecentSteps return nil when DDB is nil
	steps, err := logger.GetFlow(context.Background(), "tenant-a", "flow-nodb")
	require.NoError(t, err)
	assert.Nil(t, steps)

	recent, err := logger.GetRecentSteps(context.Background(), "tenant-a", 10)
	require.NoError(t, err)
	assert.Nil(t, recent)
}

func TestLogger_StatusFromPayload(t *testing.T) {
	cwMock := &mockCWLogsClient{}
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(cwMock, ddbStore, "/test/audit")

	// With explicit status in payload
	err := logger.LogStep(context.Background(),
		"tenant-a", "flow-status", "error_step", "https://sp.example.com", "user",
		map[string]string{"status": "error", "detail": "invalid signature"},
	)
	require.NoError(t, err)

	var event Event
	err = json.Unmarshal([]byte(*cwMock.putCalls[0].LogEvents[0].Message), &event)
	require.NoError(t, err)
	assert.Equal(t, "error", event.Status)

	// Without status in payload — defaults to "info"
	err = logger.LogStep(context.Background(),
		"tenant-a", "flow-default", "plain_step", "https://sp.example.com", "user",
		map[string]string{"detail": "no status key"},
	)
	require.NoError(t, err)

	err = json.Unmarshal([]byte(*cwMock.putCalls[1].LogEvents[0].Message), &event)
	require.NoError(t, err)
	assert.Equal(t, "info", event.Status)
}

// TestNewLogger_NilCWClient_FailsClosedInDeployedEnv asserts that constructing
// the logger with a nil CloudWatch client returns an error in every deployed
// environment (fail closed), so a deploy that forgot to wire the client cannot
// silently run with no durable audit trail once the 24h DynamoDB cache expires.
func TestNewLogger_NilCWClient_FailsClosedInDeployedEnv(t *testing.T) {
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")

	for _, env := range []config.Environment{config.EnvDev, config.EnvStaging, config.EnvProd} {
		t.Run(string(env), func(t *testing.T) {
			logger, err := NewLogger(env, nil, ddbStore, "/test/audit")
			require.Error(t, err, "nil CW client must be a construction error in %q", env)
			assert.Nil(t, logger)
			assert.Contains(t, err.Error(), "CloudWatch Logs client is required")
		})
	}
}

// TestNewLogger_NilCWClient_AllowedInLocal asserts that the local developer
// environment still tolerates a nil CloudWatch client — the explicit local/test
// double — and produces a usable logger.
func TestNewLogger_NilCWClient_AllowedInLocal(t *testing.T) {
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")

	logger, err := NewLogger(config.EnvLocal, nil, ddbStore, "/test/audit")
	require.NoError(t, err)
	require.NotNil(t, logger)

	// The nil-CW logger still writes the DynamoDB cache.
	require.NoError(t, logger.LogStep(context.Background(),
		"tenant-a", "flow-local", "sso_initiated", "https://sp.example.com", "user", nil))
	steps, err := logger.GetFlow(context.Background(), "tenant-a", "flow-local")
	require.NoError(t, err)
	assert.Len(t, steps, 1)
}

// TestNewLogger_WithCWClient_SucceedsInDeployedEnv asserts that a real client
// yields a working logger in a deployed environment (the intended path).
func TestNewLogger_WithCWClient_SucceedsInDeployedEnv(t *testing.T) {
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")

	logger, err := NewLogger(config.EnvProd, &mockCWLogsClient{}, ddbStore, "/test/audit")
	require.NoError(t, err)
	require.NotNil(t, logger)
}

// TestLogger_CWWriteFailure_EmitsMetric asserts that a CloudWatch write failure
// is surfaced as an observable metric record (not silently swallowed), so an
// alarm can be attached before the audit trail degrades.
func TestLogger_CWWriteFailure_EmitsMetric(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cwMock := &mockCWLogsClient{putErr: errors.New("throttled")}
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(cwMock, ddbStore, "/test/audit")

	err := logger.LogStep(context.Background(),
		"tenant-a", "flow-metric", "assertion_issued", "https://sp.example.com", "user-1",
		map[string]string{"status": "success"})
	require.NoError(t, err)

	// The failed write must have produced a distinct metric record carrying the
	// namespace and metric name an alarm keys off.
	var sawMetric bool
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal(line, &rec))
		if rec["msg"] == "audit_metric" {
			sawMetric = true
			assert.Equal(t, auditMetricNamespace, rec["namespace"])
			assert.Equal(t, metricCloudWatchWriteFailure, rec["metric"])
			assert.EqualValues(t, 1, rec["value"])
			assert.Equal(t, "tenant-a", rec["tenant"])
			assert.Equal(t, "flow-metric", rec["flowId"])
		}
	}
	assert.True(t, sawMetric, "a CW write failure must emit an observable audit_metric record")
}

// TestLogger_CWWriteSuccess_NoFailureMetric guards against false alarms: a
// successful CloudWatch write must not emit the failure metric.
func TestLogger_CWWriteSuccess_NoFailureMetric(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cwMock := &mockCWLogsClient{}
	memDB := store.NewMemoryDB()
	ddbStore := store.NewAuditStore(memDB, "test")
	logger := NewLoggerForTest(cwMock, ddbStore, "/test/audit")

	require.NoError(t, logger.LogStep(context.Background(),
		"tenant-a", "flow-ok", "assertion_issued", "https://sp.example.com", "user-1", nil))

	assert.NotContains(t, buf.String(), metricCloudWatchWriteFailure,
		"a successful CW write must not emit the failure metric")
}
