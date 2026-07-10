package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

// Compile-time check: Logger implements domain.AuditRepository.
var _ domain.AuditRepository = (*Logger)(nil)

// Audit-durability metric emitted when a CloudWatch Logs write fails. Combined
// with the 24h DynamoDB TTL, a sustained CW outage silently degrades to no
// durable audit trail; publishing this metric lets an alarm catch the
// outage before the last copy of the trail expires. The emission reuses the
// structured-slog metric convention already used elsewhere (see
// internal/middleware/metrics.go) rather than introducing a new metrics
// dependency; an operator attaches a metric filter / EMF extraction on it.
const (
	auditMetricNamespace         = "IdentityGateway/Audit"
	metricCloudWatchWriteFailure = "AuditCloudWatchWriteFailure"
)

// Event represents a structured audit event for CloudWatch Logs.
type Event struct {
	Tenant      string            `json:"tenant"`
	FlowID      string            `json:"flowId"`
	Step        string            `json:"step"`
	User        string            `json:"user,omitempty"`
	Application string            `json:"application,omitempty"`
	Status      string            `json:"status"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CloudWatchLogsClient is the interface for the CW Logs SDK operations we use.
type CloudWatchLogsClient interface {
	PutLogEvents(ctx context.Context, params *cloudwatchlogs.PutLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
	CreateLogStream(ctx context.Context, params *cloudwatchlogs.CreateLogStreamInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error)
}

// Logger writes audit events to CloudWatch Logs (permanent record) and
// DynamoDB (24h cache for the dashboard). It delegates DDB read operations
// (GetFlow, GetRecentSteps) to the underlying store.AuditStore.
type Logger struct {
	cwClient CloudWatchLogsClient
	ddbStore *store.AuditStore
	logGroup string // e.g., "/identity-gateway/audit"
}

// NewLogger creates a new audit Logger for the given deployment environment.
//
// CloudWatch Logs is the permanent audit record; DynamoDB is only a 24h cache
// (see store.flowStepItem TTL). A nil cwClient therefore means "no durable
// audit trail". In any deployed environment that is a fail-closed construction
// error rather than a silent skip: the caller must abort boot. A nil
// client is tolerated ONLY in the local developer environment, where it is the
// explicit local/test double.
//
// For the local/test double, prefer NewLoggerForTest, which is unconditionally
// nil-tolerant and does not require an environment argument.
func NewLogger(env config.Environment, cwClient CloudWatchLogsClient, ddbStore *store.AuditStore, logGroup string) (*Logger, error) {
	if cwClient == nil && !env.IsLocal() {
		return nil, fmt.Errorf("audit: CloudWatch Logs client is required in %q environment (nil client would drop the permanent audit trail once the 24h DynamoDB cache expires)", env)
	}
	return &Logger{
		cwClient: cwClient,
		ddbStore: ddbStore,
		logGroup: logGroup,
	}, nil
}

// NewLoggerForTest constructs a Logger without an environment gate, tolerating a
// nil cwClient. It is the explicit local/test double for unit tests and the
// opt-in local developer path — never the deployed path, which must go through
// NewLogger so a missing CloudWatch client fails closed.
func NewLoggerForTest(cwClient CloudWatchLogsClient, ddbStore *store.AuditStore, logGroup string) *Logger {
	return &Logger{
		cwClient: cwClient,
		ddbStore: ddbStore,
		logGroup: logGroup,
	}
}

// LogStep writes a flow step to CloudWatch Logs (primary) and DynamoDB (cache)
// under the given tenant. Implements domain.AuditRepository.
func (l *Logger) LogStep(ctx context.Context, tenantSlug, flowID, stepType, spEntityID, userID string, payload map[string]string) error {
	// The tenant argument is authoritative for the audit record. Keep the
	// legacy payload["tenant"] as a fallback only when the caller passed an
	// empty slug, so existing callers that stashed it in the payload still tag
	// the CloudWatch event correctly.
	tenant := tenantSlug
	if tenant == "" && payload != nil {
		tenant = payload["tenant"]
	}
	status := "info"
	if payload != nil {
		if s, ok := payload["status"]; ok {
			status = s
		}
	}

	event := Event{
		Tenant:      tenant,
		FlowID:      flowID,
		Step:        stepType,
		User:        userID,
		Application: spEntityID,
		Status:      status,
		Timestamp:   time.Now(),
		Metadata:    payload,
	}

	// Write to CloudWatch Logs (permanent audit record). The write is best
	// effort for this request's latency, but a failure must not be swallowed:
	// with only the 24h DynamoDB cache left, a sustained CW outage silently
	// erodes the durable audit trail. Emit a metric alongside the Warn
	// so an alarm can fire before the trail is lost.
	if l.cwClient != nil {
		if err := l.writeToCWLogs(ctx, event); err != nil {
			slog.Warn("failed to write audit to CloudWatch Logs",
				"error", err, "flowId", flowID, "step", stepType)
			l.emitWriteFailureMetric(tenant, flowID, stepType, err)
		}
	}

	// Write to DynamoDB (24h cache) via the existing AuditStore
	if l.ddbStore != nil {
		if err := l.ddbStore.LogStep(ctx, tenant, flowID, stepType, spEntityID, userID, payload); err != nil {
			return fmt.Errorf("audit ddb write: %w", err)
		}
	}

	return nil
}

// GetFlow delegates to the DynamoDB AuditStore, scoped to tenantSlug.
// Implements domain.AuditRepository.
func (l *Logger) GetFlow(ctx context.Context, tenantSlug, flowID string) ([]domain.FlowStep, error) {
	if l.ddbStore == nil {
		return nil, nil
	}
	return l.ddbStore.GetFlow(ctx, tenantSlug, flowID)
}

// GetRecentSteps delegates to the DynamoDB AuditStore, scoped to tenantSlug.
// Implements domain.AuditRepository.
func (l *Logger) GetRecentSteps(ctx context.Context, tenantSlug string, limit int) ([]domain.FlowStep, error) {
	if l.ddbStore == nil {
		return nil, nil
	}
	return l.ddbStore.GetRecentSteps(ctx, tenantSlug, limit)
}

// emitWriteFailureMetric publishes the audit-durability metric for a failed
// CloudWatch Logs write. It follows the codebase's structured-slog
// metric convention (see internal/middleware/metrics.go): a distinct log record
// carrying a namespace, metric name, and unit value of 1, from which an
// operator extracts a CloudWatch metric (metric filter or EMF) and attaches an
// alarm. This keeps the failure observable instead of silently dropped.
func (l *Logger) emitWriteFailureMetric(tenant, flowID, stepType string, cause error) {
	slog.Error("audit_metric",
		"namespace", auditMetricNamespace,
		"metric", metricCloudWatchWriteFailure,
		"value", 1,
		"tenant", tenant,
		"flowId", flowID,
		"step", stepType,
		"error", cause,
	)
}

func (l *Logger) writeToCWLogs(ctx context.Context, event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	streamName := event.Timestamp.Format("2006/01/02")

	// Create log stream if it doesn't exist (idempotent — ResourceAlreadyExistsException is fine)
	_, _ = l.cwClient.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  &l.logGroup,
		LogStreamName: &streamName,
	})

	_, err = l.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &l.logGroup,
		LogStreamName: &streamName,
		LogEvents: []types.InputLogEvent{{
			Message:   aws.String(string(data)),
			Timestamp: aws.Int64(event.Timestamp.UnixMilli()),
		}},
	})
	return err
}
