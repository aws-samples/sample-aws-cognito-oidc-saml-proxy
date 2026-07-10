package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestDebugAPI(t *testing.T) (humatest.TestAPI, *store.AuditStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	// Create in-memory store for tests
	db := store.NewMemoryDB()
	auditStore := store.NewAuditStore(db, "test-table")

	// The debug read handlers are tenant-scoped; inject a test tenant so
	// the caller has a tenant context, mirroring the API-path middleware.
	api.UseMiddleware(injectTenantMiddleware(testTenantSlug))

	RegisterDebugRoutes(api, auditStore)
	return api, auditStore
}

func TestDecodeAssertion_ValidBase64(t *testing.T) {
	api, _ := newTestDebugAPI(t)

	// base64 of "<saml:Assertion>test</saml:Assertion>"
	resp := api.Post("/api/v1/debug/decode-assertion", strings.NewReader(`{
		"assertion": "PHNhbWw6QXNzZXJ0aW9uPnRlc3Q8L3NhbWw6QXNzZXJ0aW9uPg=="
	}`))

	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "<saml:Assertion>test</saml:Assertion>", result["decodedXml"])
	assert.NotNil(t, result["attributes"])
}

func TestDecodeAssertion_InvalidBase64(t *testing.T) {
	api, _ := newTestDebugAPI(t)

	resp := api.Post("/api/v1/debug/decode-assertion", strings.NewReader(`{
		"assertion": "not-valid-base64!!!"
	}`))

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestGetAuditLog(t *testing.T) {
	api, _ := newTestDebugAPI(t)

	resp := api.Get("/api/v1/debug/audit-log")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	events, ok := result["events"].([]interface{})
	require.True(t, ok)
	assert.Empty(t, events)
}

func TestAuditLog_ReturnsFlowSteps(t *testing.T) {
	api, auditStore := newTestDebugAPI(t)
	ctx := context.Background()

	// Log some flow steps under the caller's tenant.
	err := auditStore.LogStep(ctx, testTenantSlug, "flow-1", "sso_initiated", "https://sp1.example.com", "user1", map[string]string{"ip": "192.0.2.1"})
	require.NoError(t, err)

	err = auditStore.LogStep(ctx, testTenantSlug, "flow-1", "authn_request_received", "https://sp1.example.com", "user1", map[string]string{"requestId": "req-123"})
	require.NoError(t, err)

	err = auditStore.LogStep(ctx, testTenantSlug, "flow-2", "sso_initiated", "https://sp2.example.com", "user2", map[string]string{"ip": "192.0.2.2"})
	require.NoError(t, err)

	// Get audit log
	resp := api.Get("/api/v1/debug/audit-log")
	require.Equal(t, http.StatusOK, resp.Code)

	var result struct {
		Events []store.FlowStep `json:"events"`
	}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify we got 3 steps back
	assert.Len(t, result.Events, 3)

	// Verify steps are sorted by timestamp descending (most recent first)
	if len(result.Events) >= 2 {
		assert.True(t, result.Events[0].Timestamp.After(result.Events[1].Timestamp) || result.Events[0].Timestamp.Equal(result.Events[1].Timestamp))
	}
}

// TestAuditLog_ScopedToTenant verifies the audit-log endpoint returns only the
// caller's tenant's steps and never another tenant's.
func TestAuditLog_ScopedToTenant(t *testing.T) {
	api, auditStore := newTestDebugAPI(t)
	ctx := context.Background()

	// Caller's tenant has one step; a different tenant has two.
	require.NoError(t, auditStore.LogStep(ctx, testTenantSlug, "mine", "sso_initiated", "https://sp.example.com", "me", nil))
	require.NoError(t, auditStore.LogStep(ctx, "other-tenant", "theirs-1", "sso_initiated", "https://sp.example.com", "them", nil))
	require.NoError(t, auditStore.LogStep(ctx, "other-tenant", "theirs-2", "sso_complete", "https://sp.example.com", "them", nil))

	resp := api.Get("/api/v1/debug/audit-log")
	require.Equal(t, http.StatusOK, resp.Code)

	var result struct {
		Events []store.FlowStep `json:"events"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	require.Len(t, result.Events, 1, "must see only the caller tenant's step")
	assert.Equal(t, "mine", result.Events[0].FlowID)
}

func TestAuditLogFlowDetail(t *testing.T) {
	api, auditStore := newTestDebugAPI(t)
	ctx := context.Background()

	flowID := "flow-detail-test"

	// Log steps for a specific flow under the caller's tenant.
	err := auditStore.LogStep(ctx, testTenantSlug, flowID, "sso_initiated", "https://sp1.example.com", "user1", map[string]string{"ip": "192.0.2.1"})
	require.NoError(t, err)

	err = auditStore.LogStep(ctx, testTenantSlug, flowID, "authn_request_received", "https://sp1.example.com", "user1", map[string]string{"requestId": "req-123"})
	require.NoError(t, err)

	err = auditStore.LogStep(ctx, testTenantSlug, flowID, "assertion_generated", "https://sp1.example.com", "user1", map[string]string{"assertionId": "assert-456"})
	require.NoError(t, err)

	// Get flow detail
	resp := api.Get("/api/v1/debug/audit-log/" + flowID)
	require.Equal(t, http.StatusOK, resp.Code)

	var result struct {
		FlowID string           `json:"flowId"`
		Steps  []store.FlowStep `json:"steps"`
	}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify the response
	assert.Equal(t, flowID, result.FlowID)
	assert.Len(t, result.Steps, 3)

	// Verify all steps have the same flow ID
	for _, step := range result.Steps {
		assert.Equal(t, flowID, step.FlowID)
	}

	// Verify we have all the expected step types (order may vary in MemoryDB)
	stepTypes := make(map[string]bool)
	for _, step := range result.Steps {
		stepTypes[step.StepType] = true
	}
	assert.True(t, stepTypes["sso_initiated"], "should have sso_initiated step")
	assert.True(t, stepTypes["authn_request_received"], "should have authn_request_received step")
	assert.True(t, stepTypes["assertion_generated"], "should have assertion_generated step")
}

// TestAuditLogFlowDetail_CrossTenant verifies that a flowID belonging to another
// tenant is not returned to the caller — it resolves as not-found because the
// flow lives under a different partition key.
func TestAuditLogFlowDetail_CrossTenant(t *testing.T) {
	api, auditStore := newTestDebugAPI(t)
	ctx := context.Background()

	// A flow owned by a different tenant, using an ID the caller might guess.
	require.NoError(t, auditStore.LogStep(ctx, "other-tenant", "victim-flow", "sso_initiated", "https://sp.example.com", "victim", nil))

	resp := api.Get("/api/v1/debug/audit-log/victim-flow")
	assert.Equal(t, http.StatusNotFound, resp.Code, "caller must not read another tenant's flow")
}

func TestAuditLogFlowDetail_NotFound(t *testing.T) {
	api, _ := newTestDebugAPI(t)

	// Request a non-existent flow
	resp := api.Get("/api/v1/debug/audit-log/non-existent-flow")
	assert.Equal(t, http.StatusNotFound, resp.Code)
}
