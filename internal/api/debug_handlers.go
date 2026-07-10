package api

import (
	"context"
	"encoding/base64"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
)

// DecodeAssertionInput represents the request to decode a SAML assertion
type DecodeAssertionInput struct {
	Body struct {
		Assertion string `json:"assertion" doc:"Base64-encoded SAML assertion"`
	}
}

// DecodeAssertionOutput represents the decoded SAML assertion response
type DecodeAssertionOutput struct {
	Body struct {
		DecodedXML string                 `json:"decodedXml" doc:"Decoded SAML assertion XML"`
		Attributes map[string]interface{} `json:"attributes" doc:"Extracted SAML attributes"`
	}
}

// AuditLogOutput represents the audit log response
type AuditLogOutput struct {
	Body struct {
		Events []domain.FlowStep `json:"events" doc:"Audit log events"`
	}
}

// FlowDetailInput represents the flow ID path parameter
type FlowDetailInput struct {
	FlowID string `path:"flowId" doc:"Flow ID to retrieve"`
}

// FlowDetailOutput represents the flow detail response
type FlowDetailOutput struct {
	Body struct {
		FlowID string            `json:"flowId" doc:"Flow ID"`
		Steps  []domain.FlowStep `json:"steps" doc:"Flow steps"`
	}
}

// RegisterDebugRoutes registers debug API routes
func RegisterDebugRoutes(api huma.API, audit domain.AuditRepository) {
	// POST /api/v1/debug/decode-assertion
	huma.Register(api, huma.Operation{
		OperationID: "decode-assertion",
		Method:      "POST",
		Path:        "/api/v1/debug/decode-assertion",
		Summary:     "Decode SAML assertion",
		Description: "Accepts a base64-encoded SAML assertion and returns the decoded XML and extracted attributes",
		Tags:        []string{"Debug"},
	}, func(ctx context.Context, input *DecodeAssertionInput) (*DecodeAssertionOutput, error) {
		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(input.Body.Assertion)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid base64 encoding", err)
		}

		resp := &DecodeAssertionOutput{}
		resp.Body.DecodedXML = string(decoded)
		resp.Body.Attributes = map[string]interface{}{
			"note": "Full SAML attribute parsing will be implemented in a future phase",
		}
		return resp, nil
	})

	// GET /api/v1/debug/audit-log
	huma.Register(api, huma.Operation{
		OperationID: "get-audit-log",
		Method:      "GET",
		Path:        "/api/v1/debug/audit-log",
		Summary:     "Get audit log",
		Description: "Returns recent audit log events",
		Tags:        []string{"Debug"},
	}, func(ctx context.Context, input *struct{}) (*AuditLogOutput, error) {
		// Scope to the caller's tenant. Fail closed if the request carries no
		// tenant context rather than returning a global, cross-tenant view.
		slug, ok := tenantSlugFromContext(ctx)
		if !ok || slug == "" {
			return nil, huma.Error403Forbidden("tenant context required")
		}
		steps, err := audit.GetRecentSteps(ctx, slug, 100)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve audit log", err)
		}

		resp := &AuditLogOutput{}
		if steps == nil {
			resp.Body.Events = []domain.FlowStep{}
		} else {
			resp.Body.Events = steps
		}
		return resp, nil
	})

	// GET /api/v1/debug/audit-log/{flowId}
	huma.Register(api, huma.Operation{
		OperationID: "get-flow-detail",
		Method:      "GET",
		Path:        "/api/v1/debug/audit-log/{flowId}",
		Summary:     "Get flow detail",
		Description: "Returns all steps for a specific flow ID",
		Tags:        []string{"Debug"},
	}, func(ctx context.Context, input *FlowDetailInput) (*FlowDetailOutput, error) {
		// Scope the lookup to the caller's tenant: a flowID from another tenant
		// lives under a different partition key and resolves as empty.
		slug, ok := tenantSlugFromContext(ctx)
		if !ok || slug == "" {
			return nil, huma.Error403Forbidden("tenant context required")
		}
		steps, err := audit.GetFlow(ctx, slug, input.FlowID)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve flow", err)
		}

		if len(steps) == 0 {
			return nil, huma.Error404NotFound("flow not found")
		}

		resp := &FlowDetailOutput{}
		resp.Body.FlowID = input.FlowID
		resp.Body.Steps = steps
		return resp, nil
	})
}
