package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
)

// AnalyticsOverviewOutput represents the analytics overview response
type AnalyticsOverviewOutput struct {
	Body struct {
		TotalApps  int `json:"totalSPs" doc:"Total number of applications"`
		TotalAuths int `json:"totalAuths" doc:"Total authentication events"`
	}
}

// AppMetricsInput represents the input for per-app metrics
type AppMetricsInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// AppMetricsOutput represents per-app metrics response
type AppMetricsOutput struct {
	Body struct {
		AppID      string `json:"appId" doc:"Application ID"`
		AuthCount  int    `json:"authCount" doc:"Authentication count"`
		LastAuth   string `json:"lastAuth,omitempty" doc:"Last authentication timestamp"`
		AvgLatency int    `json:"avgLatency" doc:"Average response latency in ms"`
	}
}

// RegisterAnalyticsRoutes registers analytics API routes
func RegisterAnalyticsRoutes(api huma.API, apps domain.AppReader, audit domain.AuditRepository) {
	// GET /api/v1/analytics/overview
	huma.Register(api, huma.Operation{
		OperationID: "get-analytics-overview",
		Method:      "GET",
		Path:        "/api/v1/analytics/overview",
		Summary:     "Get analytics overview",
		Description: "Returns aggregate statistics across all applications",
		Tags:        []string{"Analytics"},
	}, func(ctx context.Context, input *struct{}) (*AnalyticsOverviewOutput, error) {
		resp := &AnalyticsOverviewOutput{}

		// Both aggregates are scoped to the caller's tenant. Without a tenant in
		// context the counts stay zero rather than aggregating across every
		// tenant's apps and audit events.
		slug, ok := tenantSlugFromContext(ctx)
		if ok && slug != "" {
			if apps, err := apps.List(ctx, slug); err == nil {
				resp.Body.TotalApps = len(apps)
			}

			// Count audit events for this tenant only.
			if steps, err := audit.GetRecentSteps(ctx, slug, 10000); err == nil && steps != nil {
				resp.Body.TotalAuths = len(steps)
			}
		}

		return resp, nil
	})

	// GET /api/v1/analytics/applications/{id}
	huma.Register(api, huma.Operation{
		OperationID: "get-app-metrics",
		Method:      "GET",
		Path:        "/api/v1/analytics/applications/{id}",
		Summary:     "Get application metrics",
		Description: "Returns metrics for a specific application",
		Tags:        []string{"Analytics"},
	}, func(ctx context.Context, input *AppMetricsInput) (*AppMetricsOutput, error) {
		resp := &AppMetricsOutput{}
		resp.Body.AppID = input.ID
		resp.Body.AuthCount = 0
		resp.Body.AvgLatency = 0
		return resp, nil
	})
}
