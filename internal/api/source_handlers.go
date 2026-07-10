package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/safehttp"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// CreateSourceInput defines the request schema for creating an identity source.
type CreateSourceInput struct {
	Body struct {
		DisplayName string `json:"displayName" minLength:"1" maxLength:"255" doc:"Human-readable source name"`
		Type        string `json:"type,omitempty" enum:"cognito" default:"cognito" doc:"Identity source type"`
		PoolID      string `json:"poolId" minLength:"1" doc:"Cognito User Pool ID"`
		Region      string `json:"region" minLength:"1" doc:"AWS region of the user pool"`
		Domain      string `json:"domain" minLength:"1" doc:"Cognito domain"`
		ClientID    string `json:"clientId" minLength:"1" doc:"Cognito app client ID"`
	}
}

// SourceOutput wraps an IdentitySource for API responses.
type SourceOutput struct {
	Body tenant.IdentitySource
}

// ListSourcesOutput is the response for listing identity sources.
type ListSourcesOutput struct {
	Body []tenant.IdentitySource
}

// GetSourceInput defines the path parameter for source endpoints.
type GetSourceInput struct {
	ID string `path:"id" doc:"Identity source ID"`
}

// UpdateSourceInput defines the request schema for updating an identity source.
type UpdateSourceInput struct {
	ID   string `path:"id" doc:"Identity source ID"`
	Body struct {
		DisplayName string `json:"displayName" minLength:"1" maxLength:"255" doc:"Human-readable source name"`
		Type        string `json:"type,omitempty" enum:"cognito" doc:"Identity source type"`
		PoolID      string `json:"poolId,omitempty" doc:"Cognito User Pool ID"`
		Region      string `json:"region,omitempty" doc:"AWS region of the user pool"`
		Domain      string `json:"domain,omitempty" doc:"Cognito domain"`
		ClientID    string `json:"clientId,omitempty" doc:"Cognito app client ID"`
	}
}

// DeleteSourceInput defines the path parameter for deleting an identity source.
type DeleteSourceInput struct {
	ID string `path:"id" doc:"Identity source ID"`
}

// TestSourceInput defines the path parameter for testing an identity source.
type TestSourceInput struct {
	ID string `path:"id" doc:"Identity source ID"`
}

// TestSourceOutput is the response for testing identity source connectivity.
type TestSourceOutput struct {
	Body struct {
		Reachable bool   `json:"reachable" doc:"Whether the identity source is reachable"`
		LatencyMs int64  `json:"latencyMs" doc:"Response time in milliseconds"`
		Error     string `json:"error,omitempty" doc:"Error message if unreachable"`
	}
}

// DiscoverPoolInput defines the request schema for discovering Cognito pool configuration.
type DiscoverPoolInput struct {
	Body struct {
		PoolID string `json:"poolId" minLength:"1" doc:"Cognito User Pool ID (e.g., eu-north-1_ABC123)"`
		Region string `json:"region" minLength:"1" doc:"AWS region of the user pool (e.g., eu-north-1)"`
	}
}

// DiscoverPoolOutput is the response for Cognito pool discovery.
type DiscoverPoolOutput struct {
	Body struct {
		Domain     string   `json:"domain" doc:"Cognito domain (e.g., xxx.auth.eu-north-1.amazoncognito.com)"`
		Attributes []string `json:"attributes" doc:"Available schema attributes"`
	}
}

// connectivityProbe performs the outbound connectivity check for the "test
// source" endpoint. It returns the HTTP response (which the caller closes) or
// an error. A *safehttp.ErrBlockedDestination signals an SSRF-blocked target.
type connectivityProbe func(ctx context.Context, testURL string) (*http.Response, error)

// probeSafe is the production connectivity probe: it validates the URL and
// dials through the SSRF-hardened client, so tenant-controlled domains cannot
// be used to reach internal services or the instance metadata endpoint.
func probeSafe(ctx context.Context, testURL string) (*http.Response, error) {
	if err := safehttp.ValidateURL(testURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return nil, err
	}
	return safehttp.Client(5 * time.Second).Do(req)
}

// sourceRouteConfig holds optional dependencies for the source routes.
type sourceRouteConfig struct {
	probe connectivityProbe
}

// SourceRouteOption customizes source route registration.
type SourceRouteOption func(*sourceRouteConfig)

// WithConnectivityProbe overrides the outbound connectivity probe. This is an
// explicit, named test seam: production always uses the SSRF-hardened probe
// (the default), and only tests inject a permissive probe to exercise HTTP
// behavior against a loopback server.
func WithConnectivityProbe(p connectivityProbe) SourceRouteOption {
	return func(c *sourceRouteConfig) { c.probe = p }
}

// RegisterSourceRoutes registers all identity source routes.
func RegisterSourceRoutes(api huma.API, sources domain.SourceRepository, opts ...SourceRouteOption) {
	cfg := &sourceRouteConfig{probe: probeSafe}
	for _, opt := range opts {
		opt(cfg)
	}
	// Create identity source
	huma.Register(api, huma.Operation{
		OperationID: "create-identity-source",
		Method:      http.MethodPost,
		Path:        "/api/v1/identity-sources",
		Summary:     "Add an identity source",
		Description: "Adds a Cognito user pool as an identity source",
		Tags:        []string{"Identity Sources"},
	}, func(ctx context.Context, input *CreateSourceInput) (*SourceOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		src := &tenant.IdentitySource{
			DisplayName: input.Body.DisplayName,
			Type:        setStringDefault(input.Body.Type, "cognito"),
			PoolID:      input.Body.PoolID,
			Region:      input.Body.Region,
			Domain:      input.Body.Domain,
			ClientID:    input.Body.ClientID,
			Status:      "active",
		}

		// Auto-discover domain if not provided
		if src.Domain == "" && src.PoolID != "" && src.Region != "" {
			awsCfg, awsErr := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(src.Region))
			if awsErr != nil {
				slog.Warn("could not load AWS credentials for auto-discovery", "error", awsErr)
			} else {
				info, discErr := cognito.DiscoverPool(ctx, awsCfg, src.PoolID, src.Region)
				if discErr != nil {
					slog.Warn("could not auto-discover Cognito domain", "error", discErr)
				} else if info.Domain != "" {
					src.Domain = info.Domain
					slog.Info("auto-discovered Cognito domain", "domain", src.Domain)
				}
			}
		}

		id, err := sources.Create(ctx, slug, src)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to create identity source", err)
		}

		created, err := sources.Get(ctx, slug, id)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve created identity source", err)
		}

		return &SourceOutput{Body: *created}, nil
	})

	// List identity sources
	huma.Register(api, huma.Operation{
		OperationID: "list-identity-sources",
		Method:      http.MethodGet,
		Path:        "/api/v1/identity-sources",
		Summary:     "List identity sources",
		Description: "Lists all identity sources for the current tenant",
		Tags:        []string{"Identity Sources"},
	}, func(ctx context.Context, input *struct{}) (*ListSourcesOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		sources, err := sources.List(ctx, slug)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to list identity sources", err)
		}

		result := make([]tenant.IdentitySource, len(sources))
		for i, s := range sources {
			result[i] = *s
		}
		return &ListSourcesOutput{Body: result}, nil
	})

	// Get identity source by ID
	huma.Register(api, huma.Operation{
		OperationID: "get-identity-source",
		Method:      http.MethodGet,
		Path:        "/api/v1/identity-sources/{id}",
		Summary:     "Get an identity source",
		Description: "Retrieves an identity source by ID",
		Tags:        []string{"Identity Sources"},
	}, func(ctx context.Context, input *GetSourceInput) (*SourceOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		src, err := sources.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("identity source not found")
			}
			return nil, huma.Error500InternalServerError("failed to get identity source", err)
		}

		return &SourceOutput{Body: *src}, nil
	})

	// Update identity source
	huma.Register(api, huma.Operation{
		OperationID: "update-identity-source",
		Method:      http.MethodPut,
		Path:        "/api/v1/identity-sources/{id}",
		Summary:     "Update an identity source",
		Description: "Updates an existing identity source",
		Tags:        []string{"Identity Sources"},
	}, func(ctx context.Context, input *UpdateSourceInput) (*SourceOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		existing, err := sources.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("identity source not found")
			}
			return nil, huma.Error500InternalServerError("failed to get identity source", err)
		}

		existing.DisplayName = input.Body.DisplayName
		existing.Type = setStringDefault(input.Body.Type, existing.Type)
		existing.PoolID = setStringDefault(input.Body.PoolID, existing.PoolID)
		existing.Region = setStringDefault(input.Body.Region, existing.Region)
		existing.Domain = setStringDefault(input.Body.Domain, existing.Domain)
		existing.ClientID = setStringDefault(input.Body.ClientID, existing.ClientID)

		// Auto-discover domain if not provided but PoolID/Region changed
		if existing.Domain == "" && existing.PoolID != "" && existing.Region != "" {
			awsCfg, awsErr := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(existing.Region))
			if awsErr != nil {
				slog.Warn("could not load AWS credentials for auto-discovery", "error", awsErr)
			} else {
				info, discErr := cognito.DiscoverPool(ctx, awsCfg, existing.PoolID, existing.Region)
				if discErr != nil {
					slog.Warn("could not auto-discover Cognito domain", "error", discErr)
				} else if info.Domain != "" {
					existing.Domain = info.Domain
					slog.Info("auto-discovered Cognito domain", "domain", existing.Domain)
				}
			}
		}

		if err := sources.Update(ctx, slug, existing); err != nil {
			return nil, huma.Error500InternalServerError("failed to update identity source", err)
		}

		return &SourceOutput{Body: *existing}, nil
	})

	// Delete identity source
	huma.Register(api, huma.Operation{
		OperationID: "delete-identity-source",
		Method:      http.MethodDelete,
		Path:        "/api/v1/identity-sources/{id}",
		Summary:     "Delete an identity source",
		Description: "Removes an identity source",
		Tags:        []string{"Identity Sources"},
	}, func(ctx context.Context, input *DeleteSourceInput) (*struct{}, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		if err := sources.Delete(ctx, slug, input.ID); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("identity source not found")
			}
			return nil, huma.Error500InternalServerError("failed to delete identity source", err)
		}

		return nil, nil
	})

	// Test identity source connectivity
	huma.Register(api, huma.Operation{
		OperationID: "test-identity-source",
		Method:      http.MethodPost,
		Path:        "/api/v1/identity-sources/{id}/test",
		Summary:     "Test identity source connectivity",
		Description: "Tests connectivity to a Cognito User Pool by fetching its OIDC configuration",
		Tags:        []string{"Identity Sources"},
	}, func(ctx context.Context, input *TestSourceInput) (*TestSourceOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Load the identity source
		src, err := sources.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("identity source not found")
			}
			return nil, huma.Error500InternalServerError("failed to get identity source", err)
		}

		// Test connectivity by fetching the Cognito OIDC discovery endpoint.
		// Cognito serves OIDC discovery at cognito-idp.{region}.amazonaws.com/{poolId},
		// NOT at the auth domain (which is for hosted UI only).
		var testURL string
		if strings.HasPrefix(src.Domain, "http://") || strings.HasPrefix(src.Domain, "https://") {
			// Test/mock domains with explicit scheme — use as-is
			testURL = fmt.Sprintf("%s/.well-known/openid-configuration", src.Domain)
		} else if src.Region != "" && src.PoolID != "" {
			// Real Cognito: use the IdP endpoint
			testURL = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/openid-configuration", src.Region, src.PoolID)
		} else {
			// Fallback to auth domain
			testURL = fmt.Sprintf("https://%s/.well-known/openid-configuration", src.Domain)
		}

		output := &TestSourceOutput{}

		// The test URL can derive from a tenant-controlled domain, so the probe
		// runs through an SSRF-hardened client that refuses non-public
		// destinations (see probeSafe / safehttp). A blocked destination is
		// reported generically so the resolved internal address is not echoed
		// back to the caller.
		start := time.Now()
		resp, err := cfg.probe(ctx, testURL)
		latency := time.Since(start).Milliseconds()

		if err != nil {
			output.Body.Reachable = false
			output.Body.LatencyMs = latency
			var blocked *safehttp.ErrBlockedDestination
			if errors.As(err, &blocked) {
				output.Body.Error = "connectivity target is not a permitted public address"
			} else {
				output.Body.Error = err.Error()
			}
			return output, nil
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			output.Body.Reachable = false
			output.Body.LatencyMs = latency
			output.Body.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status)
			return output, nil
		}

		output.Body.Reachable = true
		output.Body.LatencyMs = latency
		return output, nil
	})

	// Discover Cognito User Pool configuration
	huma.Register(api, huma.Operation{
		OperationID: "discover-cognito-pool",
		Method:      http.MethodPost,
		Path:        "/api/v1/identity-sources/discover",
		Summary:     "Discover Cognito User Pool configuration",
		Description: "Auto-discovers the domain and schema attributes from a Cognito User Pool",
		Tags:        []string{"Identity Sources"},
	}, func(ctx context.Context, input *DiscoverPoolInput) (*DiscoverPoolOutput, error) {
		// Discovery uses the gateway's own IAM credentials to DescribeUserPool on
		// a caller-supplied pool id, so it must be scoped to an authenticated
		// tenant. Fail closed when no verified tenant context is present rather
		// than let an unscoped caller probe arbitrary pools.
		if _, ok := tenantSlugFromContext(ctx); !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Load AWS config with the specified region
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(input.Body.Region))
		if err != nil {
			return nil, huma.Error500InternalServerError("AWS credentials not available", err)
		}

		// Discover pool configuration
		info, err := cognito.DiscoverPool(ctx, awsCfg, input.Body.PoolID, input.Body.Region)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to discover pool", err)
		}

		output := &DiscoverPoolOutput{}
		output.Body.Domain = info.Domain
		output.Body.Attributes = info.Attributes
		return output, nil
	})
}
