package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// CreateTenantInput defines the request schema for creating a tenant.
type CreateTenantInput struct {
	Body struct {
		Slug        string `json:"slug" minLength:"1" maxLength:"63" doc:"Unique tenant slug"`
		DisplayName string `json:"displayName" minLength:"1" maxLength:"255" doc:"Human-readable tenant name"`
		Domain      string `json:"domain,omitempty" doc:"Tenant domain"`
		KMSKeyID    string `json:"kmsKeyId,omitempty" doc:"Custom KMS key ID for tenant-specific SAML signing (premium feature)"`
		KMSKeyArn   string `json:"kmsKeyArn,omitempty" doc:"ARN of the custom KMS signing key"`

		// SAML defaults
		DefaultSessionDurationSec int    `json:"defaultSessionDurationSec,omitempty" doc:"Default SAML session duration in seconds"`
		DefaultSignResponse       *bool  `json:"defaultSignResponse,omitempty" doc:"Default sign response flag for SAML apps"`
		DefaultSignAssertion      *bool  `json:"defaultSignAssertion,omitempty" doc:"Default sign assertion flag for SAML apps"`
		DefaultNameIDFormat       string `json:"defaultNameIdFormat,omitempty" doc:"Default NameID format for SAML apps"`

		// OIDC defaults
		DefaultIDTokenLifetimeSec     int      `json:"defaultIdTokenLifetimeSec,omitempty" doc:"Default ID token lifetime in seconds"`
		DefaultAccessTokenLifetimeSec int      `json:"defaultAccessTokenLifetimeSec,omitempty" doc:"Default access token lifetime in seconds"`
		DefaultScopes                 []string `json:"defaultScopes,omitempty" doc:"Default scopes for OIDC apps"`
	}
}

// TenantOutput wraps a Tenant for API responses.
type TenantOutput struct {
	Body tenant.Tenant
}

// ListTenantsOutput is the response for listing tenants.
type ListTenantsOutput struct {
	Body []tenant.Tenant
}

// GetTenantInput defines the path parameter for tenant endpoints.
type GetTenantInput struct {
	Slug string `path:"slug" doc:"Tenant slug"`
}

// UpdateTenantInput defines the request schema for updating a tenant.
type UpdateTenantInput struct {
	Slug string `path:"slug" doc:"Tenant slug"`
	Body struct {
		DisplayName string `json:"displayName,omitempty" doc:"Human-readable tenant name"`
		Domain      string `json:"domain,omitempty" doc:"Tenant domain"`
		KMSKeyID    string `json:"kmsKeyId,omitempty" doc:"Custom KMS key ID for tenant-specific SAML signing (premium feature)"`
		KMSKeyArn   string `json:"kmsKeyArn,omitempty" doc:"ARN of the custom KMS signing key"`

		// SAML defaults
		DefaultSessionDurationSec int    `json:"defaultSessionDurationSec,omitempty" doc:"Default SAML session duration in seconds"`
		DefaultSignResponse       *bool  `json:"defaultSignResponse,omitempty" doc:"Default sign response flag for SAML apps"`
		DefaultSignAssertion      *bool  `json:"defaultSignAssertion,omitempty" doc:"Default sign assertion flag for SAML apps"`
		DefaultNameIDFormat       string `json:"defaultNameIdFormat,omitempty" doc:"Default NameID format for SAML apps"`

		// OIDC defaults
		DefaultIDTokenLifetimeSec     int      `json:"defaultIdTokenLifetimeSec,omitempty" doc:"Default ID token lifetime in seconds"`
		DefaultAccessTokenLifetimeSec int      `json:"defaultAccessTokenLifetimeSec,omitempty" doc:"Default access token lifetime in seconds"`
		DefaultScopes                 []string `json:"defaultScopes,omitempty" doc:"Default scopes for OIDC apps"`
	}
}

// RegisterTenantRoutes registers all tenant management routes. apps is used to
// guard tenant deletion against orphaning applications; it may be nil (the
// guard is then skipped). kmsPolicy validates any client-supplied per-tenant
// KMS signing key so a tenant admin cannot register a malformed or
// cross-account key reference.
func RegisterTenantRoutes(api huma.API, tenants domain.TenantRepository, apps domain.AppReader, kmsPolicy KMSKeyPolicy) {
	// Create tenant
	huma.Register(api, huma.Operation{
		OperationID: "create-tenant",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants",
		Summary:     "Create a tenant",
		Description: "Creates a new tenant with default settings",
		Tags:        []string{"Tenants"},
	}, func(ctx context.Context, input *CreateTenantInput) (*TenantOutput, error) {
		// Validate the optional per-tenant KMS signing key before persisting it.
		// Storing an unvalidated client-supplied ARN is a confused-deputy vector:
		// the gateway signs with its own IAM identity, so a foreign-account
		// key reference must be rejected here.
		if err := validateTenantKMSKeyRefs(input.Body.KMSKeyID, input.Body.KMSKeyArn, kmsPolicy); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}

		t := &tenant.Tenant{
			Slug:             input.Body.Slug,
			DisplayName:      input.Body.DisplayName,
			Domain:           input.Body.Domain,
			KMSKeyID:         input.Body.KMSKeyID,
			KMSKeyArn:        input.Body.KMSKeyArn,
			Plan:             "standard",
			Status:           "active",
			MaxApps:          10,
			MaxAuthsPerMonth: 10000,

			// Set protocol defaults
			DefaultSessionDurationSec:     3600,
			DefaultSignResponse:           true,
			DefaultSignAssertion:          true,
			DefaultNameIDFormat:           "email",
			DefaultIDTokenLifetimeSec:     3600,
			DefaultAccessTokenLifetimeSec: 3600,
			DefaultScopes:                 []string{"openid", "email", "profile"},
		}

		// Apply overrides from input if provided
		if input.Body.DefaultSessionDurationSec > 0 {
			t.DefaultSessionDurationSec = input.Body.DefaultSessionDurationSec
		}
		if input.Body.DefaultSignResponse != nil {
			t.DefaultSignResponse = *input.Body.DefaultSignResponse
		}
		if input.Body.DefaultSignAssertion != nil {
			t.DefaultSignAssertion = *input.Body.DefaultSignAssertion
		}
		if input.Body.DefaultNameIDFormat != "" {
			t.DefaultNameIDFormat = input.Body.DefaultNameIDFormat
		}
		if input.Body.DefaultIDTokenLifetimeSec > 0 {
			t.DefaultIDTokenLifetimeSec = input.Body.DefaultIDTokenLifetimeSec
		}
		if input.Body.DefaultAccessTokenLifetimeSec > 0 {
			t.DefaultAccessTokenLifetimeSec = input.Body.DefaultAccessTokenLifetimeSec
		}
		if len(input.Body.DefaultScopes) > 0 {
			t.DefaultScopes = input.Body.DefaultScopes
		}

		if err := tenants.Create(ctx, t); err != nil {
			return nil, huma.Error500InternalServerError("failed to create tenant", err)
		}

		created, err := tenants.Get(ctx, t.Slug)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve created tenant", err)
		}

		return &TenantOutput{Body: *created}, nil
	})

	// List tenants
	huma.Register(api, huma.Operation{
		OperationID: "list-tenants",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants",
		Summary:     "List tenants",
		Description: "Lists all tenants",
		Tags:        []string{"Tenants"},
	}, func(ctx context.Context, input *struct{}) (*ListTenantsOutput, error) {
		// A per-tenant admin may enumerate only its own tenant; the full,
		// cross-tenant listing (which discloses every tenant's signing-key ARNs)
		// is reserved for global operators. Fail closed when no tenant context.
		caller, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}
		groups, _ := middleware.GetGroups(ctx)
		isOperator := hasGlobalOperator(groups)

		all, err := tenants.List(ctx)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to list tenants", err)
		}

		result := make([]tenant.Tenant, 0, len(all))
		for _, t := range all {
			if isOperator || t.Slug == caller {
				result = append(result, *t)
			}
		}
		return &ListTenantsOutput{Body: result}, nil
	})

	// Get tenant by slug
	huma.Register(api, huma.Operation{
		OperationID: "get-tenant",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{slug}",
		Summary:     "Get a tenant",
		Description: "Retrieves a tenant by slug",
		Tags:        []string{"Tenants"},
	}, func(ctx context.Context, input *GetTenantInput) (*TenantOutput, error) {
		// Cross-tenant IDOR guard: a caller may only read its own tenant unless
		// it is a global operator (mirrors the onboarding path).
		if err := requireTenantMatch(ctx, input.Slug, "get-tenant", "forbidden: cannot access a different tenant"); err != nil {
			return nil, err
		}
		t, err := tenants.Get(ctx, input.Slug)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("tenant not found")
			}
			return nil, huma.Error500InternalServerError("failed to get tenant", err)
		}
		return &TenantOutput{Body: *t}, nil
	})

	// Update tenant
	huma.Register(api, huma.Operation{
		OperationID: "update-tenant",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{slug}",
		Summary:     "Update a tenant",
		Description: "Updates a tenant's configuration, including per-tenant KMS signing key (premium feature)",
		Tags:        []string{"Tenants"},
	}, func(ctx context.Context, input *UpdateTenantInput) (*TenantOutput, error) {
		// Cross-tenant IDOR guard: a caller may only mutate its own tenant unless
		// it is a global operator (mirrors the onboarding path).
		if err := requireTenantMatch(ctx, input.Slug, "update-tenant", "forbidden: cannot modify a different tenant"); err != nil {
			return nil, err
		}
		// Validate any client-supplied per-tenant KMS key reference before it can
		// overwrite the stored value (same confused-deputy defense as create).
		if err := validateTenantKMSKeyRefs(input.Body.KMSKeyID, input.Body.KMSKeyArn, kmsPolicy); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}

		existing, err := tenants.Get(ctx, input.Slug)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("tenant not found")
			}
			return nil, huma.Error500InternalServerError("failed to get tenant", err)
		}

		// Apply updates (only non-empty fields)
		if input.Body.DisplayName != "" {
			existing.DisplayName = input.Body.DisplayName
		}
		if input.Body.Domain != "" {
			existing.Domain = input.Body.Domain
		}
		if input.Body.KMSKeyID != "" {
			existing.KMSKeyID = input.Body.KMSKeyID
		}
		if input.Body.KMSKeyArn != "" {
			existing.KMSKeyArn = input.Body.KMSKeyArn
		}

		// Apply protocol default updates if provided
		if input.Body.DefaultSessionDurationSec > 0 {
			existing.DefaultSessionDurationSec = input.Body.DefaultSessionDurationSec
		}
		if input.Body.DefaultSignResponse != nil {
			existing.DefaultSignResponse = *input.Body.DefaultSignResponse
		}
		if input.Body.DefaultSignAssertion != nil {
			existing.DefaultSignAssertion = *input.Body.DefaultSignAssertion
		}
		if input.Body.DefaultNameIDFormat != "" {
			existing.DefaultNameIDFormat = input.Body.DefaultNameIDFormat
		}
		if input.Body.DefaultIDTokenLifetimeSec > 0 {
			existing.DefaultIDTokenLifetimeSec = input.Body.DefaultIDTokenLifetimeSec
		}
		if input.Body.DefaultAccessTokenLifetimeSec > 0 {
			existing.DefaultAccessTokenLifetimeSec = input.Body.DefaultAccessTokenLifetimeSec
		}
		if len(input.Body.DefaultScopes) > 0 {
			existing.DefaultScopes = input.Body.DefaultScopes
		}

		if err := tenants.Update(ctx, existing); err != nil {
			return nil, huma.Error500InternalServerError("failed to update tenant", err)
		}

		updated, err := tenants.Get(ctx, input.Slug)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve updated tenant", err)
		}

		return &TenantOutput{Body: *updated}, nil
	})

	// Delete tenant
	huma.Register(api, huma.Operation{
		OperationID: "delete-tenant",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{slug}",
		Summary:     "Delete a tenant",
		Description: "Deletes a tenant. The built-in default tenant cannot be deleted, and a tenant that still owns applications must have them removed first.",
		Tags:        []string{"Tenants"},
	}, func(ctx context.Context, input *GetTenantInput) (*struct{}, error) {
		// Cross-tenant IDOR guard: a caller may only delete its own tenant unless
		// it is a global operator (mirrors the onboarding path).
		if err := requireTenantMatch(ctx, input.Slug, "delete-tenant", "forbidden: cannot delete a different tenant"); err != nil {
			return nil, err
		}
		if input.Slug == tenant.DefaultSlug {
			return nil, huma.Error400BadRequest("the default tenant cannot be deleted")
		}

		if _, err := tenants.Get(ctx, input.Slug); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("tenant not found")
			}
			return nil, huma.Error500InternalServerError("failed to get tenant", err)
		}

		// Guard against orphaning applications.
		if apps != nil {
			existingApps, err := apps.List(ctx, input.Slug)
			if err != nil {
				return nil, huma.Error500InternalServerError("failed to check tenant applications", err)
			}
			if len(existingApps) > 0 {
				return nil, huma.Error409Conflict("tenant still has applications; delete them before deleting the tenant")
			}
		}

		if err := tenants.Delete(ctx, input.Slug); err != nil {
			return nil, huma.Error500InternalServerError("failed to delete tenant", err)
		}
		return nil, nil
	})
}
