package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// GetClaimMappingsInput defines the request schema for getting claim mappings.
type GetClaimMappingsInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// GetClaimMappingsOutput defines the response schema for getting claim mappings.
type GetClaimMappingsOutput struct {
	Body []tenant.ClaimMapping
}

// ClaimMappingItem represents a single claim mapping in bulk operations.
type ClaimMappingItem struct {
	Name            string `json:"name" minLength:"1" doc:"Mapping name"`
	SourceType      string `json:"sourceType" enum:"cognito,static,groupMapping" doc:"Source type: cognito (from JWT claim), static (fixed value), or groupMapping (map Cognito groups)"`
	SourceAttribute string `json:"sourceAttribute" doc:"Cognito claim name or computation expression"`
	TargetAttribute string `json:"targetAttribute" doc:"Target SAML attribute name"`
	Required        bool   `json:"required" doc:"Whether this mapping is required"`
	DefaultValue    string `json:"defaultValue,omitempty" doc:"Default value if source is missing"`
}

// PutClaimMappingsInput defines the request schema for bulk updating claim mappings.
type PutClaimMappingsInput struct {
	ID   string `path:"id" doc:"Application ID"`
	Body struct {
		Mappings []ClaimMappingItem `json:"mappings" doc:"Array of claim mappings"`
	}
}

// PutClaimMappingsOutput defines the response schema for bulk updating claim mappings.
type PutClaimMappingsOutput struct {
	Body struct {
		Updated int `json:"updated" doc:"Number of mappings updated"`
	}
}

// GetRoleMappingsInput defines the request schema for getting role mappings.
type GetRoleMappingsInput struct {
	ID string `path:"id" doc:"Application ID"`
}

// GetRoleMappingsOutput defines the response schema for getting role mappings.
type GetRoleMappingsOutput struct {
	Body []tenant.RoleMapping
}

// RoleMappingItem represents a single role mapping in bulk operations.
type RoleMappingItem struct {
	CognitoGroup string `json:"cognitoGroup" minLength:"1" doc:"Cognito group name"`
	MappedValue  string `json:"mappedValue" minLength:"1" doc:"Mapped role value or URI"`
}

// PutRoleMappingsInput defines the request schema for bulk updating role mappings.
type PutRoleMappingsInput struct {
	ID   string `path:"id" doc:"Application ID"`
	Body struct {
		Mappings []RoleMappingItem `json:"mappings" doc:"Array of role mappings"`
	}
}

// PutRoleMappingsOutput defines the response schema for bulk updating role mappings.
type PutRoleMappingsOutput struct {
	Body struct {
		Updated int `json:"updated" doc:"Number of mappings updated"`
	}
}

// RegisterMappingRoutes registers all claim and role mapping routes.
func RegisterMappingRoutes(api huma.API, apps domain.AppReader, claims domain.ClaimRepository) {
	// Get claim mappings
	huma.Register(api, huma.Operation{
		OperationID: "get-claim-mappings",
		Method:      http.MethodGet,
		Path:        "/api/v1/applications/{id}/claim-mappings",
		Summary:     "Get claim mappings",
		Description: "Retrieves all claim mappings for an application",
		Tags:        []string{"Claim Mappings"},
	}, func(ctx context.Context, input *GetClaimMappingsInput) (*GetClaimMappingsOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Verify app exists
		if _, err := apps.Get(ctx, slug, input.ID); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		mappings, err := claims.GetClaimMappings(ctx, slug, input.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to get claim mappings", err)
		}

		return &GetClaimMappingsOutput{Body: mappings}, nil
	})

	// Bulk update claim mappings
	huma.Register(api, huma.Operation{
		OperationID: "put-claim-mappings",
		Method:      http.MethodPut,
		Path:        "/api/v1/applications/{id}/claim-mappings",
		Summary:     "Update claim mappings",
		Description: "Bulk updates claim mappings for an application",
		Tags:        []string{"Claim Mappings"},
	}, func(ctx context.Context, input *PutClaimMappingsInput) (*PutClaimMappingsOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Verify app exists
		if _, err := apps.Get(ctx, slug, input.ID); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		mappings := make([]tenant.ClaimMapping, len(input.Body.Mappings))
		for i, m := range input.Body.Mappings {
			mappings[i] = tenant.ClaimMapping{
				Name:            m.Name,
				SourceType:      m.SourceType,
				SourceAttribute: m.SourceAttribute,
				TargetAttribute: m.TargetAttribute,
				Required:        m.Required,
				DefaultValue:    m.DefaultValue,
			}
		}

		if err := claims.PutClaimMappings(ctx, slug, input.ID, mappings); err != nil {
			return nil, huma.Error500InternalServerError("failed to store claim mappings", err)
		}

		return &PutClaimMappingsOutput{
			Body: struct {
				Updated int `json:"updated" doc:"Number of mappings updated"`
			}{Updated: len(mappings)},
		}, nil
	})

	// Get role mappings
	huma.Register(api, huma.Operation{
		OperationID: "get-role-mappings",
		Method:      http.MethodGet,
		Path:        "/api/v1/applications/{id}/role-mappings",
		Summary:     "Get role mappings",
		Description: "Retrieves all role mappings for an application",
		Tags:        []string{"Role Mappings"},
	}, func(ctx context.Context, input *GetRoleMappingsInput) (*GetRoleMappingsOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Verify app exists
		if _, err := apps.Get(ctx, slug, input.ID); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		mappings, err := claims.GetRoleMappings(ctx, slug, input.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to get role mappings", err)
		}

		return &GetRoleMappingsOutput{Body: mappings}, nil
	})

	// Bulk update role mappings
	huma.Register(api, huma.Operation{
		OperationID: "put-role-mappings",
		Method:      http.MethodPut,
		Path:        "/api/v1/applications/{id}/role-mappings",
		Summary:     "Update role mappings",
		Description: "Bulk updates role mappings for an application",
		Tags:        []string{"Role Mappings"},
	}, func(ctx context.Context, input *PutRoleMappingsInput) (*PutRoleMappingsOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Verify app exists
		if _, err := apps.Get(ctx, slug, input.ID); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		mappings := make([]tenant.RoleMapping, len(input.Body.Mappings))
		for i, m := range input.Body.Mappings {
			mappings[i] = tenant.RoleMapping{
				CognitoGroup: m.CognitoGroup,
				MappedValue:  m.MappedValue,
			}
		}

		if err := claims.PutRoleMappings(ctx, slug, input.ID, mappings); err != nil {
			return nil, huma.Error500InternalServerError("failed to store role mappings", err)
		}

		return &PutRoleMappingsOutput{
			Body: struct {
				Updated int `json:"updated" doc:"Number of mappings updated"`
			}{Updated: len(mappings)},
		}, nil
	})
}
