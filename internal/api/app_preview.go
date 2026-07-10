package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
)

// registerPreviewRoute registers the claim mapping preview endpoint.
func registerPreviewRoute(api huma.API, previewSvc *service.PreviewService) {
	huma.Register(api, huma.Operation{
		OperationID: "preview-claim-mappings",
		Method:      http.MethodPost,
		Path:        "/api/v1/applications/{id}/claim-mappings/preview",
		Summary:     "Preview claim mappings",
		Description: "Dry-run assertion preview with test user claims",
		Tags:        []string{"Claim Mappings"},
	}, func(ctx context.Context, input *PreviewInput) (*PreviewOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Build test user claims from input
		testUser := service.TestUserClaims{
			Sub:    input.Body.Sub,
			Email:  input.Body.Email,
			Groups: input.Body.Groups,
		}

		// Delegate to service
		result, err := previewSvc.Preview(ctx, slug, input.ID, testUser)
		if err != nil {
			return nil, huma.Error500InternalServerError(fmt.Sprintf("preview failed: %v", err))
		}

		out := &PreviewOutput{}
		out.Body.Protocol = result.Protocol
		out.Body.Preview = result.Preview
		return out, nil
	})
}
