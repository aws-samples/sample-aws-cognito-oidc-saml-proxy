package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
)

// registerImportAppRoute registers the import-from-metadata endpoint.
func registerImportAppRoute(api huma.API, importSvc *service.MetadataImportService) {
	huma.Register(api, huma.Operation{
		OperationID: "import-application",
		Method:      http.MethodPost,
		Path:        "/api/v1/applications/import",
		Summary:     "Import application from SP metadata",
		Description: "Fetches SAML SP metadata from a URL and creates an application from it",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *ImportAppInput) (*AppOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Delegate to service
		result, err := importSvc.Import(ctx, slug, input.Body.MetadataURL, input.Body.SourceID, input.Body.DisplayName)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf("import failed: %v", err))
		}

		out := &AppOutput{}
		out.Body.Application = *result.App
		out.Body.ID = result.AppID
		out.Body.SAML = result.SAMLConfig
		return out, nil
	})
}
