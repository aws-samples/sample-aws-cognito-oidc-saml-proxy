package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// RegisterAppRoutes registers all application CRUD routes.
func RegisterAppRoutes(api huma.API, apps domain.AppRepository, claims domain.ClaimRepository, importSvc *service.MetadataImportService, previewSvc *service.PreviewService) {
	// Create application
	huma.Register(api, huma.Operation{
		OperationID: "create-application",
		Method:      http.MethodPost,
		Path:        "/api/v1/applications",
		Summary:     "Create an application",
		Description: "Creates a new SAML/OIDC application configuration",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *CreateAppInput) (*AppOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		app := &tenant.Application{
			DisplayName:              input.Body.DisplayName,
			Protocol:                 setStringDefault(input.Body.Protocol, "saml"),
			SourceID:                 input.Body.SourceID,
			Status:                   "active",
			CustomLoginURL:           strings.TrimSpace(input.Body.CustomLoginURL),
			TrustedLoginRedirectURIs: input.Body.TrustedLoginRedirectURIs,
		}

		if errs := validateLoginConfig(app); len(errs) > 0 {
			return nil, huma.Error422UnprocessableEntity("invalid login configuration: " + strings.Join(errs, "; "))
		}

		var samlCfg *tenant.SAMLConfig
		if strings.EqualFold(app.Protocol, "saml") {
			s := input.Body.SAML
			if s == nil {
				s = &SAMLConfigInput{}
			}
			samlCfg = &tenant.SAMLConfig{
				EntityID:           s.EntityID,
				AcsURL:             s.AcsURL,
				AcsURLs:            s.AcsURLs,
				MetadataURL:        s.MetadataURL,
				NameIDFormat:       normalizeNameIDFormat(setStringDefault(s.NameIDFormat, "persistent")),
				NameIDSource:       setStringDefault(s.NameIDSource, "sub"),
				SignResponse:       setBoolDefault(s.SignResponse, true),
				SignAssertion:      setBoolDefault(s.SignAssertion, true),
				EncryptAssertion:   setBoolDefault(s.EncryptAssertion, false),
				AllowIDPInitiated:  setBoolDefault(s.AllowIDPInitiated, false),
				SloURL:             s.SloURL,
				SessionDurationSec: setIntDefault(s.SessionDurationSec, 3600),
				ClockSkewSec:       setIntDefault(s.ClockSkewSec, 180),
			}
		}

		id, err := apps.Create(ctx, slug, app, samlCfg)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to create application", err)
		}

		// If OIDC, store OIDC config after app creation
		var generatedSecret string
		if strings.EqualFold(app.Protocol, "oidc") && input.Body.OIDC != nil && len(input.Body.OIDC.RedirectURIs) > 0 {
			o := input.Body.OIDC
			oidcCfg := &tenant.OIDCConfig{
				RedirectURIs:            o.RedirectURIs,
				PostLogoutRedirectURIs:  o.PostLogoutRedirectURIs,
				GrantTypes:              o.GrantTypes,
				ResponseTypes:           o.ResponseTypes,
				Scopes:                  o.Scopes,
				TokenEndpointAuthMethod: o.TokenEndpointAuthMethod,
				IDTokenLifetimeSec:      o.IDTokenLifetimeSec,
				AccessTokenLifetimeSec:  o.AccessTokenLifetimeSec,
				RefreshTokenLifetimeSec: o.RefreshTokenLifetimeSec,
			}
			// Confidential clients (e.g. an Amazon Cognito user pool acting as a
			// relying party) authenticate to the token endpoint with a client
			// secret. Generate one now so the client is usable immediately; it is
			// returned once in the response below.
			if isConfidentialAuthMethod(oidcCfg.TokenEndpointAuthMethod) {
				secret, err := generateClientSecret()
				if err != nil {
					return nil, huma.Error500InternalServerError("failed to generate client secret", err)
				}
				oidcCfg.ClientSecret = secret
				generatedSecret = secret
			}
			if err := apps.UpdateOIDCConfig(ctx, slug, id, oidcCfg); err != nil {
				return nil, huma.Error500InternalServerError("failed to store OIDC config", err)
			}
		}

		// Persist claim and role mappings collected by the wizard.
		if len(input.Body.ClaimMappings) > 0 {
			if err := claims.PutClaimMappings(ctx, slug, id, toClaimMappings(input.Body.ClaimMappings)); err != nil {
				return nil, huma.Error500InternalServerError("failed to store claim mappings", err)
			}
		}
		if len(input.Body.RoleMappings) > 0 {
			if err := claims.PutRoleMappings(ctx, slug, id, toRoleMappings(input.Body.RoleMappings)); err != nil {
				return nil, huma.Error500InternalServerError("failed to store role mappings", err)
			}
		}

		created, err := apps.Get(ctx, slug, id)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve created application", err)
		}

		out := &AppOutput{}
		out.Body.Application = *created
		if samlCfg != nil {
			cfg, _ := apps.GetSAMLConfig(ctx, slug, id)
			out.Body.SAML = cfg
		}
		if strings.EqualFold(created.Protocol, "oidc") {
			cfg, _ := apps.GetOIDCConfig(ctx, slug, id)
			out.Body.OIDC = cfg
		}
		out.Body.ClientSecret = generatedSecret
		return out, nil
	})

	// List applications
	huma.Register(api, huma.Operation{
		OperationID: "list-applications",
		Method:      http.MethodGet,
		Path:        "/api/v1/applications",
		Summary:     "List applications",
		Description: "Lists all applications for the current tenant",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *struct{}) (*ListAppsOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		apps, err := apps.List(ctx, slug)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to list applications", err)
		}

		result := make([]tenant.Application, 0, len(apps))
		for _, a := range apps {
			if strings.EqualFold(a.Status, "deleted") {
				continue
			}
			result = append(result, *a)
		}
		return &ListAppsOutput{Body: result}, nil
	})

	// Get application by ID
	huma.Register(api, huma.Operation{
		OperationID: "get-application",
		Method:      http.MethodGet,
		Path:        "/api/v1/applications/{id}",
		Summary:     "Get an application",
		Description: "Retrieves an application configuration by ID",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *GetAppInput) (*AppOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		app, err := apps.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		out := &AppOutput{}
		out.Body.Application = *app
		if strings.EqualFold(app.Protocol, "saml") {
			cfg, _ := apps.GetSAMLConfig(ctx, slug, input.ID)
			out.Body.SAML = cfg
		}
		if strings.EqualFold(app.Protocol, "oidc") {
			cfg, _ := apps.GetOIDCConfig(ctx, slug, input.ID)
			out.Body.OIDC = cfg
		}
		return out, nil
	})

	// Update application
	huma.Register(api, huma.Operation{
		OperationID: "update-application",
		Method:      http.MethodPut,
		Path:        "/api/v1/applications/{id}",
		Summary:     "Update an application",
		Description: "Updates an existing application configuration",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *UpdateAppInput) (*AppOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		existing, err := apps.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		existing.DisplayName = input.Body.DisplayName
		existing.Protocol = setStringDefault(input.Body.Protocol, existing.Protocol)
		existing.SourceID = input.Body.SourceID
		if input.Body.CustomLoginURL != nil {
			existing.CustomLoginURL = strings.TrimSpace(*input.Body.CustomLoginURL)
		}
		if input.Body.TrustedLoginRedirectURIs != nil {
			existing.TrustedLoginRedirectURIs = *input.Body.TrustedLoginRedirectURIs
		}

		if errs := validateLoginConfig(existing); len(errs) > 0 {
			return nil, huma.Error422UnprocessableEntity("invalid login configuration: " + strings.Join(errs, "; "))
		}

		if err := apps.Update(ctx, slug, existing); err != nil {
			return nil, huma.Error500InternalServerError("failed to update application", err)
		}

		// Update SAML config if protocol is saml
		if strings.EqualFold(existing.Protocol, "saml") && input.Body.SAML != nil && input.Body.SAML.EntityID != "" {
			s := input.Body.SAML
			samlCfg := &tenant.SAMLConfig{
				EntityID:           s.EntityID,
				AcsURL:             s.AcsURL,
				AcsURLs:            s.AcsURLs,
				MetadataURL:        s.MetadataURL,
				NameIDFormat:       normalizeNameIDFormat(s.NameIDFormat),
				NameIDSource:       s.NameIDSource,
				SignResponse:       setBoolDefault(s.SignResponse, true),
				SignAssertion:      setBoolDefault(s.SignAssertion, true),
				EncryptAssertion:   setBoolDefault(s.EncryptAssertion, false),
				AllowIDPInitiated:  setBoolDefault(s.AllowIDPInitiated, false),
				SloURL:             s.SloURL,
				SessionDurationSec: setIntDefault(s.SessionDurationSec, 3600),
				ClockSkewSec:       setIntDefault(s.ClockSkewSec, 180),
			}
			if err := apps.UpdateSAMLConfig(ctx, slug, input.ID, samlCfg); err != nil {
				return nil, huma.Error500InternalServerError("failed to update SAML config", err)
			}
		}

		// Update OIDC config if protocol is oidc
		var generatedSecret string
		if strings.EqualFold(existing.Protocol, "oidc") && input.Body.OIDC != nil && len(input.Body.OIDC.RedirectURIs) > 0 {
			o := input.Body.OIDC
			oidcCfg := &tenant.OIDCConfig{
				RedirectURIs:            o.RedirectURIs,
				PostLogoutRedirectURIs:  o.PostLogoutRedirectURIs,
				GrantTypes:              o.GrantTypes,
				ResponseTypes:           o.ResponseTypes,
				Scopes:                  o.Scopes,
				TokenEndpointAuthMethod: o.TokenEndpointAuthMethod,
				IDTokenLifetimeSec:      o.IDTokenLifetimeSec,
				AccessTokenLifetimeSec:  o.AccessTokenLifetimeSec,
				RefreshTokenLifetimeSec: o.RefreshTokenLifetimeSec,
			}
			// Manage the client secret across updates. UpdateOIDCConfig overwrites
			// the whole item, so the existing secret must be carried forward
			// explicitly or it would be wiped on every edit. For confidential
			// clients: preserve the current secret, or mint one if none exists yet
			// (e.g. switching a public client to a confidential auth method). For
			// public clients ("none"), leave the secret empty so it is cleared.
			if isConfidentialAuthMethod(oidcCfg.TokenEndpointAuthMethod) {
				prev, _ := apps.GetOIDCConfig(ctx, slug, input.ID)
				if prev != nil && prev.ClientSecret != "" {
					oidcCfg.ClientSecret = prev.ClientSecret
				} else {
					secret, err := generateClientSecret()
					if err != nil {
						return nil, huma.Error500InternalServerError("failed to generate client secret", err)
					}
					oidcCfg.ClientSecret = secret
					generatedSecret = secret
				}
			}
			if err := apps.UpdateOIDCConfig(ctx, slug, input.ID, oidcCfg); err != nil {
				return nil, huma.Error500InternalServerError("failed to update OIDC config", err)
			}
		}

		// Replace claim and role mappings when provided.
		if input.Body.ClaimMappings != nil {
			if err := claims.PutClaimMappings(ctx, slug, input.ID, toClaimMappings(input.Body.ClaimMappings)); err != nil {
				return nil, huma.Error500InternalServerError("failed to update claim mappings", err)
			}
		}
		if input.Body.RoleMappings != nil {
			if err := claims.PutRoleMappings(ctx, slug, input.ID, toRoleMappings(input.Body.RoleMappings)); err != nil {
				return nil, huma.Error500InternalServerError("failed to update role mappings", err)
			}
		}

		out := &AppOutput{}
		out.Body.Application = *existing
		if strings.EqualFold(existing.Protocol, "saml") {
			cfg, _ := apps.GetSAMLConfig(ctx, slug, input.ID)
			out.Body.SAML = cfg
		}
		if strings.EqualFold(existing.Protocol, "oidc") {
			cfg, _ := apps.GetOIDCConfig(ctx, slug, input.ID)
			out.Body.OIDC = cfg
		}
		out.Body.ClientSecret = generatedSecret
		return out, nil
	})

	// Delete application (soft delete)
	huma.Register(api, huma.Operation{
		OperationID: "delete-application",
		Method:      http.MethodDelete,
		Path:        "/api/v1/applications/{id}",
		Summary:     "Delete an application",
		Description: "Permanently deletes an application and its SAML/OIDC config and claim/role mappings",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *DeleteAppInput) (*struct{}, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Hard delete: removes the app plus its SAML/OIDC config so it no longer
		// appears in listings or occupies the entityId/clientId GSI.
		if err := apps.Delete(ctx, slug, input.ID); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to delete application", err)
		}

		// Clean up associated claim and role mappings (best-effort).
		_ = claims.PutClaimMappings(ctx, slug, input.ID, nil)
		_ = claims.PutRoleMappings(ctx, slug, input.ID, nil)

		return nil, nil
	})

	// Enable application
	huma.Register(api, huma.Operation{
		OperationID: "enable-application",
		Method:      http.MethodPost,
		Path:        "/api/v1/applications/{id}/enable",
		Summary:     "Enable an application",
		Description: "Sets the application status to active",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *EnableAppInput) (*AppOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		if err := apps.SetStatus(ctx, slug, input.ID, "active"); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to enable application", err)
		}

		app, err := apps.Get(ctx, slug, input.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve application", err)
		}

		out := &AppOutput{}
		out.Body.Application = *app
		return out, nil
	})

	// Disable application
	huma.Register(api, huma.Operation{
		OperationID: "disable-application",
		Method:      http.MethodPost,
		Path:        "/api/v1/applications/{id}/disable",
		Summary:     "Disable an application",
		Description: "Sets the application status to disabled",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *DisableAppInput) (*AppOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		if err := apps.SetStatus(ctx, slug, input.ID, "disabled"); err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to disable application", err)
		}

		app, err := apps.Get(ctx, slug, input.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to retrieve application", err)
		}

		out := &AppOutput{}
		out.Body.Application = *app
		return out, nil
	})

	// Sub-registrations
	registerImportAppRoute(api, importSvc)
	registerValidateAppRoute(api, apps)
	registerPreviewRoute(api, previewSvc)
	registerRotateSecretRoute(api, apps)
}
