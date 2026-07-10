package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service/onboarding"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

// OnboardingService is the dependency contract — matches *onboarding.Service.
// Declared as an interface so handler tests can stub without spinning up the full service.
type OnboardingService interface {
	CreateTenant(ctx context.Context, in onboarding.CreateTenantInput) (*domain.OnboardingState, error)
	SetCapabilities(ctx context.Context, slug string, packs []string) error
	GenerateIaC(ctx context.Context, slug, format string) (*onboarding.IaCArtifact, error)
	RegisterIdentity(ctx context.Context, slug string, in onboarding.RegisterIdentityInput) error
	ProbeCapabilities(ctx context.Context, slug string) (map[string]bool, error)
	Complete(ctx context.Context, slug string) error
	GetState(ctx context.Context, slug string) (*domain.OnboardingState, error)
}

// mapServiceError converts service errors to Huma HTTP errors. The real error
// is logged server-side but never surfaced to the client: the response body
// carries only a fixed, generic message per category so internal detail (store
// keys, driver strings, wrapped causes) cannot leak (CWE-209). "not
// found" errors → 404; everything else → 400.
func mapServiceError(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		slog.Warn("onboarding request rejected", "reason", "not_found", "error", err)
		return huma.Error404NotFound("onboarding session not found (expired or never started)")
	}
	slog.Warn("onboarding request rejected", "reason", "bad_request", "error", err)
	return huma.Error400BadRequest("onboarding request could not be processed")
}

// requireTenantMatch is the shared BOLA/IDOR guard for every tenant-scoped
// management endpoint. It resolves the caller's tenant from the verified JWT
// context and enforces that it matches the target slug taken from the URL path.
// Cross-tenant access is permitted only for a genuine global operator
// (GlobalOperatorGroup), mirroring the X-Tenant-Id override gate in
// middleware.TenantFromJWTForAPI. It fails closed with 403 when no tenant
// context is present or the slugs differ for a non-operator caller. action
// labels the attempt in the audit log; denyMsg is the client-facing 403 body.
func requireTenantMatch(ctx context.Context, targetSlug, action, denyMsg string) error {
	caller, ok := tenantSlugFromContext(ctx)
	if !ok {
		return huma.Error403Forbidden("tenant context required")
	}
	if caller == targetSlug {
		return nil
	}
	if groups, _ := middleware.GetGroups(ctx); hasGlobalOperator(groups) {
		return nil
	}
	slog.Warn("rejected cross-tenant request",
		"action", action,
		"caller_tenant", caller,
		"target_tenant", targetSlug,
	)
	return huma.Error403Forbidden(denyMsg)
}

// requireOnboardingTenant enforces the cross-tenant guard for the onboarding
// wizard: a caller may only drive onboarding for its own tenant (or be a global
// operator). It delegates to requireTenantMatch with an onboarding-specific
// audit label and 403 message.
func requireOnboardingTenant(ctx context.Context, slug string) error {
	return requireTenantMatch(ctx, slug, "onboard", "forbidden: cannot onboard a different tenant")
}

// hasGlobalOperator reports whether any of the caller's groups grant the
// cross-tenant global-operator role. It mirrors middleware.hasGlobalOperator,
// which is unexported, using the exported GlobalOperatorGroup constant.
func hasGlobalOperator(groups []string) bool {
	for _, g := range groups {
		if g == middleware.GlobalOperatorGroup {
			return true
		}
	}
	return false
}

// requireGlobalOperator gates a genuinely gateway-global operation — one that
// acts on shared, non-tenant-scoped state such as the IdP's active/backup
// signing-cert roles — behind GlobalOperatorGroup. Unlike requireTenantMatch it
// has no "own tenant" escape hatch: these operations affect EVERY tenant, so the
// per-tenant Admins group (which the write-RBAC middleware already requires) is
// deliberately not sufficient — only a genuine global operator may drive them.
// It mirrors the X-Tenant-Id override gate in middleware.TenantFromJWTForAPI and
// fails closed with 403 when the caller lacks the role. action labels the
// attempt in the audit log; denyMsg is the client-facing 403 body.
func requireGlobalOperator(ctx context.Context, action, denyMsg string) error {
	groups, _ := middleware.GetGroups(ctx)
	if hasGlobalOperator(groups) {
		return nil
	}
	slog.Warn("rejected gateway-global operation: caller is not a global operator",
		"action", action,
		"groups", groups,
	)
	return huma.Error403Forbidden(denyMsg)
}

// --- Request/response types ---

type CreateOnboardingInput struct {
	Body struct {
		Slug        string `json:"slug" pattern:"^[a-z][a-z0-9-]{2,30}$" doc:"Tenant slug (DNS-safe, 3-31 chars, lowercase)"`
		DisplayName string `json:"displayName" minLength:"1" maxLength:"255" doc:"Human-readable name"`
		Domain      string `json:"domain,omitempty" doc:"Primary domain for branding"`
	}
}

type OnboardingStateOutput struct {
	Body domain.OnboardingState
}

type OnboardingSlugInput struct {
	Slug string `path:"slug" doc:"Tenant slug"`
}

type SetCapabilitiesInput struct {
	Slug string `path:"slug" doc:"Tenant slug"`
	Body struct {
		Packs []string `json:"packs" doc:"Capability pack names (core/user_directory/user_lifecycle)"`
	}
}

type GenerateIaCInput struct {
	Slug string `path:"slug" doc:"Tenant slug"`
	Body struct {
		Format string `json:"format" enum:"cfn,tf,cli" doc:"Output format"`
	}
}

type IaCArtifactOutput struct {
	Body struct {
		Format         string `json:"format"`
		ExternalID     string `json:"externalId" doc:"Shared secret embedded in trust policy — copy to your CloudFormation stack parameters"`
		DownloadURL    string `json:"downloadUrl,omitempty" doc:"Public HTTPS URL to the rendered template (24-hour expiry)"`
		QuickCreateURL string `json:"cloudformationQuickCreateUrl,omitempty" doc:"CloudFormation console URL that pre-populates template and ExternalId (cfn format only)"`
	}
}

type RegisterIdentityAPIInput struct {
	Slug string `path:"slug" doc:"Tenant slug"`
	Body struct {
		RoleArn   string `json:"roleArn" pattern:"^arn:aws:iam::\\d{12}:role/.+" doc:"Customer role ARN"`
		PoolID    string `json:"poolId" pattern:"^[a-z]{2}-[a-z]+-\\d_\\w+" doc:"Cognito pool ID"`
		ClientID  string `json:"clientId" doc:"Cognito app client ID"`
		SecretArn string `json:"secretArn" pattern:"^arn:aws:secretsmanager:.+" doc:"Secrets Manager ARN of the client_secret"`
		Region    string `json:"region" doc:"AWS region"`
		Domain    string `json:"domain,omitempty" doc:"Cognito domain (optional — auto-discovered if empty)"`
	}
}

type CapabilityMapOutput struct {
	Body struct {
		CapabilityMap map[string]bool `json:"capabilityMap"`
	}
}

// RegisterOnboardingRoutes registers the seven wizard-backing endpoints.
func RegisterOnboardingRoutes(api huma.API, svc OnboardingService) {
	huma.Register(api, huma.Operation{
		OperationID: "create-onboarding",
		Method:      http.MethodPost,
		Path:        "/api/v1/onboarding",
		Summary:     "Start onboarding (step 1)",
		Tags:        []string{"Onboarding"},
	}, func(ctx context.Context, in *CreateOnboardingInput) (*OnboardingStateOutput, error) {
		if err := requireOnboardingTenant(ctx, in.Body.Slug); err != nil {
			return nil, err
		}
		state, err := svc.CreateTenant(ctx, onboarding.CreateTenantInput{
			Slug:        in.Body.Slug,
			DisplayName: in.Body.DisplayName,
			Domain:      in.Body.Domain,
		})
		if err != nil {
			return nil, mapServiceError(err)
		}
		return &OnboardingStateOutput{Body: *state}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-onboarding",
		Method:      http.MethodGet,
		Path:        "/api/v1/onboarding/{slug}",
		Summary:     "Load wizard state for resume",
		Tags:        []string{"Onboarding"},
	}, func(ctx context.Context, in *OnboardingSlugInput) (*OnboardingStateOutput, error) {
		if err := requireOnboardingTenant(ctx, in.Slug); err != nil {
			return nil, err
		}
		state, err := svc.GetState(ctx, in.Slug)
		if err != nil {
			slog.Warn("onboarding request rejected", "reason", "not_found", "error", err)
			return nil, huma.Error404NotFound("onboarding state not found")
		}
		return &OnboardingStateOutput{Body: *state}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-capabilities",
		Method:      http.MethodPut,
		Path:        "/api/v1/onboarding/{slug}/capabilities",
		Summary:     "Choose feature packs (step 2)",
		Tags:        []string{"Onboarding"},
	}, func(ctx context.Context, in *SetCapabilitiesInput) (*struct{}, error) {
		if err := requireOnboardingTenant(ctx, in.Slug); err != nil {
			return nil, err
		}
		if err := svc.SetCapabilities(ctx, in.Slug, in.Body.Packs); err != nil {
			return nil, mapServiceError(err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "generate-iac",
		Method:      http.MethodPost,
		Path:        "/api/v1/onboarding/{slug}/iac",
		Summary:     "Generate IaC artifact (step 3)",
		Tags:        []string{"Onboarding"},
	}, func(ctx context.Context, in *GenerateIaCInput) (*IaCArtifactOutput, error) {
		if err := requireOnboardingTenant(ctx, in.Slug); err != nil {
			return nil, err
		}
		artifact, err := svc.GenerateIaC(ctx, in.Slug, in.Body.Format)
		if err != nil {
			return nil, mapServiceError(err)
		}
		out := &IaCArtifactOutput{}
		out.Body.Format = artifact.Format
		out.Body.ExternalID = artifact.ExternalID
		out.Body.DownloadURL = artifact.DownloadURL
		out.Body.QuickCreateURL = artifact.QuickCreateURL
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "register-identity",
		Method:      http.MethodPost,
		Path:        "/api/v1/onboarding/{slug}/identity",
		Summary:     "Register AWS identity outputs (step 4)",
		Tags:        []string{"Onboarding"},
	}, func(ctx context.Context, in *RegisterIdentityAPIInput) (*struct{}, error) {
		if err := requireOnboardingTenant(ctx, in.Slug); err != nil {
			return nil, err
		}
		err := svc.RegisterIdentity(ctx, in.Slug, onboarding.RegisterIdentityInput{
			RoleArn:   in.Body.RoleArn,
			PoolID:    in.Body.PoolID,
			ClientID:  in.Body.ClientID,
			SecretArn: in.Body.SecretArn,
			Region:    in.Body.Region,
			Domain:    in.Body.Domain,
		})
		if err != nil {
			return nil, mapServiceError(err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "probe-capabilities",
		Method:      http.MethodPost,
		Path:        "/api/v1/onboarding/{slug}/probe",
		Summary:     "Probe capabilities (step 5 — stubbed)",
		Tags:        []string{"Onboarding"},
	}, func(ctx context.Context, in *OnboardingSlugInput) (*CapabilityMapOutput, error) {
		if err := requireOnboardingTenant(ctx, in.Slug); err != nil {
			return nil, err
		}
		result, err := svc.ProbeCapabilities(ctx, in.Slug)
		if err != nil {
			return nil, mapServiceError(err)
		}
		out := &CapabilityMapOutput{}
		out.Body.CapabilityMap = result
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "complete-onboarding",
		Method:      http.MethodPost,
		Path:        "/api/v1/onboarding/{slug}/complete",
		Summary:     "Finalize onboarding (step 6)",
		Tags:        []string{"Onboarding"},
	}, func(ctx context.Context, in *OnboardingSlugInput) (*struct{}, error) {
		if err := requireOnboardingTenant(ctx, in.Slug); err != nil {
			return nil, err
		}
		if err := svc.Complete(ctx, in.Slug); err != nil {
			return nil, mapServiceError(err)
		}
		return &struct{}{}, nil
	})
}
