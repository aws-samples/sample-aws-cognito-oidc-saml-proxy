package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

// Dependencies holds all dependencies needed by API handlers.
type Dependencies struct {
	Tenants       domain.TenantRepository
	Apps          domain.AppRepository
	Sources       domain.SourceRepository
	Claims        domain.ClaimRepository
	Audit         domain.AuditRepository
	ImportSvc     *service.MetadataImportService
	PreviewSvc    *service.PreviewService
	CertSvc       *service.CertificateService
	CertMgr       *service.CertManager
	SettingsSvc   *service.SettingsService
	OnboardingSvc OnboardingService
	BaseURL       string
	EntityID      string
	KMSKeyID      string

	// AWSRegion and SaaSAccountID identify the gateway's own AWS account and
	// operating region. They pin any client-supplied per-tenant KMS key ARN to
	// the gateway account so a tenant admin cannot register a cross-account key
	// the gateway's role happens to have a grant on. SaaSAccountID is
	// config.SaaSAccountID; AWSRegion is config.AWSRegion.
	AWSRegion     string
	SaaSAccountID string

	// Environment is the parsed deployment environment. It is the sole gate that
	// decides whether the local-dev auth bypass may be selected:
	// only config.EnvLocal permits it. In every other environment NewRouter
	// requires a real JWKS Verifier and fails closed without one.
	Environment config.Environment
	// Verifier cryptographically verifies inbound management-API ID tokens against
	// the Cognito JWKS endpoint. It MUST be non-nil in every deployed
	// (dev/staging/prod) environment; NewRouter refuses to build a router without
	// it outside local dev.
	Verifier *cognito.JWKSVerifier
	// VerifierClientID is the Cognito SPA app-client ID the ID token's `aud` must
	// match. Only SPA-issued ID tokens (token_use=id) reach /api/v1/*, so this is
	// the single expected audience.
	VerifierClientID string

	// EdgeAuthSecret is the CloudFront origin-verify shared secret. When
	// non-empty (every deployed environment) NewRouter installs a middleware that
	// rejects any request lacking the matching X-Origin-Verify header, closing the
	// API Gateway execute-api bypass of the CloudFront WAF. Empty only in local
	// dev, where the middleware is a no-op. Sourced from config.EdgeAuthSecret.
	EdgeAuthSecret string
}

// NewRouter creates a new Chi router with middleware. It fails closed on
// authentication: if the environment is anything other than local and no real
// JWKS Verifier is supplied, it returns an error rather than silently building a
// router that would accept unauthenticated (or merely decode-only) requests.
// A deployed build therefore cannot come up with authentication
// disabled — the process exits at startup instead.
func NewRouter(deps Dependencies) (chi.Router, error) {
	authMiddleware, err := apiAuthMiddleware(deps)
	if err != nil {
		return nil, err
	}

	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.Logging)
	r.Use(middleware.Metrics)

	// Edge gate: reject any request that did not transit CloudFront (and
	// therefore the CloudFront WAF) before auth or tenant resolution runs. In a
	// deployed environment EdgeAuthSecret is non-empty and this enforces on every
	// path; in local dev it is empty and the middleware is a no-op passthrough.
	r.Use(middleware.RequireEdgeSecret(deps.EdgeAuthSecret))

	// Apply RBAC and tenant middleware globally — they skip non-API paths internally.
	// The auth middleware only enforces on /api/v1/* paths (skips /health, /saml/*, /t/*);
	// TenantFromJWT only loads tenant context on /api/v1/* paths.
	r.Use(authMiddleware)
	// Middleware needs concrete type for now (can be improved later)
	tenantStore, ok := deps.Tenants.(*store.TenantStore)
	if !ok {
		return nil, fmt.Errorf("TenantFromJWTForAPI middleware requires *store.TenantStore, got %T", deps.Tenants)
	}
	r.Use(middleware.TenantFromJWTForAPI(tenantStore))

	return r, nil
}

// apiAuthMiddleware selects the /api/v1/* authentication middleware, failing
// closed. The decision is driven entirely by the parsed environment enum
// and the presence of a real verifier — never by a raw environment-variable read
// at request time:
//
//   - A real JWKS Verifier is present  → cryptographic JWT verification (the
//     deployed path). Used in every environment when wired, including local dev
//     against a real pool.
//   - No verifier, environment is local → the explicit, loudly-logged local-dev
//     bypass. This is the ONLY unauthenticated path and it is unreachable in a
//     deployed build.
//   - No verifier, environment is not local → refuse to build the router. The
//     process fails to start rather than degrade to decode-only or open access.
func apiAuthMiddleware(deps Dependencies) (func(next http.Handler) http.Handler, error) {
	if deps.Verifier != nil {
		return middleware.RequireAuthForAPIWithVerifier(deps.Verifier, deps.VerifierClientID), nil
	}
	if deps.Environment.IsLocal() {
		slog.Warn("LOCAL DEV: management API authentication is disabled (no JWKS verifier configured); this is only permitted because PROXY_ENVIRONMENT=local")
		return middleware.AllowUnauthenticatedForAPILocalDev(), nil
	}
	return nil, fmt.Errorf("refusing to start: environment %q requires a Cognito JWKS verifier for management-API authentication, but none was configured (set PROXY_COGNITO_POOL_ID and PROXY_COGNITO_CLIENT_ID)", deps.Environment)
}

// genericServerErrorMessage is the only detail a 5xx huma response ever carries
// to the client. The real cause is logged server-side keyed by the correlation
// id embedded in the response so operators can still triage the failure.
const genericServerErrorMessage = "internal server error"

// installErrorSanitizerOnce guards the one-time replacement of the package-level
// huma.NewError hook so that concurrent router construction (prod plus parallel
// tests) wires it exactly once and idempotently.
var installErrorSanitizerOnce sync.Once

// installErrorSanitizer replaces huma's global error constructor so that any
// response with status >= 500 is scrubbed of internal detail before it reaches
// the client (CWE-209). huma routes every error — the Error5xx helpers,
// WriteErr, and bare errors returned from handlers — through huma.NewError, so
// this single hook is the global backstop across the whole huma surface even as
// individual endpoints sanitize their own responses.
//
// For 5xx the detailed message and wrapped errors are logged via slog keyed by a
// short random correlation id, and the client receives only a generic message
// plus that id (so a support caller can be correlated to the server log without
// leaking stack/driver/AWS detail). 4xx and below are passed through unchanged —
// those messages are intentionally client-facing.
//
// It is wired once, idempotently, in NewHumaAPI so that production and tests
// share the same behaviour without re-registering on every router build.
func installErrorSanitizer() {
	installErrorSanitizerOnce.Do(func() {
		base := huma.NewError
		huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
			if status < http.StatusInternalServerError {
				return base(status, msg, errs...)
			}

			correlationID := newCorrelationID()

			// Log the full detail server-side, keyed by the correlation id, so
			// operators can still diagnose the failure. The client never sees it.
			attrs := []any{"correlationId", correlationID, "status", status, "detail", msg}
			for i, e := range errs {
				if e != nil {
					attrs = append(attrs, fmt.Sprintf("error_%d", i), e.Error())
				}
			}
			slog.Error("management API server error", attrs...)

			// Return a scrubbed error: generic message + correlation id, no
			// wrapped errors (which would re-expose the internal detail).
			return base(status, fmt.Sprintf("%s (correlation id: %s)", genericServerErrorMessage, correlationID))
		}
	})
}

// newCorrelationID returns a short random hex id used to tie a scrubbed 5xx
// client response to the detailed server-side log entry. It falls back to a
// fixed sentinel only if the system CSPRNG is unavailable, so a response is
// never emitted without an id.
func newCorrelationID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b)
}

// NewHumaAPI creates a Huma API instance from a Chi router. It also installs the
// global 5xx error sanitizer (once) so no huma endpoint can leak internal error
// detail to clients.
func NewHumaAPI(r chi.Router, title, version string) huma.API {
	installErrorSanitizer()
	config := huma.DefaultConfig(title, version)
	config.Servers = []*huma.Server{
		{URL: "http://localhost:8080", Description: "Local development"},
	}
	return humachi.New(r, config)
}

// RegisterAPIRoutes registers all API routes with their handlers.
func RegisterAPIRoutes(api huma.API, deps Dependencies) {
	// Pin client-supplied per-tenant KMS keys to the gateway's own account/region.
	// Strict everywhere except local dev, so a deployed gateway that does not know
	// its own account refuses a fully-qualified ARN rather than accepting it
	// unpinned.
	kmsPolicy := KMSKeyPolicy{
		AccountID: deps.SaaSAccountID,
		Region:    deps.AWSRegion,
		Strict:    !deps.Environment.IsLocal(),
	}
	RegisterTenantRoutes(api, deps.Tenants, deps.Apps, kmsPolicy)
	RegisterSourceRoutes(api, deps.Sources)
	RegisterAppRoutes(api, deps.Apps, deps.Claims, deps.ImportSvc, deps.PreviewSvc)
	RegisterMappingRoutes(api, deps.Apps, deps.Claims)
	RegisterIntegrationRoutes(api, deps.Apps, deps.BaseURL, deps.CertSvc)
	RegisterHealthRoutes(api, deps.CertSvc, deps.CertMgr)
	RegisterDebugRoutes(api, deps.Audit)
	RegisterAnalyticsRoutes(api, deps.Apps, deps.Audit)
	RegisterSettingsRoutes(api, deps.SettingsSvc)
	if deps.OnboardingSvc != nil {
		RegisterOnboardingRoutes(api, deps.OnboardingSvc)
	}
}
