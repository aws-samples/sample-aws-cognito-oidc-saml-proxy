package domain

import (
	"context"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// AppReader provides read operations for Applications.
type AppReader interface {
	Get(ctx context.Context, tenantSlug, appID string) (*tenant.Application, error)
	// GetByTenantEntityID resolves a SAML app within a single tenant. Tenant is
	// a required argument, not derived from the entityID, because SAML
	// entityIDs are unique only within a tenant — a cross-tenant lookup would
	// let one tenant's assertion resolve another tenant's app.
	GetByTenantEntityID(ctx context.Context, tenantSlug, entityID string) (app *tenant.Application, samlCfg *tenant.SAMLConfig, err error)
	GetSAMLConfig(ctx context.Context, tenantSlug, appID string) (*tenant.SAMLConfig, error)
	GetOIDCConfig(ctx context.Context, tenantSlug, appID string) (*tenant.OIDCConfig, error)
	List(ctx context.Context, tenantSlug string) ([]*tenant.Application, error)
}

// AppWriter provides write operations for Applications.
type AppWriter interface {
	Create(ctx context.Context, tenantSlug string, app *tenant.Application, samlCfg *tenant.SAMLConfig) (string, error)
	Update(ctx context.Context, tenantSlug string, app *tenant.Application) error
	UpdateSAMLConfig(ctx context.Context, tenantSlug, appID string, cfg *tenant.SAMLConfig) error
	UpdateOIDCConfig(ctx context.Context, tenantSlug, appID string, cfg *tenant.OIDCConfig) error
	SetStatus(ctx context.Context, tenantSlug, appID, status string) error
	Delete(ctx context.Context, tenantSlug, appID string) error
}

// AppRepository combines read and write operations for Applications.
type AppRepository interface {
	AppReader
	AppWriter
}

// TenantReader provides read operations for Tenants.
type TenantReader interface {
	Get(ctx context.Context, slug string) (*tenant.Tenant, error)
	List(ctx context.Context) ([]*tenant.Tenant, error)
}

// TenantWriter provides write operations for Tenants.
type TenantWriter interface {
	Create(ctx context.Context, t *tenant.Tenant) error
	Update(ctx context.Context, t *tenant.Tenant) error
	Delete(ctx context.Context, slug string) error
}

// TenantRepository combines read and write operations for Tenants.
type TenantRepository interface {
	TenantReader
	TenantWriter
}

// SourceReader provides read operations for IdentitySources.
type SourceReader interface {
	Get(ctx context.Context, tenantSlug, sourceID string) (*tenant.IdentitySource, error)
	List(ctx context.Context, tenantSlug string) ([]*tenant.IdentitySource, error)
}

// SourceWriter provides write operations for IdentitySources.
type SourceWriter interface {
	Create(ctx context.Context, tenantSlug string, src *tenant.IdentitySource) (string, error)
	Update(ctx context.Context, tenantSlug string, src *tenant.IdentitySource) error
	Delete(ctx context.Context, tenantSlug, sourceID string) error
}

// SourceRepository combines read and write operations for IdentitySources.
type SourceRepository interface {
	SourceReader
	SourceWriter
}

// ClaimRepository provides operations for ClaimMapping and RoleMapping.
type ClaimRepository interface {
	GetClaimMappings(ctx context.Context, tenantSlug, appID string) ([]tenant.ClaimMapping, error)
	PutClaimMappings(ctx context.Context, tenantSlug, appID string, mappings []tenant.ClaimMapping) error
	GetRoleMappings(ctx context.Context, tenantSlug, appID string) ([]tenant.RoleMapping, error)
	PutRoleMappings(ctx context.Context, tenantSlug, appID string, mappings []tenant.RoleMapping) error
}

// AuditRepository provides flow tracing and audit logging.
//
// Every method takes tenantSlug as a required argument — like every other
// repository here — rather than deriving it implicitly. Flow traces carry
// identity metadata (entity IDs, user IDs, timing), so a read that is not
// scoped to the caller's tenant leaks one tenant's activity to another. The
// store partitions records by tenant, so GetFlow/GetRecentSteps physically
// cannot return another tenant's steps.
type AuditRepository interface {
	LogStep(ctx context.Context, tenantSlug, flowID, stepType, spEntityID, userID string, payload map[string]string) error
	// GetFlow returns the steps of flowID only if that flow belongs to
	// tenantSlug; a flow owned by another tenant resolves as empty.
	GetFlow(ctx context.Context, tenantSlug, flowID string) ([]FlowStep, error)
	// GetRecentSteps returns recent steps for tenantSlug only.
	GetRecentSteps(ctx context.Context, tenantSlug string, limit int) ([]FlowStep, error)
}

// SessionRepository tracks SLO session participants across multiple SPs and
// records server-side session revocations.
type SessionRepository interface {
	AddParticipant(ctx context.Context, sessionIndex, spEntityID, userID, nameID string, expiry time.Time) error
	GetParticipants(ctx context.Context, sessionIndex string) ([]SessionParticipant, error)
	// RevokeSession records a server-side revocation marker for a SAML session,
	// keyed by its SessionIndex. The gateway session is carried in a signed,
	// stateless cookie with an 8h lifetime, so clearing the cookie on logout
	// cannot stop a copied cookie replayed at the (separate) SSO Lambda. A
	// durable marker lets GetSession reject a revoked session before the
	// cookie's own expiry.
	RevokeSession(ctx context.Context, sessionIndex string) error
	// IsSessionRevoked reports whether RevokeSession has been called for the
	// given SessionIndex and the marker has not yet expired. Callers MUST fail
	// closed (treat the session as revoked) on error rather than trusting the
	// cookie.
	IsSessionRevoked(ctx context.Context, sessionIndex string) (bool, error)
}

// ReplayRepository provides protection against AuthnRequest replay attacks.
type ReplayRepository interface {
	MarkSeen(ctx context.Context, authnRequestID string, ttl time.Duration) error
	IsSeen(ctx context.Context, authnRequestID string) (bool, error)
}
