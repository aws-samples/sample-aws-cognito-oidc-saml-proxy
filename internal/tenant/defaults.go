package tenant

// DefaultSlug is the tenant slug used when a request carries no tenant context
// (e.g. a Cognito token without a custom:tenant_id claim). The gateway seeds a
// tenant with this slug at startup so protocol and management flows always
// resolve to a valid tenant.
const DefaultSlug = "default"

// DefaultDisplayName is the human-readable name for the default tenant.
const DefaultDisplayName = "Default Tenant"

// NewDefaultTenant returns a Tenant populated with the standard gateway
// defaults for the built-in default tenant. Used by the startup seeder.
func NewDefaultTenant() *Tenant {
	return &Tenant{
		Slug:             DefaultSlug,
		DisplayName:      DefaultDisplayName,
		Plan:             "standard",
		Status:           "active",
		MaxApps:          10,
		MaxAuthsPerMonth: 10000,

		DefaultSessionDurationSec:     3600,
		DefaultSignResponse:           true,
		DefaultSignAssertion:          true,
		DefaultNameIDFormat:           "email",
		DefaultIDTokenLifetimeSec:     3600,
		DefaultAccessTokenLifetimeSec: 3600,
		DefaultScopes:                 []string{"openid", "email", "profile"},
	}
}
