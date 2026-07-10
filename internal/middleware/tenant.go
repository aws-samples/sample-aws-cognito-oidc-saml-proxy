package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

type tenantSlugKey struct{}

type groupsKey struct{}

// SetTenantSlug stores the tenant slug extracted from JWT (called by auth middleware).
func SetTenantSlug(ctx context.Context, slug string) context.Context {
	return context.WithValue(ctx, tenantSlugKey{}, slug)
}

// GetTenantSlug retrieves the tenant slug from context (used by TenantFromJWT).
func GetTenantSlug(ctx context.Context) (string, bool) {
	slug, ok := ctx.Value(tenantSlugKey{}).(string)
	return slug, ok
}

// SetGroups stores the caller's Cognito groups on the context (called by
// RequireAuth). Downstream middleware reads them for entitlement decisions.
func SetGroups(ctx context.Context, groups []string) context.Context {
	return context.WithValue(ctx, groupsKey{}, groups)
}

// GetGroups retrieves the caller's Cognito groups from context.
func GetGroups(ctx context.Context) ([]string, bool) {
	groups, ok := ctx.Value(groupsKey{}).([]string)
	return groups, ok
}

// GlobalOperatorGroup is the Cognito group that designates a genuinely global
// gateway operator — a principal entitled to act across every tenant boundary.
// It is deliberately distinct from the per-tenant "Admins"/"Operators" groups
// (which gate management-API access within a single tenant): only a member of
// this group may use the X-Tenant-Id header to target a tenant other than the
// one bound to its token. See TenantFromJWTForAPI.
const GlobalOperatorGroup = "GlobalOperators"

// hasGlobalOperator reports whether any of the caller's groups grant the
// cross-tenant global-operator role.
func hasGlobalOperator(groups []string) bool {
	for _, g := range groups {
		if g == GlobalOperatorGroup {
			return true
		}
	}
	return false
}

// TenantFromPath is middleware for /t/{tenant}/* routes (SAML protocol endpoints).
// It extracts the tenant slug from the URL path, loads the tenant, and adds it to context.
func TenantFromPath(tenantStore *store.TenantStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract tenant slug from path
			slug, err := tenant.ExtractFromPath(r.URL.Path)
			if err != nil {
				slog.Warn("failed to extract tenant from path",
					"path", r.URL.Path,
					"error", err,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "tenant not found"}); err != nil {
					slog.Error("failed to encode response", "error", err)
				}
				return
			}

			// Load tenant from store
			t, err := tenantStore.Get(r.Context(), slug)
			if err != nil {
				slog.Warn("tenant not found in store",
					"slug", slug,
					"error", err,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "tenant not found"}); err != nil {
					slog.Error("failed to encode response", "error", err)
				}
				return
			}

			// Check tenant status
			if t.Status == "suspended" {
				slog.Warn("tenant is suspended",
					"slug", slug,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "tenant suspended"}); err != nil {
					slog.Error("failed to encode response", "error", err)
				}
				return
			}

			// Add tenant to context
			ctx := tenant.WithContext(r.Context(), t)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TenantHeaderOverride is the request header a console client sets to target a
// tenant other than the one bound to its token (the tenant switcher). It is
// honored ONLY for callers in the global operator role (GlobalOperatorGroup);
// for everyone else the JWT's custom:tenant_id claim is authoritative and the
// header is ignored.
const TenantHeaderOverride = "X-Tenant-Id"

// TenantFromJWTForAPI wraps TenantFromJWT but only applies to /api/v1/* paths.
//
// Tenant resolution precedence for management-API requests:
//  1. custom:tenant_id from the JWT (set upstream by RequireAuth) — authoritative.
//  2. the built-in default tenant, when the token carries no tenant.
//
// The X-Tenant-Id header may override (1), but ONLY when the caller holds the
// global operator role (GlobalOperatorGroup) — a role deliberately separate
// from the per-tenant Admins/Operators groups. Any other caller that sends the
// header is rejected with 403 rather than silently operating cross-tenant: the
// override is a privileged, audited action, never an ambient capability of a
// per-tenant admin. Every honored override is logged with both the
// caller's claimed tenant and the requested target tenant.
func TenantFromJWTForAPI(tenantStore *store.TenantStore) func(http.Handler) http.Handler {
	tenantMiddleware := TenantFromJWT(tenantStore)
	return func(next http.Handler) http.Handler {
		wrapped := tenantMiddleware(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}

			claimed, hasClaim := GetTenantSlug(r.Context())

			if override := strings.TrimSpace(r.Header.Get(TenantHeaderOverride)); override != "" {
				groups, _ := GetGroups(r.Context())
				if !hasGlobalOperator(groups) {
					// A per-tenant caller attempted a cross-tenant override.
					// Fail closed — do not fall back to the claim, so the
					// attempt is unambiguously rejected and surfaced.
					slog.Warn("rejected X-Tenant-Id override: caller is not a global operator",
						"path", r.URL.Path,
						"claimed_tenant", claimed,
						"target_tenant", override,
						"groups", groups,
					)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					if err := json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: tenant override not permitted"}); err != nil {
						slog.Error("failed to encode response", "error", err)
					}
					return
				}
				slog.Info("honoring X-Tenant-Id override for global operator",
					"path", r.URL.Path,
					"claimed_tenant", claimed,
					"target_tenant", override,
				)
				r = r.WithContext(SetTenantSlug(r.Context(), override))
			} else if !hasClaim {
				// No tenant in the token → fall back to the default tenant.
				r = r.WithContext(SetTenantSlug(r.Context(), tenant.DefaultSlug))
			}
			wrapped.ServeHTTP(w, r)
		})
	}
}

// TenantFromJWT is middleware for /api/v1/* routes (management API).
// It expects the tenant slug to already be set in context by RequireAuth middleware,
// loads the tenant, and adds it to context.
func TenantFromJWT(tenantStore *store.TenantStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract tenant slug from context (set by auth middleware)
			slug, ok := GetTenantSlug(r.Context())
			if !ok || slug == "" {
				slog.Warn("tenant slug not found in context",
					"path", r.URL.Path,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"}); err != nil {
					slog.Error("failed to encode response", "error", err)
				}
				return
			}

			// Load tenant from store
			t, err := tenantStore.Get(r.Context(), slug)
			if err != nil {
				slog.Warn("tenant not found in store",
					"slug", slug,
					"error", err,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"}); err != nil {
					slog.Error("failed to encode response", "error", err)
				}
				return
			}

			// Add tenant to context
			ctx := tenant.WithContext(r.Context(), t)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
