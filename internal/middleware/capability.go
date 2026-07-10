package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// RequireCapability returns middleware that allows the request only when the
// tenant on the context has the named capability granted in its CapabilityMap.
//
// Behaviour:
//   - Map contains the key with value true → allow, next handler runs.
//   - Map contains the key with value false, OR key missing → 403 with
//     {"error":"capability_not_enabled","capabilityRequired":"<cap>","remediation":"/onboarding"}.
//   - Map is nil (legacy Terraform-seeded tenants) → allow, preserving
//     backwards-compatible behaviour.
//   - No tenant in context → 500 (this is a wiring bug; RequireCapability must
//     come after TenantFromJWT/TenantFromPath in the middleware chain).
func RequireCapability(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tnt, ok := tenant.FromContext(r.Context())
			if !ok || tnt == nil {
				slog.Error("RequireCapability: no tenant in context", "path", r.URL.Path, "capability", name)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "internal_error",
				})
				return
			}

			// nil map = legacy tenant — allow any capability for backwards compatibility.
			if tnt.CapabilityMap == nil {
				next.ServeHTTP(w, r)
				return
			}

			if tnt.CapabilityMap[name] {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":              "capability_not_enabled",
				"capabilityRequired": name,
				"remediation":        "/onboarding",
			})
		})
	}
}
