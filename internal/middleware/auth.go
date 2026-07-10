package middleware

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
)

// RequireAuth returns middleware that validates JWT tokens from the Authorization
// header and enforces RBAC based on Cognito groups.
//
// With a non-nil JWKSVerifier, JWT signatures are cryptographically verified
// against the Cognito JWKS endpoint. When the verifier is nil, the middleware
// still requires a bearer token and enforces RBAC, but only decodes the payload
// without verifying the signature — a decode-only TEST DOUBLE used by the RBAC
// unit tests, never a deployed code path. Deployed wiring is required to supply a
// real verifier (api.NewRouter fails closed otherwise), so this
// convenience wrapper must not be used to build a production router.
//
// Write operations (POST, PUT, DELETE) require the "Admins" group.
// Read operations (GET) allow "Admins" or "Operators" groups.
//
// There is NO environment-based bypass here: a deployed build can never disable
// authentication by setting an environment variable. The only way to
// skip auth is the explicit, local-only AllowUnauthenticatedForAPILocalDev test
// double, selected once at router-construction time.
func RequireAuth(next http.Handler) http.Handler {
	return RequireAuthWithVerifier(nil, "")(next)
}

// RequireAuthWithVerifier returns middleware that validates JWT tokens. If
// verifier is non-nil, JWT signatures are cryptographically verified via JWKS
// (the deployed path). If nil, the middleware still requires a bearer token and
// enforces RBAC but skips signature verification — a decode-only test double for
// exercising RBAC logic in unit tests. It is never selected by deployed wiring:
// api.NewRouter refuses to build a non-local router without a real verifier.
func RequireAuthWithVerifier(verifier *cognito.JWKSVerifier, clientID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Bearer token
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"invalid Authorization header format"}`, http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" {
				http.Error(w, `{"error":"empty bearer token"}`, http.StatusUnauthorized)
				return
			}

			var groups []string
			var claims map[string]interface{}
			var err error

			if verifier != nil {
				// Production: verify JWT signature via JWKS
				claims, err = verifier.Verify(token, clientID)
				if err != nil {
					slog.Error("JWKS JWT verification failed", "error", err)
					http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
					return
				}
				groups = extractGroupsFromClaims(claims)
			} else {
				// Fallback: decode-only (local dev or when API Gateway handles verification)
				groups, claims, err = extractGroupsFromJWT(token)
				if err != nil {
					slog.Error("failed to decode JWT", "error", err)
					http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
					return
				}
			}

			// Extract tenant_id from JWT claims and store in context
			ctx := r.Context()
			if tenantID, ok := claims["custom:tenant_id"].(string); ok && tenantID != "" {
				ctx = SetTenantSlug(ctx, tenantID)
			}
			// Persist the caller's groups so downstream tenant-resolution
			// middleware can make entitlement decisions — specifically gating
			// the X-Tenant-Id cross-tenant override behind the global operator
			// role (see TenantFromJWTForAPI). Without this the override could be
			// driven by any authenticated per-tenant admin.
			ctx = SetGroups(ctx, groups)
			r = r.WithContext(ctx)

			// RBAC check
			isWrite := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete
			if isWrite {
				if !containsGroup(groups, "Admins") {
					slog.Warn("forbidden: write operation requires Admins group",
						"method", r.Method,
						"path", r.URL.Path,
						"groups", groups,
					)
					http.Error(w, `{"error":"forbidden: Admins group required for write operations"}`, http.StatusForbidden)
					return
				}
			} else {
				// Read operations (GET, etc.)
				if !containsGroup(groups, "Admins") && !containsGroup(groups, "Operators") {
					slog.Warn("forbidden: read operation requires Admins or Operators group",
						"method", r.Method,
						"path", r.URL.Path,
						"groups", groups,
					)
					http.Error(w, `{"error":"forbidden: Admins or Operators group required"}`, http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractGroupsFromClaims extracts cognito:groups from a pre-validated claims map.
func extractGroupsFromClaims(claims map[string]interface{}) []string {
	var groups []string
	if rawGroups, ok := claims["cognito:groups"].([]interface{}); ok {
		for _, g := range rawGroups {
			if s, ok := g.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	return groups
}

// extractGroupsFromJWT decodes the JWT payload segment and extracts cognito:groups.
// It returns the groups slice and the full claims map for additional processing.
func extractGroupsFromJWT(token string) ([]string, map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, &jwtError{"invalid JWT format"}
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, &jwtError{"failed to decode JWT payload"}
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, &jwtError{"failed to parse JWT payload"}
	}

	var groups []string
	if rawGroups, ok := payload["cognito:groups"].([]interface{}); ok {
		for _, g := range rawGroups {
			if s, ok := g.(string); ok {
				groups = append(groups, s)
			}
		}
	}

	return groups, payload, nil
}

// containsGroup checks if a group name exists in the groups slice.
func containsGroup(groups []string, target string) bool {
	for _, g := range groups {
		if g == target {
			return true
		}
	}
	return false
}

type jwtError struct {
	msg string
}

func (e *jwtError) Error() string {
	return e.msg
}

// RequireAuthForAPI wraps RequireAuth but only applies to /api/v1/* paths.
// Other paths (health, SAML, OIDC, OpenAPI) pass through without auth.
func RequireAuthForAPI(next http.Handler) http.Handler {
	return RequireAuthForAPIWithVerifier(nil, "")(next)
}

// RequireAuthForAPIWithVerifier wraps RequireAuthWithVerifier but only applies
// to /api/v1/* paths. When verifier is non-nil, JWT signatures are
// cryptographically verified via JWKS.
func RequireAuthForAPIWithVerifier(verifier *cognito.JWKSVerifier, clientID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		authMiddleware := RequireAuthWithVerifier(verifier, clientID)(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/v1/") {
				authMiddleware.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AllowUnauthenticatedForAPILocalDev returns middleware that lets /api/v1/*
// requests through WITHOUT any authentication. It is an explicit, named test
// double for skipping authentication: rather than a deployed build silently
// disabling auth based on an environment variable, the bypass is an explicit
// function that the caller must choose at router-construction time, and which
// api.NewRouter selects ONLY for the local developer environment. Every call
// logs loudly so an accidental production selection is impossible to miss in
// the logs.
//
// This must never be wired into a deployed (dev/staging/prod) router. The single
// caller that may select it is api.NewRouter, gated on config.Environment.IsLocal().
func AllowUnauthenticatedForAPILocalDev() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/v1/") {
				slog.Warn("LOCAL DEV ONLY: serving management API request with NO authentication — this bypass must never run in a deployed environment",
					"method", r.Method,
					"path", r.URL.Path,
				)
			}
			next.ServeHTTP(w, r)
		})
	}
}
