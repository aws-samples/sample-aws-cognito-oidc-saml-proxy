package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
)

// EdgeVerifyHeader is the request header CloudFront injects on every origin
// request carrying the shared origin-verify secret. CloudFront overwrites any
// value a viewer tries to supply for a configured custom origin header, so a
// client that reaches the API Gateway execute-api endpoint directly (bypassing
// CloudFront and its WAF) cannot forge it.
const EdgeVerifyHeader = "X-Origin-Verify"

// RequireEdgeSecret returns middleware that enforces the CloudFront
// origin-verify shared secret on every request, closing the execute-api bypass.
// WAFv2 cannot associate a Web ACL with an API Gateway HTTP (v2) stage,
// so the API's only edge protection is the CloudFront Web ACL; without this gate
// an attacker could hit the raw execute-api URL and skip the WAF's managed rule
// groups and rate limits entirely. CloudFront adds EdgeVerifyHeader on the origin
// request (frontend.tf custom_header) and overwrites any viewer-supplied copy, so
// only traffic that actually transited CloudFront (and therefore the WAF) carries
// the correct secret; everything else is rejected 403.
//
// Fail-closed like the management-API auth gate: if secret is empty the
// middleware is a no-op passthrough, which is ONLY the local-dev case. config.Load
// requires PROXY_EDGE_AUTH_SECRET in every deployed (dev/staging/prod)
// environment, so a deployed Lambda never boots with an empty secret and therefore
// always enforces. The comparison is constant-time to avoid a timing oracle on the
// secret.
func RequireEdgeSecret(secret string) func(http.Handler) http.Handler {
	want := []byte(secret)
	enforce := len(want) > 0

	return func(next http.Handler) http.Handler {
		if !enforce {
			slog.Warn("LOCAL DEV: CloudFront origin-verify enforcement is disabled (no PROXY_EDGE_AUTH_SECRET set); direct API access is not gated — this must never happen in a deployed environment")
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := []byte(r.Header.Get(EdgeVerifyHeader))
			if subtle.ConstantTimeCompare(got, want) != 1 {
				slog.Warn("rejected request lacking a valid CloudFront origin-verify header",
					"path", r.URL.Path,
					"method", r.Method,
					"remoteAddr", r.RemoteAddr,
				)
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
