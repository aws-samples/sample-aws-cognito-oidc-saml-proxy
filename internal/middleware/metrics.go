package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Metrics middleware logs CloudWatch EMF-format metrics for SAML operations.
// Matches both legacy /saml/* paths and tenant-scoped /t/{tenant}/saml/* paths.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		if strings.Contains(r.URL.Path, "/saml/") {
			duration := time.Since(start).Milliseconds()
			slog.Info("saml_metrics",
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration,
				"success", wrapped.statusCode < 400,
			)
		}
	})
}
