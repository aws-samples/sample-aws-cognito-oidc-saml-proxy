package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Logging middleware logs structured request information using slog.
// It creates a request-scoped logger enriched with correlation ID, path,
// method, and tenant (when present) and stores it in the request context.
// Downstream handlers can retrieve it via LoggerFromContext.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Extract correlation ID from AWS trace header or generic request ID header.
		requestID := r.Header.Get("X-Amzn-Trace-Id")
		if requestID == "" {
			requestID = r.Header.Get("X-Request-Id")
		}

		// Extract tenant slug from URL if present (/t/{tenant}/...).
		tenant := ""
		if parts := strings.Split(r.URL.Path, "/"); len(parts) >= 3 && parts[1] == "t" {
			tenant = parts[2]
		}

		// Build request-scoped logger with common attributes.
		logger := slog.Default().With(
			"requestId", requestID,
			"path", r.URL.Path,
			"method", r.Method,
		)
		if tenant != "" {
			logger = logger.With("tenant", tenant)
		}

		// Inject logger into request context.
		ctx := ContextWithLogger(r.Context(), logger)

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		logger.Info("request",
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
