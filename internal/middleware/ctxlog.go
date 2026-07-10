package middleware

import (
	"context"
	"log/slog"
)

type ctxLoggerKey struct{}

// ContextWithLogger stores a logger in the context.
func ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxLoggerKey{}, logger)
}

// LoggerFromContext retrieves the logger from context, falling back to slog.Default().
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(ctxLoggerKey{}).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}
