package tenant

import (
	"context"
	"fmt"
	"strings"
)

type contextKey string

const tenantContextKey contextKey = "tenant"

// ExtractFromPath extracts the tenant slug from a URL path with format /t/{slug}/...
func ExtractFromPath(path string) (string, error) {
	if !strings.HasPrefix(path, "/t/") {
		return "", fmt.Errorf("path does not contain tenant prefix: %s", path)
	}
	parts := strings.SplitN(strings.TrimPrefix(path, "/t/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("empty tenant slug in path: %s", path)
	}
	return parts[0], nil
}

// ExtractFromClaims extracts the tenant slug from JWT claims using the custom:tenant_id claim.
func ExtractFromClaims(claims map[string]interface{}) (string, error) {
	if v, ok := claims["custom:tenant_id"].(string); ok && v != "" {
		return v, nil
	}
	return "", fmt.Errorf("missing custom:tenant_id in JWT claims")
}

// WithContext stores a tenant in the context.
func WithContext(ctx context.Context, t *Tenant) context.Context {
	return context.WithValue(ctx, tenantContextKey, t)
}

// FromContext retrieves a tenant from the context.
func FromContext(ctx context.Context) (*Tenant, bool) {
	t, ok := ctx.Value(tenantContextKey).(*Tenant)
	return t, ok
}
