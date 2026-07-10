package tenant

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTenantFromPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		want      string
		wantError bool
	}{
		{
			name: "valid path with saml route",
			path: "/t/acme/saml/sso",
			want: "acme",
		},
		{
			name: "valid path with hyphens",
			path: "/t/acme-corp/saml/metadata",
			want: "acme-corp",
		},
		{
			name: "valid path with underscores",
			path: "/t/acme_corp/api/auth",
			want: "acme_corp",
		},
		{
			name: "valid path tenant only",
			path: "/t/test",
			want: "test",
		},
		{
			name:      "no tenant prefix",
			path:      "/saml/sso",
			wantError: true,
		},
		{
			name:      "empty tenant slug",
			path:      "/t//saml/sso",
			wantError: true,
		},
		{
			name:      "missing tenant slug",
			path:      "/t/",
			wantError: true,
		},
		{
			name:      "root path",
			path:      "/",
			wantError: true,
		},
		{
			name:      "empty path",
			path:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractFromPath(tt.path)
			if tt.wantError {
				assert.Error(t, err)
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestExtractTenantFromClaims(t *testing.T) {
	tests := []struct {
		name      string
		claims    map[string]interface{}
		want      string
		wantError bool
	}{
		{
			name: "valid tenant claim",
			claims: map[string]interface{}{
				"custom:tenant_id": "acme",
				"sub":              "user123",
			},
			want: "acme",
		},
		{
			name: "tenant claim with hyphens",
			claims: map[string]interface{}{
				"custom:tenant_id": "acme-corp",
				"email":            "user@example.com",
			},
			want: "acme-corp",
		},
		{
			name: "missing tenant claim",
			claims: map[string]interface{}{
				"sub":   "user123",
				"email": "user@example.com",
			},
			wantError: true,
		},
		{
			name: "empty tenant claim",
			claims: map[string]interface{}{
				"custom:tenant_id": "",
				"sub":              "user123",
			},
			wantError: true,
		},
		{
			name: "wrong type tenant claim",
			claims: map[string]interface{}{
				"custom:tenant_id": 12345,
				"sub":              "user123",
			},
			wantError: true,
		},
		{
			name:      "nil claims",
			claims:    nil,
			wantError: true,
		},
		{
			name:      "empty claims",
			claims:    map[string]interface{}{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractFromClaims(tt.claims)
			if tt.wantError {
				assert.Error(t, err)
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTenantContext(t *testing.T) {
	t.Run("store and retrieve tenant from context", func(t *testing.T) {
		tenant := &Tenant{
			Slug:        "acme",
			DisplayName: "Acme Corp",
			Plan:        "enterprise",
			Status:      "active",
		}

		ctx := context.Background()
		ctx = WithContext(ctx, tenant)

		retrieved, ok := FromContext(ctx)
		require.True(t, ok, "tenant should be in context")
		require.NotNil(t, retrieved)
		assert.Equal(t, "acme", retrieved.Slug)
		assert.Equal(t, "Acme Corp", retrieved.DisplayName)
		assert.Equal(t, "enterprise", retrieved.Plan)
		assert.Equal(t, "active", retrieved.Status)
	})

	t.Run("missing tenant returns false", func(t *testing.T) {
		ctx := context.Background()
		retrieved, ok := FromContext(ctx)
		assert.False(t, ok, "tenant should not be in context")
		assert.Nil(t, retrieved)
	})

	t.Run("context isolation", func(t *testing.T) {
		tenant1 := &Tenant{Slug: "tenant1"}
		tenant2 := &Tenant{Slug: "tenant2"}

		ctx1 := WithContext(context.Background(), tenant1)
		ctx2 := WithContext(context.Background(), tenant2)

		retrieved1, ok1 := FromContext(ctx1)
		retrieved2, ok2 := FromContext(ctx2)

		require.True(t, ok1)
		require.True(t, ok2)
		assert.Equal(t, "tenant1", retrieved1.Slug)
		assert.Equal(t, "tenant2", retrieved2.Slug)
	})
}
