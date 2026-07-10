package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
)

// isConfidentialAuthMethod reports whether a token endpoint authentication
// method requires a client secret. Public clients ("none") authenticate with
// PKCE only and have no secret.
func isConfidentialAuthMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "client_secret_basic", "client_secret_post":
		return true
	default:
		return false
	}
}

// generateClientSecret returns a new high-entropy client secret: 32 random
// bytes, hex-encoded (64 hex chars).
func generateClientSecret() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}

// registerRotateSecretRoute registers the rotate-client-secret endpoint.
func registerRotateSecretRoute(api huma.API, apps domain.AppRepository) {
	huma.Register(api, huma.Operation{
		OperationID: "rotate-client-secret",
		Method:      http.MethodPost,
		Path:        "/api/v1/applications/{id}/rotate-secret",
		Summary:     "Rotate OIDC client secret",
		Description: "Generates a new client secret for OIDC applications (shown once)",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *RotateSecretInput) (*RotateSecretOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		// Load the application
		app, err := apps.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		// Verify protocol is OIDC
		if !strings.EqualFold(app.Protocol, "oidc") {
			return nil, huma.Error400BadRequest("secret rotation is only supported for OIDC applications")
		}

		// Load OIDC config
		oidcCfg, err := apps.GetOIDCConfig(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("OIDC configuration not found")
			}
			return nil, huma.Error500InternalServerError("failed to get OIDC config", err)
		}

		// Verify tokenEndpointAuthMethod requires a secret (public clients don't use secrets)
		if !isConfidentialAuthMethod(oidcCfg.TokenEndpointAuthMethod) {
			return nil, huma.Error400BadRequest("public clients do not use secrets")
		}

		// Generate new secret: 32 random bytes, hex-encoded (64 hex chars)
		newSecret, err := generateClientSecret()
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to generate random secret", err)
		}

		// Update OIDC config with new secret
		oidcCfg.ClientSecret = newSecret
		if err := apps.UpdateOIDCConfig(ctx, slug, input.ID, oidcCfg); err != nil {
			return nil, huma.Error500InternalServerError("failed to store new secret", err)
		}

		// Return the secret (this is the only time it's exposed)
		out := &RotateSecretOutput{}
		out.Body.ClientSecret = newSecret
		return out, nil
	})
}
