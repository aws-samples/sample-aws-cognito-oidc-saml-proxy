package config_test

import (
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Defaults(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, "info", cfg.LogLevel)
}

func TestLoadConfig_MissingEnvironment(t *testing.T) {
	// No env vars set at all -- PROXY_ENVIRONMENT is required
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PROXY_ENVIRONMENT is required")
}

func TestLoadConfig_MissingRequired_Production(t *testing.T) {
	// Only set PROXY_ENVIRONMENT — PROXY_AWS_REGION is required in a deployed
	// (non-local) environment. Clear AWS_REGION since config falls back to it.
	t.Setenv("PROXY_ENVIRONMENT", "prod")
	t.Setenv("AWS_REGION", "")
	t.Setenv("PROXY_AWS_REGION", "")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PROXY_AWS_REGION")
}

// TestLoadConfig_MissingCognitoClientID_Production asserts that a deployed
// (non-local) environment WITHOUT PROXY_COGNITO_CLIENT_ID fails config load. An
// empty client ID would make the JWKS verifier skip the aud check and accept an
// ID token minted for a different app client in the same pool, so the gateway
// must fail closed at boot rather than start with the control silently disabled.
func TestLoadConfig_MissingCognitoClientID_Production(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PROXY_COGNITO_CLIENT_ID", "")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PROXY_COGNITO_CLIENT_ID")
}

// TestLoadConfig_MissingCognitoPoolID_Production asserts that a deployed
// environment WITHOUT PROXY_COGNITO_POOL_ID fails config load. Without a pool ID
// the management-API verifier is never built, dropping the in-process JWT
// verification defense-in-depth, so this must also fail closed.
func TestLoadConfig_MissingCognitoPoolID_Production(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PROXY_COGNITO_POOL_ID", "")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PROXY_COGNITO_POOL_ID")
}

// TestLoadConfig_MissingEdgeSecretARN_Production asserts that a deployed
// (non-local) environment WITHOUT PROXY_EDGE_AUTH_SECRET_ARN fails config load.
// Without the ARN the function cannot fetch the raw token from Secrets Manager
// and the edge gate would be absent, reopening the raw execute-api bypass.
func TestLoadConfig_MissingEdgeSecretARN_Production(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PROXY_EDGE_AUTH_SECRET_ARN", "")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PROXY_EDGE_AUTH_SECRET_ARN")
}

// TestLoadConfig_EdgeSecretARNLoaded asserts a deployed config with the ARN set
// loads it onto Config for the cold-start SM fetch.
func TestLoadConfig_EdgeSecretARNLoaded(t *testing.T) {
	setRequiredEnv(t)
	arn := "arn:aws:secretsmanager:eu-north-1:127218179144:secret:dev-edge-secret-AbCdEf"
	t.Setenv("PROXY_EDGE_AUTH_SECRET_ARN", arn)
	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, arn, cfg.EdgeAuthSecretARN)
}

// TestLoadConfig_LocalWithoutEdgeSecretARN asserts the origin-verify secret ARN
// remains optional in local dev (no CloudFront edge, no SM fetch): a local
// config without it must still load, and FetchEdgeSecret returns an empty string
// that makes the middleware a no-op passthrough.
func TestLoadConfig_LocalWithoutEdgeSecretARN(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "local")
	t.Setenv("AWS_REGION", "")
	t.Setenv("PROXY_AWS_REGION", "")
	t.Setenv("PROXY_EDGE_AUTH_SECRET_ARN", "")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.True(t, cfg.Environment.IsLocal())
	assert.Empty(t, cfg.EdgeAuthSecretARN)
}

// TestLoadConfig_LocalWithoutCognitoIDs asserts the Cognito pool/client IDs
// remain optional in local dev (auth is bypassed explicitly there): a local
// config with neither set must still load successfully.
func TestLoadConfig_LocalWithoutCognitoIDs(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "local")
	t.Setenv("AWS_REGION", "")
	t.Setenv("PROXY_AWS_REGION", "")
	t.Setenv("PROXY_COGNITO_POOL_ID", "")
	t.Setenv("PROXY_COGNITO_CLIENT_ID", "")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.True(t, cfg.Environment.IsLocal())
	assert.Empty(t, cfg.CognitoPoolID)
	assert.Empty(t, cfg.CognitoClientID)
}

// TestLoadConfig_UnknownEnvironment asserts that an unrecognized
// PROXY_ENVIRONMENT value fails config load rather than falling through to the
// most-permissive branch. "production" is a deliberately-plausible typo for the
// real value "prod".
func TestLoadConfig_UnknownEnvironment(t *testing.T) {
	t.Setenv("PROXY_ENVIRONMENT", "production")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a recognized environment")
}

func TestLoadConfig_AllFields(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PROXY_LOG_LEVEL", "debug")
	t.Setenv("PROXY_PORT", "9090")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "9090", cfg.Port)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "eu-north-1", cfg.AWSRegion)
}

func TestLoadConfig_LocalDefaults(t *testing.T) {
	// Only set PROXY_ENVIRONMENT=local -- all other required fields
	// should receive sensible defaults.
	t.Setenv("PROXY_ENVIRONMENT", "local")
	// Clear AWS_REGION so it doesn't leak into the test via envOr fallback.
	t.Setenv("AWS_REGION", "")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, config.EnvLocal, cfg.Environment)
	assert.True(t, cfg.Environment.IsLocal())
	assert.Equal(t, "http://localhost:8080", cfg.BaseURL)
	assert.Equal(t, "http://localhost:8080", cfg.EntityID)
	assert.Equal(t, "local-dev-key", cfg.KMSKeyID)
	assert.Equal(t, "federation-gateway-local", cfg.DynamoDBTable)
	assert.Equal(t, "eu-north-1", cfg.AWSRegion)
}

func TestLoadConfig_LocalOverrides(t *testing.T) {
	// Local mode should still respect explicit env vars over defaults.
	t.Setenv("PROXY_ENVIRONMENT", "local")
	t.Setenv("PROXY_BASE_URL", "http://myhost:9090")
	t.Setenv("PROXY_ENTITY_ID", "urn:my:entity")
	t.Setenv("PROXY_KMS_KEY_ID", "alias/my-key")
	t.Setenv("PROXY_DYNAMODB_TABLE", "my-table")
	t.Setenv("PROXY_AWS_REGION", "us-east-1")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "http://myhost:9090", cfg.BaseURL)
	assert.Equal(t, "urn:my:entity", cfg.EntityID)
	assert.Equal(t, "alias/my-key", cfg.KMSKeyID)
	assert.Equal(t, "my-table", cfg.DynamoDBTable)
	assert.Equal(t, "us-east-1", cfg.AWSRegion)
}

func TestLoadConfig_LocalCustomPort(t *testing.T) {
	// When a custom port is set in local mode, BaseURL and EntityID
	// defaults should incorporate it.
	t.Setenv("PROXY_ENVIRONMENT", "local")
	t.Setenv("PROXY_PORT", "9999")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:9999", cfg.BaseURL)
	assert.Equal(t, "http://localhost:9999", cfg.EntityID)
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PROXY_AWS_REGION", "eu-north-1")
	t.Setenv("PROXY_DYNAMODB_TABLE", "saml-proxy-table")
	t.Setenv("PROXY_SESSION_TABLE", "saml-proxy-session-table")
	t.Setenv("PROXY_KMS_KEY_ID", "alias/test-key")
	t.Setenv("PROXY_ENTITY_ID", "https://saml.example.com")
	t.Setenv("PROXY_BASE_URL", "https://api.example.com")
	// Deployed environments require the Cognito pool/client IDs so the
	// management-API JWKS verifier is built and its aud check is enforced.
	t.Setenv("PROXY_COGNITO_POOL_ID", "eu-north-1_TestPool")
	t.Setenv("PROXY_COGNITO_CLIENT_ID", "test-client-id")
	// Deployed environments require the CloudFront origin-verify secret ARN so
	// the cold-start SM fetch succeeds and the edge gate enforces.
	t.Setenv("PROXY_EDGE_AUTH_SECRET_ARN", "arn:aws:secretsmanager:eu-north-1:127218179144:secret:test-edge-secret-AbCdEf")
	t.Setenv("PROXY_ENVIRONMENT", "prod")
}
