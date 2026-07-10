package config

import (
	"fmt"
	"os"
	"strings"
)

// Environment is the closed set of deployment environments the gateway runs in.
// It is parsed from PROXY_ENVIRONMENT and is the single source of truth for every
// fail-open toggle in the codebase (auth bypass, OIDC insecure issuer, in-memory
// stores, mock KMS). Any value outside this set fails config load rather than
// silently degrading to the most-permissive branch. The infra layer
// (infra/variables.tf) constrains var.environment to dev|staging|prod and emits
// it verbatim as PROXY_ENVIRONMENT; "local" is the developer-workstation-only
// value that never appears in a deployed Lambda. Those four are the complete set.
type Environment string

const (
	EnvLocal   Environment = "local"
	EnvDev     Environment = "dev"
	EnvStaging Environment = "staging"
	EnvProd    Environment = "prod"
)

// IsLocal reports whether the gateway is running in the local developer
// environment — the ONLY environment in which JWT auth may be bypassed, the OIDC
// issuer may be served over plain HTTP, and in-memory stores may back the API.
// Every such toggle MUST gate on this method, never on a raw string comparison,
// so a typo or unexpected value can never select the insecure path.
func (e Environment) IsLocal() bool { return e == EnvLocal }

// parseEnvironment maps the raw PROXY_ENVIRONMENT value onto the closed enum.
// Empty and unrecognized values are both rejected: the gateway fails to
// boot rather than fall through to an insecure default.
func parseEnvironment(raw string) (Environment, error) {
	switch Environment(raw) {
	case EnvLocal, EnvDev, EnvStaging, EnvProd:
		return Environment(raw), nil
	case "":
		return "", fmt.Errorf("PROXY_ENVIRONMENT is required (set to 'local' for development, or one of dev/staging/prod)")
	default:
		return "", fmt.Errorf("PROXY_ENVIRONMENT %q is not a recognized environment (must be one of: local, dev, staging, prod)", raw)
	}
}

type Config struct {
	// Server
	Port        string
	LogLevel    string
	Environment Environment

	// AWS
	AWSRegion string

	// DynamoDB
	DynamoDBTable string
	SessionTable  string

	// KMS
	KMSKeyID           string // RSA signing key (SIGN_VERIFY)
	KMSKeyIDBackup     string // Optional RSA signing key for the backup signing certificate (key rolling)
	KMSEncryptionKeyID string // Symmetric encryption key (ENCRYPT_DECRYPT) for cookie key derivation

	// Multi-tenant mode
	TenantMode string // "pool" (one Cognito pool per tenant) or "group" (groups within one pool)

	// Cognito user pool used to authenticate the management API. These drive the
	// in-process JWKS verifier that cryptographically validates management-API ID
	// tokens. CognitoClientID is the SPA app-client ID the token `aud`
	// must match. Both are empty in local dev (auth is bypassed explicitly there)
	// and required in deployed environments for the router to start.
	CognitoPoolID   string // PROXY_COGNITO_POOL_ID
	CognitoClientID string // PROXY_COGNITO_CLIENT_ID — SPA app-client ID (ID-token audience)

	// SAML
	EntityID string
	BaseURL  string

	// Onboarding wizard — IaC rendering (Plan B2)
	SaaSAccountID       string // PROXY_SAAS_ACCOUNT_ID — gateway's own AWS account number
	SaaSPrincipalName   string // PROXY_SAAS_PRINCIPAL_NAME — IAM role name customers trust
	IaCTemplatesBucket  string // PROXY_IAC_TEMPLATES_BUCKET — private S3 bucket rendered templates are written to
	IaCTemplatesBaseURL string // PROXY_IAC_TEMPLATES_BASE_URL — CloudFront base URL templates are served from; the bucket is private and fronted by CloudFront/OAC

	// OIDCCryptoKeySecretARN is the Secrets Manager ARN (or name) of the 32-byte
	// binary secret used as op.Config.CryptoKey for OIDC bearer encryption.
	// All OIDC Lambdas must share the same value (MF-5). Empty in local dev
	// (a per-process random key is used instead).
	OIDCCryptoKeySecretARN string // PROXY_OIDC_CRYPTO_KEY_SECRET_ARN

	// EdgeAuthSecretARN is the Secrets Manager ARN of the CloudFront
	// origin-verify shared secret. Each request-handling Lambda fetches the raw
	// 48-character token from SM once at cold-start and passes it to
	// middleware.RequireEdgeSecret; the token is never stored in the Lambda
	// environment variables. Empty only in local dev (where the edge middleware
	// is a no-op and no SM fetch is attempted); required in every deployed
	// environment so the router always enforces the edge gate.
	EdgeAuthSecretARN string // PROXY_EDGE_AUTH_SECRET_ARN
}

func Load() (*Config, error) {
	// Parse and validate the environment first: it is the single gate that every
	// fail-open toggle keys off, so an empty or unrecognized value must abort the
	// boot before any other field is interpreted.
	environment, err := parseEnvironment(env("PROXY_ENVIRONMENT"))
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Port:                   envOr("PROXY_PORT", "8080"),
		LogLevel:               envOr("PROXY_LOG_LEVEL", "info"),
		Environment:            environment,
		AWSRegion:              envOr("PROXY_AWS_REGION", os.Getenv("AWS_REGION")),
		DynamoDBTable:          env("PROXY_DYNAMODB_TABLE"),
		SessionTable:           env("PROXY_SESSION_TABLE"),
		KMSKeyID:               env("PROXY_KMS_KEY_ID"),
		KMSKeyIDBackup:         env("PROXY_KMS_KEY_ID_BACKUP"),
		KMSEncryptionKeyID:     env("PROXY_KMS_ENCRYPTION_KEY_ID"),
		TenantMode:             envOr("PROXY_TENANT_MODE", "pool"),
		CognitoPoolID:          env("PROXY_COGNITO_POOL_ID"),
		CognitoClientID:        env("PROXY_COGNITO_CLIENT_ID"),
		EntityID:               env("PROXY_ENTITY_ID"),
		BaseURL:                env("PROXY_BASE_URL"),
		SaaSAccountID:          env("PROXY_SAAS_ACCOUNT_ID"),
		SaaSPrincipalName:      envOr("PROXY_SAAS_PRINCIPAL_NAME", "identity-gateway-management-api"),
		IaCTemplatesBucket:     env("PROXY_IAC_TEMPLATES_BUCKET"),
		IaCTemplatesBaseURL:    env("PROXY_IAC_TEMPLATES_BASE_URL"),
		OIDCCryptoKeySecretARN: env("PROXY_OIDC_CRYPTO_KEY_SECRET_ARN"),
		EdgeAuthSecretARN:      env("PROXY_EDGE_AUTH_SECRET_ARN"),
	}

	// Apply local development defaults BEFORE validation
	if cfg.Environment.IsLocal() {
		if cfg.BaseURL == "" {
			cfg.BaseURL = "http://localhost:" + cfg.Port
		}
		if cfg.EntityID == "" {
			cfg.EntityID = cfg.BaseURL
		}
		if cfg.KMSKeyID == "" {
			cfg.KMSKeyID = "local-dev-key"
		}
		if cfg.DynamoDBTable == "" {
			cfg.DynamoDBTable = "federation-gateway-local"
		}
		if cfg.AWSRegion == "" {
			cfg.AWSRegion = "eu-north-1"
		}
	}

	// Validate only universally required fields.
	// BaseURL, EntityID, KMSKeyID, etc. are optional at config level —
	// per-capability Lambda functions may not need all of them.
	var missing []string

	// Production-only requirements — only validate what's universally needed.
	// Per-capability Lambda functions may not have all env vars set.
	// Function-specific vars (SESSION_TABLE, KMS_KEY_ID, etc.) are validated
	// at the point of use, not at config load.
	if !cfg.Environment.IsLocal() {
		if cfg.AWSRegion == "" {
			missing = append(missing, "PROXY_AWS_REGION")
		}
		// The management-API JWKS verifier is defense-in-depth and its
		// audience check is only meaningful with a client ID to compare against.
		// Both the pool ID and the SPA app-client ID are therefore
		// mandatory in every deployed environment: an empty pool ID leaves the
		// verifier un-built, and an empty client ID makes the verifier skip the
		// aud check — silently accepting an ID token minted for a *different* app
		// client in the same pool. Fail closed at boot rather than degrade to that
		// fail-open path. Auth is bypassed explicitly (and only) in local dev, so
		// these remain optional there.
		if cfg.CognitoPoolID == "" {
			missing = append(missing, "PROXY_COGNITO_POOL_ID")
		}
		if cfg.CognitoClientID == "" {
			missing = append(missing, "PROXY_COGNITO_CLIENT_ID")
		}
		// The CloudFront origin-verify secret ARN is the reference the Lambda uses
		// to fetch the raw token from Secrets Manager at cold-start. Without it the
		// function cannot obtain the secret and middleware.RequireEdgeSecret would
		// have nothing to enforce, reopening the raw execute-api bypass. Mandatory
		// in every deployed environment — fail closed at boot rather than serve
		// unguarded. Bypassed (and only) in local dev, where there is no CloudFront
		// edge and no SM fetch is attempted.
		if cfg.EdgeAuthSecretARN == "" {
			missing = append(missing, "PROXY_EDGE_AUTH_SECRET_ARN")
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

// env retrieves an environment variable value. Returns empty string if not set.
// Note: This does not enforce that the variable is required - validation happens in Load().
func env(key string) string {
	return os.Getenv(key)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
