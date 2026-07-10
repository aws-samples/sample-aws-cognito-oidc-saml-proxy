package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	chiadapter "github.com/awslabs/aws-lambda-go-api-proxy/chi"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/guregu/dynamo/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/audit"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	proxyoidc "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/oidc"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

var router chi.Router

func init() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	setupLogging(cfg.LogLevel)

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		slog.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	dynamoDB := dynamo.New(awsCfg)
	configDB := store.NewDB(dynamoDB, cfg.DynamoDBTable)
	sessionDB := store.NewDB(dynamoDB, cfg.SessionTable)

	// Config table stores
	appStore := store.NewAppStore(configDB, cfg.DynamoDBTable)
	claimStore := store.NewClaimStore(configDB, cfg.DynamoDBTable)
	sourceStore := store.NewSourceStore(configDB, cfg.DynamoDBTable)
	// Session table: needed by Storage for OIDC state lookups
	auditStore := store.NewAuditStore(sessionDB, cfg.SessionTable)

	// Wrap audit store with CloudWatch Logs audit logger
	cwLogsClient := cloudwatchlogs.NewFromConfig(awsCfg)
	auditLogger, err := audit.NewLogger(cfg.Environment, cwLogsClient, auditStore, "/identity-gateway/audit")
	if err != nil {
		slog.Error("failed to construct audit logger", "error", err)
		os.Exit(1)
	}

	// KMS — JWKS advertises the active signing key's public key. The signer
	// follows the active certificate's KMS key (primary, or the backup key after
	// a promotion); falls back to the primary key when no active cert is stored.
	newSigner := func(keyID string) *crypto.KMSSigner {
		return crypto.NewKMSSigner(crypto.NewAWSKMSClient(awsCfg, keyID))
	}
	certStore := crypto.NewCertStore(configDB)
	signingKeyID := cfg.KMSKeyID
	var signer *crypto.KMSSigner
	if s, _, kid, selErr := crypto.SelectActiveSigner(context.Background(), certStore, cfg.KMSKeyID, newSigner); selErr == nil {
		signer, signingKeyID = s, kid
	} else {
		signer = newSigner(cfg.KMSKeyID)
	}
	joseSigner, err := crypto.NewKMSJoseSigner(signingKeyID, signer.Client())
	if err != nil {
		slog.Error("failed to create KMS jose signer", "error", err)
		os.Exit(1)
	}

	// OIDC storage — full Provider but only discovery/keys/userinfo/end_session
	// routes will be hit thanks to API Gateway routing.
	oidcStorage := proxyoidc.NewStorage(appStore, claimStore, sourceStore, joseSigner, sessionDB, signingKeyID)
	// Publish both the primary and backup public keys in JWKS so tokens signed
	// before/after a key roll remain verifiable during the grace window.
	proxyoidc.AddBackupVerificationKey(oidcStorage, newSigner, cfg.KMSKeyID, cfg.KMSKeyIDBackup, signingKeyID)

	smClient := secretsmanager.NewFromConfig(awsCfg)

	// Fetch the CloudFront origin-verify secret from SM. The raw token is never
	// stored in the Lambda environment (only the ARN is); the function must
	// abort at boot rather than start with an empty edge gate.
	edgeSecret, edgeSecretErr := crypto.FetchEdgeSecret(context.Background(), smClient, cfg.EdgeAuthSecretARN)
	if edgeSecretErr != nil {
		slog.Error("failed to fetch edge secret", "error", edgeSecretErr)
		os.Exit(1)
	}

	router = chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(chimiddleware.RealIP)
	router.Use(chimiddleware.Recoverer)
	router.Use(middleware.Logging)
	// Edge gate: reject requests that bypassed CloudFront/WAF. RPs fetch
	// discovery/JWKS via the public CloudFront URL, so they carry the header;
	// direct execute-api hits do not. The secret is fetched from SM above;
	// no-op in local dev (empty ARN → empty secret).
	router.Use(middleware.RequireEdgeSecret(edgeSecret))

	// MF-5: fetch the shared OIDC CryptoKey from Secrets Manager. /userinfo
	// decrypts the bearer that oidc-token minted; both must share the same key.
	cryptoKey, err := crypto.FetchOIDCCryptoKey(context.Background(), smClient, cfg.OIDCCryptoKeySecretARN)
	if err != nil {
		slog.Error("failed to fetch OIDC crypto key", "error", err)
		os.Exit(1)
	}

	// MF-9: pass nil hmacKey and skipLoginCallbackRoutes=true. This Lambda
	// serves only OIDC discovery and JWKS — it must not expose login/callback
	// routes. Passing nil instead of an all-zero placeholder means any
	// mis-routed login request gets ErrCookieSigningDisabled (fail closed).
	if err := proxyoidc.RegisterOIDCRoutes(router, oidcStorage, cfg.BaseURL, appStore, sourceStore, auditLogger, cryptoKey, nil, nil, true); err != nil {
		slog.Error("failed to register OIDC routes", "error", err)
		os.Exit(1)
	}

	slog.Info("oidc-discovery function initialized", "configTable", cfg.DynamoDBTable)
}

func main() {
	chiAdapter := chiadapter.NewV2(router.(*chi.Mux))
	lambda.Start(chiAdapter.ProxyWithContextV2)
}

func setupLogging(logLevel string) {
	level := slog.LevelInfo
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}
