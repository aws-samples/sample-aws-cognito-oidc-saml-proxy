package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	chiadapter "github.com/awslabs/aws-lambda-go-api-proxy/chi"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/guregu/dynamo/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/audit"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/saml"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
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
	tenantStore := store.NewTenantStore(configDB, cfg.DynamoDBTable)
	sourceStore := store.NewSourceStore(configDB, cfg.DynamoDBTable)
	appStore := store.NewAppStore(configDB, cfg.DynamoDBTable)
	claimStore := store.NewClaimStore(configDB, cfg.DynamoDBTable)

	// Seed the built-in default tenant so SAML flows resolve even before the
	// management API has been used. Idempotent.
	if err := tenantStore.EnsureTenant(context.Background(), tenant.NewDefaultTenant()); err != nil {
		slog.Warn("failed to ensure default tenant exists", "error", err)
	}
	// Session table stores
	replayStore := store.NewReplayStore(sessionDB, cfg.SessionTable)
	sessionStore := store.NewSessionStore(sessionDB, cfg.SessionTable)
	auditStore := store.NewAuditStore(sessionDB, cfg.SessionTable)

	// Wrap audit store with CloudWatch Logs audit logger
	cwLogsClient := cloudwatchlogs.NewFromConfig(awsCfg)
	auditLogger, err := audit.NewLogger(cfg.Environment, cwLogsClient, auditStore, "/identity-gateway/audit")
	if err != nil {
		slog.Error("failed to construct audit logger", "error", err)
		os.Exit(1)
	}

	// KMS signer for SAML assertion signing. The signer follows the active
	// certificate's KMS key (primary, or the backup key after a promotion).
	newSigner := func(keyID string) *crypto.KMSSigner {
		return crypto.NewKMSSigner(crypto.NewAWSKMSClient(awsCfg, keyID))
	}
	primarySigner := newSigner(cfg.KMSKeyID)

	// Load the active signing certificate and a signer matching its KMS key.
	// If no active cert exists yet, bootstrap a self-signed one with the primary key.
	certStore := crypto.NewCertStore(configDB)
	signer, cert, _, err := crypto.SelectActiveSigner(context.Background(), certStore, cfg.KMSKeyID, newSigner)
	if err != nil {
		// No active cert — generate initial one with the primary key.
		cert, err = crypto.GenerateSelfSignedCert(primarySigner, cfg.EntityID)
		if err != nil {
			slog.Error("failed to generate certificate", "error", err)
			os.Exit(1)
		}
		if storeErr := certStore.StoreActiveCert(context.Background(), cert); storeErr != nil {
			slog.Warn("failed to persist cert", "error", storeErr)
		}
		signer = primarySigner
	}

	// Fetch the CloudFront origin-verify secret from SM. The raw token is never
	// stored in the Lambda environment (only the ARN is); the function must
	// abort at boot rather than start with an empty edge gate.
	smClient := secretsmanager.NewFromConfig(awsCfg)
	edgeSecret, edgeSecretErr := crypto.FetchEdgeSecret(context.Background(), smClient, cfg.EdgeAuthSecretARN)
	if edgeSecretErr != nil {
		slog.Error("failed to fetch edge secret", "error", edgeSecretErr)
		os.Exit(1)
	}

	// Derive cookie encryption key from KMS
	hmacKey := deriveHMACKey(awsCfg, cfg.KMSEncryptionKeyID)

	// SAML components
	spProvider := saml.NewSPProvider(appStore)
	sessionProvider := saml.NewSessionProvider(
		saml.WithSourceStore(sourceStore),
		saml.WithAppStore(appStore),
		saml.WithHMACKey(hmacKey),
		saml.WithProviderBaseURL(cfg.BaseURL),
	)
	sessionProvider.SetAuditStore(auditLogger)
	sessionProvider.SetReplayStore(replayStore)
	// Consult server-side revocation markers on cookie reuse so a logout at the
	// SLO Lambda invalidates a replayed session cookie here too.
	sessionProvider.SetSessionStore(sessionStore)
	sessionProvider.SetPendingLoginStore(store.NewPendingLoginStore(sessionDB, cfg.SessionTable))
	assertionMaker := saml.NewAssertionMaker(appStore, claimStore)

	tenantIdPHandler := saml.NewTenantIdPHandler(
		saml.WithSigner(signer),
		saml.WithCertificate(cert),
		saml.WithCertStore(certStore),
		saml.WithSPProvider(spProvider),
		saml.WithSessionProvider(sessionProvider),
		saml.WithAssertionMaker(assertionMaker),
		saml.WithBaseURL(cfg.BaseURL),
	)

	router = chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(chimiddleware.RealIP)
	router.Use(chimiddleware.Recoverer)
	router.Use(middleware.Logging)
	// Edge gate: only requests that transited CloudFront (and its WAF)
	// carry the origin-verify secret; direct execute-api hits are rejected. The
	// secret is fetched from SM above; no-op in local dev (empty ARN → empty secret).
	router.Use(middleware.RequireEdgeSecret(edgeSecret))

	saml.RegisterTenantRoutes(router, saml.TenantRoutesConfig{
		Handler:     tenantIdPHandler,
		SessionProv: sessionProvider,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       auditLogger,
		Replay:      replayStore,
	})

	slog.Info("saml-sso function initialized",
		"configTable", cfg.DynamoDBTable,
		"sessionTable", cfg.SessionTable)
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

func deriveHMACKey(awsCfg aws.Config, encKeyID string) []byte {
	kmsClient := kms.NewFromConfig(awsCfg)
	dataKeyOut, err := kmsClient.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
		KeyId:   &encKeyID,
		KeySpec: kmstypes.DataKeySpecAes256,
	})
	if err != nil {
		slog.Error("failed to generate data key from KMS", "error", err)
		os.Exit(1)
	}
	return dataKeyOut.Plaintext
}
