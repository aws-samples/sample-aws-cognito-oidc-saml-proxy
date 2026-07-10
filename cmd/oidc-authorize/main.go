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
	// Session table stores
	auditStore := store.NewAuditStore(sessionDB, cfg.SessionTable)

	// Wrap audit store with CloudWatch Logs audit logger
	cwLogsClient := cloudwatchlogs.NewFromConfig(awsCfg)
	auditLogger, err := audit.NewLogger(cfg.Environment, cwLogsClient, auditStore, "/identity-gateway/audit")
	if err != nil {
		slog.Error("failed to construct audit logger", "error", err)
		os.Exit(1)
	}

	// KMS JOSE signer for OIDC JWT signing. Follows the active certificate's KMS
	// key (primary, or the backup key after a promotion); falls back to the
	// primary key when no active cert is stored yet.
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

	// Cookie encryption key from KMS
	hmacKey := deriveHMACKey(awsCfg, cfg.KMSEncryptionKeyID)

	smClient := secretsmanager.NewFromConfig(awsCfg)

	// Fetch the CloudFront origin-verify secret from SM. The raw token is never
	// stored in the Lambda environment (only the ARN is); the function must
	// abort at boot rather than start with an empty edge gate.
	edgeSecret, edgeSecretErr := crypto.FetchEdgeSecret(context.Background(), smClient, cfg.EdgeAuthSecretARN)
	if edgeSecretErr != nil {
		slog.Error("failed to fetch edge secret", "error", edgeSecretErr)
		os.Exit(1)
	}

	// MF-5: fetch the shared OIDC CryptoKey from Secrets Manager. All OIDC
	// Lambdas must share the same 32-byte key so tokens minted here are
	// decryptable by oidc-discovery and revocation is reliable under concurrency.
	cryptoKey, cryptoKeyErr := crypto.FetchOIDCCryptoKey(context.Background(), smClient, cfg.OIDCCryptoKeySecretARN)
	if cryptoKeyErr != nil {
		slog.Error("failed to fetch OIDC crypto key", "error", cryptoKeyErr)
		os.Exit(1)
	}

	// OIDC storage and provider
	oidcStorage := proxyoidc.NewStorage(appStore, claimStore, sourceStore, joseSigner, sessionDB, signingKeyID)
	proxyoidc.AddBackupVerificationKey(oidcStorage, newSigner, cfg.KMSKeyID, cfg.KMSKeyIDBackup, signingKeyID)

	// Pending-login store backs the custom login page (REPLACE-mode) flow.
	pendingLoginStore := store.NewPendingLoginStore(sessionDB, cfg.SessionTable)

	router = chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(chimiddleware.RealIP)
	router.Use(chimiddleware.Recoverer)
	router.Use(middleware.Logging)
	// Edge gate: reject requests that bypassed CloudFront/WAF. The secret is
	// fetched from SM above; no-op in local dev (empty ARN → empty secret).
	router.Use(middleware.RequireEdgeSecret(edgeSecret))

	if err := proxyoidc.RegisterOIDCRoutes(router, oidcStorage, cfg.BaseURL, appStore, sourceStore, auditLogger, cryptoKey, hmacKey, pendingLoginStore, false); err != nil {
		slog.Error("failed to register OIDC routes", "error", err)
		os.Exit(1)
	}

	slog.Info("oidc-authorize function initialized",
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
