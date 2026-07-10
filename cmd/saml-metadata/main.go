package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	chiadapter "github.com/awslabs/aws-lambda-go-api-proxy/chi"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/guregu/dynamo/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/saml"
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

	// Config table stores (read-only)
	tenantStore := store.NewTenantStore(configDB, cfg.DynamoDBTable)
	appStore := store.NewAppStore(configDB, cfg.DynamoDBTable)
	claimStore := store.NewClaimStore(configDB, cfg.DynamoDBTable)

	// KMS signer — needed for the signing cert (metadata includes the public key).
	// Follows the active certificate's KMS key (primary or backup after promotion).
	newSigner := func(keyID string) *crypto.KMSSigner {
		return crypto.NewKMSSigner(crypto.NewAWSKMSClient(awsCfg, keyID))
	}

	// Read active signing certificate from CertStore (never generate here)
	certStore := crypto.NewCertStore(configDB)
	signer, cert, _, err := crypto.SelectActiveSigner(context.Background(), certStore, cfg.KMSKeyID, newSigner)
	if err != nil {
		slog.Error("no active signing certificate available", "error", err)
		os.Exit(1)
	}

	// Metadata handler needs SPProvider + signer + cert
	spProvider := saml.NewSPProvider(appStore)
	tenantIdPHandler := saml.NewTenantIdPHandler(
		saml.WithSigner(signer),
		saml.WithCertificate(cert),
		saml.WithCertStore(certStore),
		saml.WithBaseURL(cfg.BaseURL),
		saml.WithTenantReader(tenantStore),
		saml.WithSPProvider(spProvider),
		saml.WithAppReader(appStore),
		saml.WithClaimRepository(claimStore),
	)

	// Fetch the CloudFront origin-verify secret from SM. The raw token is never
	// stored in the Lambda environment (only the ARN is); the function must
	// abort at boot rather than start with an empty edge gate.
	smClient := secretsmanager.NewFromConfig(awsCfg)
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
	// Edge gate: reject requests that bypassed CloudFront/WAF. SPs fetch
	// metadata via the public CloudFront URL, so they carry the header; direct
	// execute-api hits do not. The secret is fetched from SM above; no-op in
	// local dev (empty ARN → empty secret).
	router.Use(middleware.RequireEdgeSecret(edgeSecret))

	router.Route("/t/{tenant}/saml", func(r chi.Router) {
		r.Get("/metadata", tenantIdPHandler.ServeMetadata)
		r.Get("/metadata/{appId}", tenantIdPHandler.ServeAppMetadata)
	})

	slog.Info("saml-metadata function initialized", "configTable", cfg.DynamoDBTable)
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
