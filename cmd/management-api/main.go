package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	awsstsclient "github.com/aws/aws-sdk-go-v2/service/sts"
	chiadapter "github.com/awslabs/aws-lambda-go-api-proxy/chi"
	"github.com/go-chi/chi/v5"
	"github.com/guregu/dynamo/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/api"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/audit"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/aws/iam"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/aws/sts"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/iac/publisher"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/iac/templates"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service/onboarding"
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

	// Config table stores (read/write)
	tenantStore := store.NewTenantStore(configDB, cfg.DynamoDBTable)
	sourceStore := store.NewSourceStore(configDB, cfg.DynamoDBTable)
	appStore := store.NewAppStore(configDB, cfg.DynamoDBTable)
	claimStore := store.NewClaimStore(configDB, cfg.DynamoDBTable)

	// Seed the built-in default tenant so management and protocol flows always
	// resolve to a valid tenant. Idempotent: an existing tenant is left as-is.
	if err := tenantStore.EnsureTenant(context.Background(), tenant.NewDefaultTenant()); err != nil {
		slog.Warn("failed to ensure default tenant exists", "error", err)
	}
	// Session table: audit store for read access
	auditStore := store.NewAuditStore(sessionDB, cfg.SessionTable)

	// Wrap audit store with CloudWatch Logs audit logger
	cwLogsClient := cloudwatchlogs.NewFromConfig(awsCfg)
	auditLogger, err := audit.NewLogger(cfg.Environment, cwLogsClient, auditStore, "/identity-gateway/audit")
	if err != nil {
		slog.Error("failed to construct audit logger", "error", err)
		os.Exit(1)
	}

	// Read active signing certificate from CertStore (never generate here)
	certStore := crypto.NewCertStore(configDB)
	cert, err := certStore.GetActiveCert(context.Background())
	if err != nil {
		slog.Error("no active signing certificate available", "error", err)
		os.Exit(1)
	}
	certPEM := crypto.CertToPEM(cert)

	// KMS signers for certificate lifecycle (CSR generation / import validation).
	// The private keys never leave KMS; signers only expose Sign + Public.
	primarySigner := crypto.NewKMSSigner(crypto.NewAWSKMSClient(awsCfg, cfg.KMSKeyID))
	var backupSigner *crypto.KMSSigner
	if cfg.KMSKeyIDBackup != "" {
		backupSigner = crypto.NewKMSSigner(crypto.NewAWSKMSClient(awsCfg, cfg.KMSKeyIDBackup))
	}

	// Services
	importSvc := service.NewMetadataImportService(appStore, &service.HTTPMetadataFetcher{})
	previewSvc := service.NewPreviewService(appStore, claimStore)
	certSvc := service.NewCertificateService(certPEM)
	certMgr := service.NewCertManager(service.CertManagerConfig{
		Store:         certStore,
		PrimarySigner: primarySigner,
		BackupSigner:  backupSigner,
		PrimaryKeyID:  cfg.KMSKeyID,
		BackupKeyID:   cfg.KMSKeyIDBackup,
		EntityID:      cfg.EntityID,
	})
	settingsSvc := service.NewSettingsService(tenantStore, cfg.EntityID, cfg.BaseURL, cfg.KMSKeyID, cfg.KMSKeyIDBackup)

	// Onboarding (SaaS wizard)
	// IaC rendering is always on; publisher is only wired when a bucket is configured.
	// Without a bucket, GenerateIaC returns rendered Bytes but no DownloadURL/QuickCreateURL,
	// degrading gracefully to returning rendered bytes only.
	iacRenderer := rendererAdapter{}
	var iacPublisher onboarding.Publisher
	if cfg.IaCTemplatesBucket != "" {
		s3Client := awss3.NewFromConfig(awsCfg)
		// The templates bucket is private: Block Public Access is on and no
		// public-read policy is attached, so the S3 virtual-hosted URL returns 403
		// to customers. Rendered templates are served through CloudFront/OAC, so
		// the download URLs handed to customers MUST use the CloudFront base URL.
		// PROXY_IAC_TEMPLATES_BASE_URL carries it (infra wires it to the gateway's
		// own CloudFront domain). Fall back to the S3 virtual-hosted host only when
		// it is unset — the local-dev/legacy public-bucket path.
		publicBaseURL := cfg.IaCTemplatesBaseURL
		if publicBaseURL == "" {
			publicBaseURL = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", cfg.IaCTemplatesBucket, cfg.AWSRegion)
		}
		iacPublisher = publisher.NewS3(
			s3Client,
			cfg.IaCTemplatesBucket,
			publicBaseURL,
		)
	}

	onboardingStateStore := store.NewOnboardingStateStore(sessionDB, cfg.SessionTable)

	// Cross-account STS provider + prober factory for capability probe.
	awsSTSClient := awsstsclient.NewFromConfig(awsCfg)
	stsProvider := sts.NewProvider(awsSTSClient)

	proberFactory := func(creds aws.CredentialsProvider) onboarding.CapabilityProber {
		// creds already comes from sts.Provider.AssumeForTenant which wraps
		// in aws.NewCredentialsCache; no need to double-wrap.
		tenantCfg := awsCfg.Copy()
		tenantCfg.Credentials = creds
		iamClient := awsiam.NewFromConfig(tenantCfg)
		return iam.NewProber(iamClient)
	}

	onboardingSvc := onboarding.NewService(onboarding.Config{
		Tenants:           tenantStore,
		Sources:           sourceStore,
		State:             onboardingStateStore,
		Audit:             auditLogger,
		Renderer:          iacRenderer,
		Publisher:         iacPublisher,
		StsAssumer:        stsProvider,
		ProberFactory:     proberFactory,
		SaaSAccountID:     cfg.SaaSAccountID,
		SaaSPrincipalName: cfg.SaaSPrincipalName,
		Region:            cfg.AWSRegion,
	})

	// Fetch the CloudFront origin-verify secret from SM. The raw token is never
	// stored in the Lambda environment (only the ARN is); the function must
	// abort at boot rather than start with an empty edge gate.
	smClient := secretsmanager.NewFromConfig(awsCfg)
	edgeSecret, edgeSecretErr := crypto.FetchEdgeSecret(context.Background(), smClient, cfg.EdgeAuthSecretARN)
	if edgeSecretErr != nil {
		slog.Error("failed to fetch edge secret", "error", edgeSecretErr)
		os.Exit(1)
	}

	// Cryptographically verify management-API ID tokens against the Cognito JWKS
	// endpoint. The API Gateway JWT authorizer is the primary edge control;
	// this in-process verifier is defense-in-depth so the Lambda never trusts a
	// bearer token it has not itself validated. JWKS is a public endpoint (no IAM
	// permission required). Outside local dev the pool/client IDs are mandatory —
	// api.NewRouter fails closed below if the verifier is nil.
	var verifier *cognito.JWKSVerifier
	if cfg.CognitoPoolID != "" {
		var jwksErr error
		verifier, jwksErr = cognito.NewJWKSVerifier(cfg.CognitoPoolID, cfg.AWSRegion)
		if jwksErr != nil {
			slog.Error("invalid Cognito pool ID or region in config", "error", jwksErr)
			os.Exit(1)
		}
	}

	deps := api.Dependencies{
		Tenants:          tenantStore,
		Apps:             appStore,
		Sources:          sourceStore,
		Claims:           claimStore,
		Audit:            auditLogger,
		ImportSvc:        importSvc,
		PreviewSvc:       previewSvc,
		CertSvc:          certSvc,
		CertMgr:          certMgr,
		SettingsSvc:      settingsSvc,
		OnboardingSvc:    onboardingSvc,
		BaseURL:          cfg.BaseURL,
		EntityID:         cfg.EntityID,
		KMSKeyID:         cfg.KMSKeyID,
		AWSRegion:        cfg.AWSRegion,
		SaaSAccountID:    cfg.SaaSAccountID,
		Environment:      cfg.Environment,
		Verifier:         verifier,
		VerifierClientID: cfg.CognitoClientID,
		EdgeAuthSecret:   edgeSecret,
	}

	router, err = api.NewRouter(deps)
	if err != nil {
		slog.Error("failed to build management API router", "error", err)
		os.Exit(1)
	}

	humaAPI := api.NewHumaAPI(router, "SAML Proxy Management API", "1.0.0")
	api.RegisterAPIRoutes(humaAPI, deps)

	slog.Info("management-api function initialized",
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

// rendererAdapter bridges the onboarding.Renderer interface (which uses a
// locally-defined RendererInput) to the templates.Render function (which uses
// templates.Input). Kept separate so onboarding doesn't import iac/templates.
type rendererAdapter struct{}

func (rendererAdapter) Render(format string, in onboarding.RendererInput) ([]byte, error) {
	return templates.Render(format, templates.Input{
		TenantSlug:        in.TenantSlug,
		ExternalID:        in.ExternalID,
		SaaSAccountID:     in.SaaSAccountID,
		SaaSPrincipalName: in.SaaSPrincipalName,
		Region:            in.Region,
		WantUserDirectory: in.WantUserDirectory,
		WantUserLifecycle: in.WantUserLifecycle,
	})
}
