package main

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	chiadapter "github.com/awslabs/aws-lambda-go-api-proxy/chi"
	"github.com/go-chi/chi/v5"
	"github.com/guregu/dynamo/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/api"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/audit"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/config"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	proxyoidc "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/oidc"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/saml"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Setup structured logging
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// Load AWS config for production use (DynamoDB, KMS, etc.)
	var awsCfg aws.Config
	if !cfg.Environment.IsLocal() {
		var awsErr error
		awsCfg, awsErr = awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion(cfg.AWSRegion),
		)
		if awsErr != nil {
			slog.Error("failed to load AWS config", "error", awsErr)
			os.Exit(1)
		}
	}

	// Initialize store backend
	// For local dev, use in-memory store. For production, use DynamoDB via guregu/dynamo.
	// Two separate table instances: config table (tenants, apps, sources, claims)
	// and session table (OIDC auth requests/tokens, replay guards, sessions, audit).
	var configDB, sessionDB store.TableAPI
	if cfg.Environment.IsLocal() {
		slog.Info("using in-memory store for local development")
		configDB = store.NewMemoryDB()
		sessionDB = store.NewMemoryDB()
	} else {
		// Production: connect to real DynamoDB via guregu/dynamo
		dynamoDB := dynamo.New(awsCfg)
		configDB = store.NewDB(dynamoDB, cfg.DynamoDBTable)
		sessionDB = store.NewDB(dynamoDB, cfg.SessionTable)
		slog.Info("connected to DynamoDB",
			"configTable", cfg.DynamoDBTable,
			"sessionTable", cfg.SessionTable,
			"region", cfg.AWSRegion)
	}

	// Create all stores — config table stores
	tenantStore := store.NewTenantStore(configDB, cfg.DynamoDBTable)
	sourceStore := store.NewSourceStore(configDB, cfg.DynamoDBTable)
	appStore := store.NewAppStore(configDB, cfg.DynamoDBTable)
	claimStore := store.NewClaimStore(configDB, cfg.DynamoDBTable)
	// Session table stores
	replayStore := store.NewReplayStore(sessionDB, cfg.SessionTable)
	sessionStore := store.NewSessionStore(sessionDB, cfg.SessionTable)
	auditStore := store.NewAuditStore(sessionDB, cfg.SessionTable)

	// Wrap audit store with CloudWatch Logs audit logger. CloudWatch Logs is the
	// permanent, tamper-evident audit record; DynamoDB is only a 24h cache. In any
	// deployed environment we MUST write to CloudWatch, so wire a real client from
	// the loaded AWS config there. Only local dev passes nil (DDB/in-memory only),
	// so a deployed proxy can never silently drop the durable audit trail.
	var cwLogsClient audit.CloudWatchLogsClient
	if !cfg.Environment.IsLocal() {
		cwLogsClient = cloudwatchlogs.NewFromConfig(awsCfg)
	}
	auditLogger, err := audit.NewLogger(cfg.Environment, cwLogsClient, auditStore, "/identity-gateway/audit")
	if err != nil {
		slog.Error("failed to construct audit logger", "error", err)
		os.Exit(1)
	}

	// Wire replay store to session provider for AuthnRequest replay protection

	// For local dev: create a default "local" tenant with mock identity source
	if cfg.Environment.IsLocal() {
		if err := bootstrapLocalTenant(tenantStore, sourceStore, appStore, awsCfg); err != nil {
			slog.Warn("failed to bootstrap local tenant", "error", err)
		} else {
			slog.Info("local tenant bootstrapped", "tenant", "local")
		}
	}

	// Create KMS signer and certificate
	// For local dev, we'll use a mock KMS client. For production, use real AWS KMS.
	var signer *crypto.KMSSigner
	if cfg.Environment.IsLocal() {
		slog.Info("using mock KMS signer for local development")
		mockKMS, err := newMockKMSClient()
		if err != nil {
			slog.Error("failed to create mock KMS client", "error", err)
			os.Exit(1)
		}
		signer = crypto.NewKMSSigner(mockKMS)
	} else {
		// Production: use real AWS KMS for SAML signing
		slog.Info("initializing AWS KMS signer", "keyId", cfg.KMSKeyID)
		awsKMS := crypto.NewAWSKMSClient(awsCfg, cfg.KMSKeyID)
		signer = crypto.NewKMSSigner(awsKMS)
	}

	// Load or generate signing certificate via CertStore.
	// CertStore uses DynamoDB in production and MemoryDB for local dev.
	// Only the proxy monolith (used for local dev) generates certs as a fallback.
	certStore := crypto.NewCertStore(configDB)
	cert, err := certStore.GetActiveCert(context.Background())
	if err != nil {
		// No active cert — generate one (allowed in monolith for local dev bootstrap)
		cert, err = crypto.GenerateSelfSignedCert(signer, cfg.EntityID)
		if err != nil {
			slog.Error("failed to generate certificate", "error", err)
			os.Exit(1)
		}
		if storeErr := certStore.StoreActiveCert(context.Background(), cert); storeErr != nil {
			slog.Warn("failed to persist cert", "error", storeErr)
		}
	}

	// Convert certificate to PEM format for API responses
	certPEM := crypto.CertToPEM(cert)

	// Derive cookie encryption key from KMS (defense-in-depth: key never stored at rest).
	// In production, uses KMS GenerateDataKey so the key material is protected by the HSM.
	// In local dev, falls back to random bytes.
	var hmacKey []byte
	if !cfg.Environment.IsLocal() && cfg.KMSEncryptionKeyID != "" {
		kmsClient := kms.NewFromConfig(awsCfg)
		encKeyID := cfg.KMSEncryptionKeyID
		dataKeyOut, err := kmsClient.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
			KeyId:   &encKeyID,
			KeySpec: kmstypes.DataKeySpecAes256,
		})
		if err != nil {
			slog.Error("failed to generate data key from KMS", "error", err)
			os.Exit(1)
		}
		hmacKey = dataKeyOut.Plaintext
		slog.Info("cookie encryption key derived from KMS", "keyId", cfg.KMSEncryptionKeyID)
	} else {
		hmacKey = make([]byte, 32)
		if _, err := rand.Read(hmacKey); err != nil {
			slog.Error("failed to generate random HMAC key", "error", err)
			os.Exit(1)
		}
		slog.Info("cookie encryption key generated from random (local dev)")
	}

	// Create SAML components
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
	// SLO handler invalidates a replayed session cookie here too.
	sessionProvider.SetSessionStore(sessionStore)
	assertionMaker := saml.NewAssertionMaker(appStore, claimStore)

	// Create TenantIdPHandler
	tenantIdPHandler := saml.NewTenantIdPHandler(
		saml.WithSigner(signer),
		saml.WithCertificate(cert),
		saml.WithCertStore(certStore),
		saml.WithSPProvider(spProvider),
		saml.WithSessionProvider(sessionProvider),
		saml.WithAssertionMaker(assertionMaker),
		saml.WithBaseURL(cfg.BaseURL),
	)

	// Create services
	importSvc := service.NewMetadataImportService(appStore, &service.HTTPMetadataFetcher{})
	previewSvc := service.NewPreviewService(appStore, claimStore)
	certSvc := service.NewCertificateService(certPEM)
	settingsSvc := service.NewSettingsService(tenantStore, cfg.EntityID, cfg.BaseURL, cfg.KMSKeyID, cfg.KMSKeyIDBackup)

	// Cryptographically verify management-API ID tokens against the Cognito JWKS
	// endpoint when a pool is configured. In local dev without a pool,
	// api.NewRouter selects the explicit local-dev bypass; in any deployed
	// environment a nil verifier makes NewRouter fail closed.
	var apiVerifier *cognito.JWKSVerifier
	if cfg.CognitoPoolID != "" {
		var jwksErr error
		apiVerifier, jwksErr = cognito.NewJWKSVerifier(cfg.CognitoPoolID, cfg.AWSRegion)
		if jwksErr != nil {
			slog.Error("invalid Cognito pool ID or region in config", "error", jwksErr)
			os.Exit(1)
		}
	}

	// Fetch the CloudFront origin-verify secret from SM. Empty ARN in local dev
	// causes FetchEdgeSecret to return an empty string (no SM call), making
	// the edge middleware a no-op passthrough — the same behaviour as before.
	smClient := secretsmanager.NewFromConfig(awsCfg)
	edgeSecret, edgeSecretErr := crypto.FetchEdgeSecret(context.Background(), smClient, cfg.EdgeAuthSecretARN)
	if edgeSecretErr != nil {
		slog.Error("failed to fetch edge secret", "error", edgeSecretErr)
		os.Exit(1)
	}

	// Create router and API dependencies
	deps := api.Dependencies{
		Tenants:          tenantStore,
		Apps:             appStore,
		Sources:          sourceStore,
		Claims:           claimStore,
		Audit:            auditLogger,
		ImportSvc:        importSvc,
		PreviewSvc:       previewSvc,
		CertSvc:          certSvc,
		SettingsSvc:      settingsSvc,
		BaseURL:          cfg.BaseURL,
		EntityID:         cfg.EntityID,
		KMSKeyID:         cfg.KMSKeyID,
		AWSRegion:        cfg.AWSRegion,
		SaaSAccountID:    cfg.SaaSAccountID,
		Environment:      cfg.Environment,
		Verifier:         apiVerifier,
		VerifierClientID: cfg.CognitoClientID,
		EdgeAuthSecret:   edgeSecret,
	}

	router, err := api.NewRouter(deps)
	if err != nil {
		slog.Error("failed to build management API router", "error", err)
		os.Exit(1)
	}

	// Register health check FIRST (before Huma takes over unmatched routes)
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Pending-login store backs the custom login page (REPLACE-mode) flow,
	// shared by the SAML session provider and the OIDC login handler.
	pendingLoginStore := store.NewPendingLoginStore(sessionDB, cfg.SessionTable)
	sessionProvider.SetPendingLoginStore(pendingLoginStore)

	// Register tenant-scoped SAML routes: /t/{tenant}/saml/*
	// The tenant middleware is already applied by the router for /t/* routes
	saml.RegisterTenantRoutes(router, saml.TenantRoutesConfig{
		Handler:     tenantIdPHandler,
		SessionProv: sessionProvider,
		Sessions:    sessionStore,
		Tenants:     tenantStore,
		Apps:        appStore,
		Claims:      claimStore,
		Audit:       auditLogger,
	})

	// Register OIDC provider routes: /t/{tenant}/oidc/*
	if cfg.Environment.IsLocal() || os.Getenv("PROXY_ENABLE_OIDC") == "true" {
		joseSigner, err := crypto.NewKMSJoseSigner(cfg.KMSKeyID, signer.Client())
		if err != nil {
			slog.Error("failed to create KMS jose signer", "error", err)
			os.Exit(1)
		}

		oidcStorage := proxyoidc.NewStorage(appStore, claimStore, sourceStore, joseSigner, sessionDB, cfg.KMSKeyID)

		// MF-5: fetch the shared OIDC CryptoKey from Secrets Manager so all
		// processes (including this monolith when run in deployed mode or after
		// a restart) share the same key. In local dev without a secret ARN, fall
		// back to a random per-process key — tokens don't cross process boundaries
		// in that environment.
		var oidcCryptoKey [32]byte
		if cfg.OIDCCryptoKeySecretARN != "" {
			smClient := secretsmanager.NewFromConfig(awsCfg)
			var smErr error
			oidcCryptoKey, smErr = crypto.FetchOIDCCryptoKey(context.Background(), smClient, cfg.OIDCCryptoKeySecretARN)
			if smErr != nil {
				slog.Error("failed to fetch OIDC crypto key from Secrets Manager", "error", smErr)
				os.Exit(1)
			}
			slog.Info("OIDC crypto key loaded from Secrets Manager")
		} else {
			// Local dev only: no SM ARN configured — use a random ephemeral key.
			if _, err := rand.Read(oidcCryptoKey[:]); err != nil {
				slog.Error("failed to generate OIDC crypto key", "error", err)
				os.Exit(1)
			}
			slog.Info("OIDC crypto key generated randomly (local dev — set PROXY_OIDC_CRYPTO_KEY_SECRET_ARN for persistence)")
		}

		if err := proxyoidc.RegisterOIDCRoutes(router, oidcStorage, cfg.BaseURL, appStore, sourceStore, auditLogger, oidcCryptoKey, hmacKey, pendingLoginStore, false); err != nil {
			slog.Error("failed to register OIDC routes", "error", err)
			os.Exit(1)
		}
		slog.Info("OIDC provider enabled", "base_url", cfg.BaseURL)
	}

	// Create Huma API with OpenAPI config
	humaAPI := api.NewHumaAPI(router, "SAML Proxy Management API", "1.0.0")

	// Register API routes (management API under /api/v1/*)
	api.RegisterAPIRoutes(humaAPI, deps)

	// Lambda or HTTP server mode
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		// Running in AWS Lambda — use aws-lambda-go-api-proxy
		slog.Info("starting in Lambda mode (API Gateway v2)")
		chiAdapter := chiadapter.NewV2(router.(*chi.Mux))
		lambda.Start(chiAdapter.ProxyWithContextV2)
	} else {
		// Running locally — standard HTTP server
		srv := &http.Server{
			Addr:         ":" + cfg.Port,
			Handler:      router,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go func() {
			slog.Info("starting server",
				"port", cfg.Port,
				"environment", cfg.Environment,
				"openapi_spec", "http://localhost:"+cfg.Port+"/openapi.json")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "error", err)
				os.Exit(1)
			}
		}()

		<-ctx.Done()
		slog.Info("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
		}
	}

	slog.Info("server stopped")
}

// bootstrapLocalTenant creates a default "local" tenant with a mock identity source
// and a sample application for local development.
func bootstrapLocalTenant(tenantStore *store.TenantStore, sourceStore *store.SourceStore, appStore *store.AppStore, awsCfg aws.Config) error {
	ctx := context.Background()

	// Check if tenant already exists
	if _, err := tenantStore.Get(ctx, "local"); err == nil {
		// Already exists, skip
		return nil
	}

	// Create tenant
	t := &tenant.Tenant{
		Slug:             "local",
		DisplayName:      "Local Development",
		Plan:             "free",
		Status:           "active",
		MaxApps:          10,
		MaxAuthsPerMonth: 1000,

		// Set protocol defaults
		DefaultSessionDurationSec:     3600,
		DefaultSignResponse:           true,
		DefaultSignAssertion:          true,
		DefaultNameIDFormat:           "email",
		DefaultIDTokenLifetimeSec:     3600,
		DefaultAccessTokenLifetimeSec: 3600,
		DefaultScopes:                 []string{"openid", "email", "profile"},
	}
	if err := tenantStore.Create(ctx, t); err != nil {
		return err
	}

	// Create identity source from environment variables.
	// In local mode, these are optional — if not set, the bootstrap is skipped.
	poolID := os.Getenv("PROXY_COGNITO_POOL_ID")
	clientID := os.Getenv("PROXY_COGNITO_CLIENT_ID")
	region := os.Getenv("PROXY_AWS_REGION")
	if poolID == "" || clientID == "" {
		slog.Info("skipping local identity source bootstrap (PROXY_COGNITO_POOL_ID or PROXY_COGNITO_CLIENT_ID not set)")
		return nil
	}
	if region == "" {
		region = "eu-north-1"
	}

	src := &tenant.IdentitySource{
		DisplayName: "Local Cognito",
		Type:        "cognito",
		PoolID:      poolID,
		ClientID:    clientID,
		Region:      region,
		Status:      "active",
	}

	// Auto-discover domain if AWS credentials are available
	if awsCfg.Region != "" {
		info, discErr := cognito.DiscoverPool(ctx, awsCfg, src.PoolID, src.Region)
		if discErr != nil {
			slog.Warn("could not auto-discover Cognito domain for bootstrap", "error", discErr)
		} else if info.Domain != "" {
			src.Domain = info.Domain
			slog.Info("auto-discovered Cognito domain for bootstrap", "domain", src.Domain)
		}
	}

	if src.Domain == "" {
		domain := os.Getenv("PROXY_COGNITO_DOMAIN")
		if domain != "" {
			src.Domain = domain
		} else {
			slog.Warn("no Cognito domain available for bootstrap — set PROXY_COGNITO_DOMAIN")
			return nil
		}
	}

	sourceID, err := sourceStore.Create(ctx, "local", src)
	if err != nil {
		return err
	}

	// Create sample application with SAML config
	app := &tenant.Application{
		DisplayName: "Test Application",
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}

	samlCfg := &tenant.SAMLConfig{
		EntityID:           "https://test-sp.local",
		AcsURL:             "http://localhost:8081/saml/acs",
		AcsURLs:            []string{"http://localhost:8081/saml/acs"},
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:       "email",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       60,
	}

	if _, err := appStore.Create(ctx, "local", app, samlCfg); err != nil {
		return err
	}

	// Create sample OIDC application
	oidcApp := &tenant.Application{
		DisplayName: "Test OIDC App",
		Protocol:    "oidc",
		SourceID:    sourceID,
		Status:      "active",
	}
	oidcAppID, err := appStore.Create(ctx, "local", oidcApp, nil)
	if err != nil {
		return err
	}

	oidcCfg := &tenant.OIDCConfig{
		RedirectURIs:            []string{"http://localhost:8082/callback"},
		PostLogoutRedirectURIs:  []string{"http://localhost:8082/"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email", "profile"},
		TokenEndpointAuthMethod: "none",
		IDTokenLifetimeSec:      3600,
		AccessTokenLifetimeSec:  3600,
	}
	if err := appStore.UpdateOIDCConfig(ctx, "local", oidcAppID, oidcCfg); err != nil {
		return err
	}

	// Note: Claim mappings are configured through the management UI or API,
	// not hardcoded. When an identity source is added, the gateway can
	// auto-discover Cognito schema attributes via DescribeUserPool.

	slog.Info("bootstrapped sample apps",
		"saml_sp_entity", "https://test-sp.local",
		"saml_sp_acs", "http://localhost:8081/saml/acs",
		"oidc_rp_redirect", "http://localhost:8082/callback",
		"oidc_client_id", oidcAppID,
	)

	return nil
}

// mockKMSClient is a minimal mock for local development (duplicated from integration tests)
type mockKMSClient struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func newMockKMSClient() (*mockKMSClient, error) {
	// For local dev, persist the signing key to a file so it survives restarts.
	// In production, KMS provides key persistence — the key ID is stable.
	// SPs cache the IdP metadata cert, so a stable key is critical.
	keyFile := ".local-dev-signing-key.pem"
	var privateKey *rsa.PrivateKey

	if data, err := os.ReadFile(keyFile); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				privateKey = key
				slog.Info("loaded persisted local signing key", "file", keyFile)
			}
		}
	}

	if privateKey == nil {
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		// Persist for next restart
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			slog.Warn("could not persist local signing key", "error", err)
		} else {
			slog.Info("generated and persisted local signing key", "file", keyFile)
		}
	}
	return &mockKMSClient{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

func (m *mockKMSClient) Sign(digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, m.privateKey, opts.HashFunc(), digest)
}

func (m *mockKMSClient) PublicKey() (*rsa.PublicKey, error) {
	return m.publicKey, nil
}
