package oidc

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// RegisterOIDCRoutes creates the zitadel/oidc provider and mounts it at /t/{tenant}/oidc/*.
// The provider handles: /.well-known/openid-configuration, /authorize, /token, /keys, /userinfo, etc.
// It also registers login and callback handlers for bridging zitadel/oidc with Cognito authentication.
//
// cryptoKey is the 32-byte AES-GCM key zitadel/oidc uses to encrypt every
// opaque bearer token (op.Config.CryptoKey). All OIDC Lambdas MUST share the
// same key — a bearer minted by oidc-token cannot be decrypted by
// oidc-discovery if the keys differ (MF-5). In deployed environments the key
// is fetched from AWS Secrets Manager (crypto.FetchOIDCCryptoKey); in local
// development a fresh random key is acceptable because a single process handles
// all routes.
//
// skipLoginCallbackRoutes controls whether the /login, /t/{tenant}/oidc/login,
// /t/{tenant}/oidc/callback, and /t/{tenant}/oidc/login/complete routes are
// registered. Set it to true on Lambdas that only serve token exchange, JWKS, or
// discovery (oidc-token, oidc-discovery): those Lambdas must not expose
// unauthenticated login/callback surfaces, and their hmacKey should be nil.
// Passing hmacKey=nil with skipLoginCallbackRoutes=false is still safe: every
// sign/verify call returns ErrCookieSigningDisabled so a mis-routed login
// request fails closed.
func RegisterOIDCRoutes(r chi.Router, storage *Storage, baseURL string, apps domain.AppReader, sources domain.SourceReader, audit domain.AuditRepository, cryptoKey [32]byte, hmacKey []byte, pendingStore *store.PendingLoginStore, skipLoginCallbackRoutes bool, loginOpts ...LoginHandlerOption) error {
	config := &op.Config{
		CryptoKey:                cryptoKey,
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		SupportedScopes:          []string{"openid", "profile", "email", "offline_access"},
	}

	// Use a custom issuer function that derives the issuer from the request path.
	// The tenant slug is extracted from the URL: /t/{tenant}/oidc/...
	issuerFn := func(insecure bool) (op.IssuerFromRequest, error) {
		return func(r *http.Request) string {
			return issuerFromRequest(r, baseURL)
		}, nil
	}

	// WithAllowInsecure lets the provider serve its issuer (and validate redirect
	// URIs) over plain HTTP. That is only ever acceptable for local development,
	// where baseURL is http://localhost:PORT. In every deployed environment
	// local.base_url is https:// (infra/locals.tf), so gating on the scheme means
	// a deployed provider always enforces HTTPS issuers and never silently accepts
	// http://.
	providerOpts := []op.Option{}
	if strings.HasPrefix(baseURL, "http://") {
		slog.Warn("OIDC provider allowing insecure HTTP issuer — only valid for local development", "base_url", baseURL)
		providerOpts = append(providerOpts, op.WithAllowInsecure())
	}

	provider, err := op.NewProvider(config, storage, issuerFn, providerOpts...)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create the login handler for Cognito authentication bridge.
	loginHandler, err := NewLoginHandler(storage, apps, sources, audit, hmacKey, baseURL, pendingStore, loginOpts...)
	if err != nil {
		return fmt.Errorf("failed to create login handler: %w", err)
	}

	if !skipLoginCallbackRoutes {
		// Register the root-level /login redirect handler.
		// zitadel/oidc calls Client.LoginURL() which returns /login?authRequestID=...
		// This handler reads the auth request to find the tenant slug and redirects
		// to the tenant-scoped login handler at /t/{tenant}/oidc/login.
		r.Get("/login", loginHandler.HandleLoginRedirect)
	} else {
		slog.Info("OIDC login/callback routes not registered on this Lambda (skipLoginCallbackRoutes=true)")
	}

	// Mount the OIDC provider handler under /t/{tenant}/oidc/
	r.Route("/t/{tenant}/oidc", func(r chi.Router) {
		if !skipLoginCallbackRoutes {
			// Login and callback handlers MUST be registered before the wildcard
			// so chi matches them first.
			r.Get("/login", loginHandler.HandleLogin)
			r.Get("/callback", loginHandler.HandleCallback)
			r.Post("/login/complete", loginHandler.HandleLoginComplete)
		}

		r.HandleFunc("/*", func(w http.ResponseWriter, req *http.Request) {
			// Strip the /t/{tenant}/oidc prefix so the provider sees paths
			// like /.well-known/openid-configuration, /authorize, /token, etc.
			tenantSlug := chi.URLParam(req, "tenant")
			if tenantSlug == "" {
				http.Error(w, "missing tenant", http.StatusBadRequest)
				return
			}

			// The wildcard path after /t/{tenant}/oidc
			remaining := chi.URLParam(req, "*")
			if !strings.HasPrefix(remaining, "/") {
				remaining = "/" + remaining
			}

			slog.Debug("OIDC request",
				"tenant", tenantSlug,
				"path", remaining,
				"method", req.Method,
			)

			// Preserve the tenant slug for issuerFromRequest (the URL path
			// is about to be rewritten, so chi.URLParam won't work later).
			req.Header.Set("X-Tenant-Slug", tenantSlug)

			// Rewrite the request URL for the provider handler
			req.URL.Path = remaining
			req.URL.RawPath = remaining

			provider.ServeHTTP(w, req)
		})
	})

	slog.Info("OIDC provider routes registered", "path", "/t/{tenant}/oidc/*",
		"loginCallbackRoutes", !skipLoginCallbackRoutes)
	return nil
}

// issuerFromRequest derives the OIDC issuer URL from the HTTP request.
// For a request to /t/acme/oidc/..., the issuer is baseURL + /t/acme/oidc.
func issuerFromRequest(r *http.Request, baseURL string) string {
	tenantSlug := r.Header.Get("X-Tenant-Slug")
	if tenantSlug == "" {
		tenantSlug = "default"
	}
	return strings.TrimSuffix(baseURL, "/") + "/t/" + tenantSlug + "/oidc"
}
