package saml

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	proxycrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

const (
	// sessionCookieName is the cookie that holds the authenticated SAML session.
	sessionCookieName = "saml_session"
	// flowCookieName holds the SAML request context + PKCE verifier during the
	// Cognito OAuth2 redirect flow.
	flowCookieName = "saml_flow"
	// cookieMaxAge controls how long the flow cookie is valid (10 minutes).
	cookieMaxAge = 600
)

// flowState is the data persisted in the flow cookie while the user
// authenticates at Cognito.
type flowState struct {
	FlowID     string `json:"fid"` // matches OAuth2 state parameter
	RelayState string `json:"rs"`
	RequestBuf string `json:"rb"` // base64-encoded original SAMLRequest
	Verifier   string `json:"v"`
	SPEntityID string `json:"sp"`
	SourceID   string `json:"sid"` // identity source ID for callback
	TenantSlug string `json:"ts"`  // tenant slug for callback
	CreatedAt  int64  `json:"ca"`
}

// sessionEnvelope is the local, HMAC-signed wrapper persisted in the session
// cookie. The crewsaml.Session type is vendored and cannot carry our binding
// fields, so we bind the session to the tenant, identity source, and target SP
// it was minted for in this envelope instead. GetSession refuses to reuse a
// cookie whose binding does not match the current request, preventing a session
// established for one tenant/SP from being replayed against another
// (cross-tenant SSO).
type sessionEnvelope struct {
	Session    *crewsaml.Session `json:"session"`
	TenantSlug string            `json:"tenant"`
	SourceID   string            `json:"source,omitempty"`
	SPEntityID string            `json:"sp,omitempty"`
}

// SessionProvider implements crewsaml.SessionProvider. It bridges the Cognito
// OAuth2+PKCE flow with the crewjam/saml IdP library.
//
// In multi-tenant mode, the session provider dynamically resolves which Cognito
// pool to use based on the tenant and application configuration.
type SessionProvider struct {
	sources      domain.SourceReader
	apps         domain.AppReader
	signedCookie *proxycrypto.SignedCookie
	replayStore  *store.ReplayStore
	auditStore   domain.AuditRepository
	baseURL      string
	// idp is the legacy single-tenant IdP, set once at construction. In
	// multi-tenant mode it stays nil and idpFactory is used instead.
	idp *crewsaml.IdentityProvider
	// idpFactory builds a tenant-scoped IdP on demand. It is set once at wiring
	// time (never per-request), so the OAuth2 callback can rebuild the IdP for
	// its own tenant — resolved from the signed flow state — instead of reading
	// a shared field that a concurrent request for a different tenant could have
	// overwritten. This closes both the data race and the cross-tenant
	// flow-confusion it enabled.
	idpFactory func(tenantSlug string) *crewsaml.IdentityProvider

	// pendingStore persists the original request context while the user
	// authenticates at a custom login page (REPLACE-mode custom login).
	pendingStore *store.PendingLoginStore

	// sessionStore records server-side session revocations so a logout at the
	// SLO Lambda invalidates the stateless session cookie everywhere, including
	// a copy replayed at this (separate) SSO Lambda before the cookie's own 8h
	// expiry. When nil (legacy/tests), GetSession skips the revocation check and
	// behaves as before.
	sessionStore domain.SessionRepository

	// cognitoAuth is the legacy single-tenant auth client. Kept for backward
	// compatibility in tests that don't use dynamic identity sources.
	cognitoAuth *cognito.AuthClient

	// jwksVerifiers caches an idTokenVerifier per Cognito pool (keyed by
	// region|poolID) so the direct ID-token auth path does not refetch JWKS on
	// every request. The verifier itself caches keys for an hour.
	jwksMu        sync.Mutex
	jwksVerifiers map[string]idTokenVerifier
	// verifierFactory builds a verifier for a pool. Defaults to a JWKS-backed
	// verifier; overridable in tests.
	verifierFactory func(poolID, region string) idTokenVerifier
}

// idTokenVerifier verifies a Cognito ID token's signature and claims, returning
// the validated claim set. *cognito.JWKSVerifier satisfies this interface.
type idTokenVerifier interface {
	Verify(tokenString, expectedClientID string) (map[string]interface{}, error)
}

// SessionProviderOption is a functional option for configuring SessionProvider.
type SessionProviderOption func(*SessionProvider)

// WithSourceStore sets the identity source reader.
func WithSourceStore(s domain.SourceReader) SessionProviderOption {
	return func(sp *SessionProvider) { sp.sources = s }
}

// WithAppStore sets the application reader.
func WithAppStore(a domain.AppReader) SessionProviderOption {
	return func(sp *SessionProvider) { sp.apps = a }
}

// WithHMACKey sets the HMAC key for cookie signing and optionally enables encryption.
// It panics if key is non-nil but not exactly 32 bytes — a short key is a
// programming error; callers must supply a properly-sized key or nil.
func WithHMACKey(key []byte) SessionProviderOption {
	return func(sp *SessionProvider) {
		sc, err := proxycrypto.NewSignedCookie(key)
		if err != nil {
			panic("WithHMACKey: " + err.Error())
		}
		sp.signedCookie = sc
	}
}

// WithProviderBaseURL sets the base URL for tenant-scoped callback endpoints.
func WithProviderBaseURL(url string) SessionProviderOption {
	return func(sp *SessionProvider) { sp.baseURL = url }
}

// WithVerifierFactory overrides the ID-token verifier factory. Production leaves
// this unset so the default JWKS-backed verifier is used; it exists so callers
// outside this package (notably the root-package e2e suite, which cannot reach
// an unexported field) can inject a stub verifier for a mock Cognito pool.
func WithVerifierFactory(factory func(poolID, region string) cognito.IDTokenVerifier) SessionProviderOption {
	return func(sp *SessionProvider) {
		sp.verifierFactory = func(poolID, region string) idTokenVerifier {
			return factory(poolID, region)
		}
	}
}

// NewSessionProvider creates a new multi-tenant SessionProvider with functional options.
//
// The HMAC key is used to sign the flow cookie to prevent tampering. It should be a
// random 32-byte key. The same key is used for AES-256-GCM encryption of cookie
// payloads (PKCE verifiers, user PII).
func NewSessionProvider(opts ...SessionProviderOption) *SessionProvider {
	sp := &SessionProvider{}
	for _, opt := range opts {
		opt(sp)
	}
	return sp
}

// NewSessionProviderCompat creates a SessionProvider with a static Cognito auth
// client for backward compatibility in tests. It panics if hmacKey is non-nil
// but not exactly 32 bytes — callers must supply a well-sized key or nil.
func NewSessionProviderCompat(cognitoAuth *cognito.AuthClient, hmacKey []byte) *SessionProvider {
	sc, err := proxycrypto.NewSignedCookie(hmacKey)
	if err != nil {
		panic("NewSessionProviderCompat: " + err.Error())
	}
	return &SessionProvider{
		cognitoAuth:  cognitoAuth,
		signedCookie: sc,
	}
}

// SetReplayStore wires the replay store for AuthnRequest replay protection.
func (sp *SessionProvider) SetReplayStore(rs *store.ReplayStore) {
	sp.replayStore = rs
}

// SetAuditStore wires the audit repository for flow step logging.
// Accepts domain.AuditRepository so callers can pass either the raw
// store.AuditStore or the audit.Logger wrapper.
func (sp *SessionProvider) SetAuditStore(as domain.AuditRepository) {
	sp.auditStore = as
}

// SetIDP wires a single, fixed IdP reference after construction (the IdP needs
// the SessionProvider, so there is a circular dependency that we break here).
// This is the legacy single-tenant path used by NewIdentityProvider and tests;
// it is called once at wiring time, never per-request. Multi-tenant callers use
// SetIDPFactory instead so each request's callback resolves its own tenant's
// IdP rather than sharing one mutable field.
func (sp *SessionProvider) SetIDP(idp *crewsaml.IdentityProvider) {
	sp.idp = idp
}

// SetIDPFactory wires a per-tenant IdP builder. It is set once at wiring time.
// When set, the OAuth2 callback rebuilds the IdP for the tenant recorded in the
// (signed, tamper-proof) flow state, so concurrent SSO flows for different
// tenants never share or overwrite a single IdP reference.
func (sp *SessionProvider) SetIDPFactory(factory func(tenantSlug string) *crewsaml.IdentityProvider) {
	sp.idpFactory = factory
}

// idpForTenant returns the IdP to resume an SSO flow with. In multi-tenant mode
// it builds a fresh tenant-scoped IdP from the factory; otherwise it returns the
// single legacy IdP. Returns nil if neither is configured.
func (sp *SessionProvider) idpForTenant(tenantSlug string) *crewsaml.IdentityProvider {
	if sp.idpFactory != nil && tenantSlug != "" {
		return sp.idpFactory(tenantSlug)
	}
	return sp.idp
}

// SetPendingLoginStore wires the pending-login store used by the custom login
// page (REPLACE-mode) flow.
func (sp *SessionProvider) SetPendingLoginStore(ps *store.PendingLoginStore) {
	sp.pendingStore = ps
}

// SetSessionStore wires the session repository used to consult server-side
// revocation markers on cookie reuse. It accepts domain.SessionRepository
// so callers can pass the concrete store or a test double.
func (sp *SessionProvider) SetSessionStore(s domain.SessionRepository) {
	sp.sessionStore = s
}

// resolveAuthClient resolves the Cognito auth client for the given request.
// In multi-tenant mode, it looks up the identity source from the app's config
// within the caller-supplied tenant. In legacy mode (tests), it uses the static
// cognitoAuth client. The tenant is an input, not derived from the entityID: a
// SAML entityID is unique only within a tenant, so scoping the lookup to the
// tenant on the request path is what prevents one tenant's SP from resolving
// against another tenant's identity source. Returns the resolved sourceID.
func (sp *SessionProvider) resolveAuthClient(ctx context.Context, tenantSlug, entityID string) (*cognito.AuthClient, string, error) {
	// Legacy single-tenant path: use pre-configured client.
	if sp.cognitoAuth != nil {
		return sp.cognitoAuth, "", nil
	}

	if tenantSlug == "" {
		return nil, "", fmt.Errorf("missing tenant for entity ID %q", entityID)
	}

	// Multi-tenant path: resolve the app within this tenant, then its source.
	app, _, err := sp.apps.GetByTenantEntityID(ctx, tenantSlug, entityID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve application for entity ID %q in tenant %q: %w", entityID, tenantSlug, err)
	}

	source, err := sp.sources.Get(ctx, tenantSlug, app.SourceID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve identity source %q for tenant %q: %w", app.SourceID, tenantSlug, err)
	}

	// Build callback URL scoped to the tenant.
	callbackURL := sp.baseURL + "/t/" + tenantSlug + "/saml/acs"
	authClient, err := cognito.NewAuthClientForSource(ctx, source, callbackURL, cognito.NoSecretFetcher)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create auth client for source %q: %w", source.ID, err)
	}

	return authClient, source.ID, nil
}

// GetSession implements crewsaml.SessionProvider.
//
// If a valid session cookie exists, it returns the session. Otherwise it
// initiates a Cognito OAuth2+PKCE redirect and returns nil (meaning the HTTP
// response has already been written).
func (sp *SessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *crewsaml.IdpAuthnRequest) *crewsaml.Session {
	// Check for existing session cookie. A cookie is only reused if its signed
	// binding matches the tenant and target SP of THIS request; a session minted
	// for another tenant or another SP is ignored (treated as no session) so it
	// cannot be replayed across the tenant/SP boundary — the core cross-tenant
	// SSO defense. Falling through re-authenticates rather than leaking a foreign
	// session.
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		if session, env, derr := sp.decodeSessionEnvelope(cookie.Value); derr == nil {
			if sp.sessionBindingMatches(r, req, env) {
				// The cookie is authentic and bound to this tenant/SP. Before
				// honouring it, consult the server-side revocation marker: a
				// logout processed at the SLO Lambda records the SessionIndex as
				// revoked, and a copy of this cookie replayed here must not
				// survive that logout for the remainder of its 8h lifetime. Fail
				// closed — a store error re-authenticates rather than trusting a
				// cookie we could not check.
				if sp.sessionStore != nil && session != nil {
					revoked, rerr := sp.sessionStore.IsSessionRevoked(r.Context(), session.Index)
					if rerr != nil {
						slog.Warn("session revocation check failed; re-authenticating",
							"error", rerr, "tenant", env.TenantSlug)
					} else if revoked {
						slog.Info("rejected revoked session cookie; re-authenticating",
							"tenant", env.TenantSlug, "sp", env.SPEntityID)
					} else {
						return session
					}
				} else {
					return session
				}
			} else {
				slog.Warn("rejected session cookie bound to a different tenant/SP",
					"cookieTenant", env.TenantSlug, "cookieSP", env.SPEntityID,
					"pathTenant", chi.URLParam(r, "tenant"))
			}
		}
	}

	// No valid session -- check for a directly-presented Cognito ID token before
	// falling back to the interactive Cognito OAuth2 redirect. This lets a caller
	// that already holds a valid ID token (issued by the SP's bound identity
	// source) federate without a fresh Code+PKCE login.
	if session, handled := sp.trySessionFromIDToken(w, r, req); handled {
		return session
	}

	// No session and no bearer token. If the target app has a custom login page
	// configured, REPLACE the Cognito Hosted UI redirect with a redirect to that
	// page. The page authenticates the user and posts an ID token back to the
	// SAML session-establish endpoint to resume this flow.
	if handled := sp.tryCustomLoginRedirect(w, r, req); handled {
		return nil
	}

	// No valid session -- start the Cognito OAuth2 flow.

	// Replay protection: atomically claim this AuthnRequest ID. MarkSeen is a
	// single conditional write, so it both detects replays and records the ID
	// with no check-then-act gap. Fail CLOSED: a replayed ID or an unavailable
	// replay store both reject the request rather than continue the flow.
	if sp.replayStore != nil && req.Request.ID != "" {
		if err := sp.replayStore.MarkSeen(r.Context(), req.Request.ID, 5*time.Minute); err != nil {
			if errors.Is(err, store.ErrConditionFailed) {
				slog.Warn("rejected replayed AuthnRequest", "authnRequestID", req.Request.ID)
				http.Error(w, "replayed AuthnRequest", http.StatusForbidden)
				return nil
			}
			slog.Error("replay store unavailable; rejecting request", "error", err)
			http.Error(w, "replay protection unavailable", http.StatusServiceUnavailable)
			return nil
		}
	}

	entityID := req.ServiceProviderMetadata.EntityID
	tenantSlug := chi.URLParam(r, "tenant")

	// Log SSO initiation (use AuthnRequest ID as flow ID)
	if sp.auditStore != nil && req.Request.ID != "" {
		if err := sp.auditStore.LogStep(r.Context(), tenantSlug, req.Request.ID, "sso_initiated", entityID, "", nil); err != nil {
			slog.Error("audit store log failed", "error", err)
		}
	}
	authClient, sourceID, err := sp.resolveAuthClient(r.Context(), tenantSlug, entityID)
	if err != nil {
		slog.Error("failed to resolve auth client", "error", err, "entityID", entityID, "tenant", tenantSlug)
		http.Error(w, "unable to resolve identity provider", http.StatusInternalServerError)
		return nil
	}

	verifier, challenge := authClient.GeneratePKCE()

	// Generate a flow ID for state parameter.
	flowID := generateFlowID()

	// Encode the SAML request buffer so we can resume after Cognito callback.
	reqBuf := base64.StdEncoding.EncodeToString(req.RequestBuffer)

	state := &flowState{
		FlowID:     flowID,
		RelayState: req.RelayState,
		RequestBuf: reqBuf,
		Verifier:   verifier,
		SPEntityID: entityID,
		SourceID:   sourceID,
		TenantSlug: tenantSlug,
		CreatedAt:  time.Now().Unix(),
	}

	// Set flow cookie (signed).
	cookieValue, err := sp.signedEncode(state)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil
	}

	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to Cognito authorization endpoint.
	authURL := authClient.AuthorizationURL(flowID, challenge)
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

// HandleCallback processes the Cognito OAuth2 callback, exchanges the code for
// tokens, builds a SAML session, and resumes the IdP SSO flow.
func (sp *SessionProvider) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Load flow state from cookie.
	cookie, err := r.Cookie(flowCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing flow cookie", http.StatusBadRequest)
		return
	}

	state, err := sp.signedDecode(cookie.Value)
	if err != nil {
		http.Error(w, "invalid flow cookie", http.StatusBadRequest)
		return
	}

	// Check expiry (10 minutes).
	if time.Now().Unix()-state.CreatedAt > int64(cookieMaxAge) {
		http.Error(w, "flow expired", http.StatusBadRequest)
		return
	}

	// Validate OAuth2 state parameter matches the flow cookie (CSRF protection).
	callbackState := r.URL.Query().Get("state")
	if callbackState == "" || callbackState != state.FlowID {
		http.Error(w, "state parameter mismatch", http.StatusForbidden)
		return
	}

	// Resolve the auth client from the flow state.
	var authClient *cognito.AuthClient
	if sp.cognitoAuth != nil {
		// Legacy single-tenant path.
		authClient = sp.cognitoAuth
	} else if state.TenantSlug != "" && state.SourceID != "" {
		// Multi-tenant path: recreate auth client from stored source ID.
		source, err := sp.sources.Get(r.Context(), state.TenantSlug, state.SourceID)
		if err != nil {
			slog.Error("failed to load identity source for callback", "error", err,
				"tenantSlug", state.TenantSlug, "sourceID", state.SourceID)
			http.Error(w, "unable to resolve identity provider", http.StatusInternalServerError)
			return
		}
		callbackURL := sp.baseURL + "/t/" + state.TenantSlug + "/saml/acs"
		authClient, err = cognito.NewAuthClientForSource(r.Context(), source, callbackURL, cognito.NoSecretFetcher)
		if err != nil {
			slog.Error("failed to create auth client for callback", "error", err,
				"tenantSlug", state.TenantSlug, "sourceID", state.SourceID)
			http.Error(w, "unable to resolve identity provider", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "unable to resolve identity provider for callback", http.StatusInternalServerError)
		return
	}

	// Exchange authorization code for tokens. Use the request context so the
	// outbound token exchange is cancelled if the client disconnects, rather
	// than leaking the connection until it completes on its own.
	idToken, err := authClient.ExchangeCode(r.Context(), code, state.Verifier)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	// Verify the ID token's RS256 signature via the pool's JWKS and validate
	// its iss/aud/exp/token_use claims in-process, rather than trusting the
	// token because it arrived over the token-exchange TLS connection. This is
	// the same verification the direct ID-token path performs, so a token that
	// was tampered with or minted by a compromised token endpoint is rejected.
	poolID, region := authClient.PoolID(), authClient.Region()
	if poolID == "" || region == "" {
		slog.Error("callback: identity source missing poolID/region; cannot verify id token")
		http.Error(w, "unable to verify id token", http.StatusInternalServerError)
		return
	}
	jv, jvErr := sp.verifierFor(poolID, region)
	if jvErr != nil {
		slog.Warn("callback: invalid identity source pool ID or region", "error", jvErr)
		http.Error(w, "invalid identity source configuration", http.StatusBadRequest)
		return
	}
	payload, err := jv.Verify(idToken, authClient.ClientID())
	if err != nil {
		slog.Warn("callback: id token verification failed", "error", err)
		http.Error(w, "invalid id token", http.StatusBadGateway)
		return
	}

	claims := cognito.ExtractClaims(payload)

	// Log successful SSO completion
	if sp.auditStore != nil {
		payload := map[string]string{
			"status": "success",
		}
		if state.TenantSlug != "" {
			payload["tenant"] = state.TenantSlug
		}
		if err := sp.auditStore.LogStep(r.Context(), state.TenantSlug, state.FlowID, "sso_complete", state.SPEntityID, claims.Email, payload); err != nil {
			slog.Error("audit store log failed", "error", err)
		}
	}

	// Build SAML session from Cognito claims.
	session := buildSessionFromClaims(claims)

	// Set session cookie so subsequent requests find the session. Bind it to the
	// tenant/source/SP recorded in the (signed) flow state so it cannot be
	// replayed against another tenant or SP.
	sessCookie, err := sp.encodeBoundSessionCookie(session, state.TenantSlug, state.SourceID, state.SPEntityID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessCookie,
		Path:     "/",
		MaxAge:   int(session.ExpireTime.Sub(session.CreateTime).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear flow cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Resume the SAML SSO flow by forwarding to the IdP SSO handler. Rebuild
	// the IdP for THIS flow's tenant (recorded in the signed flow state) rather
	// than reading a shared field: a concurrent SSO flow for another tenant must
	// not be able to redirect this callback through its IdP. We reconstruct the
	// original SAMLRequest as a POST form value and inject the session cookie
	// into the request so that GetSession finds it without starting another
	// Cognito redirect.
	idp := sp.idpForTenant(state.TenantSlug)
	if idp != nil {
		reqBuf, err := base64.StdEncoding.DecodeString(state.RequestBuf)
		if err == nil {
			r.Method = http.MethodPost
			r.PostForm = r.URL.Query()
			r.PostForm.Set("SAMLRequest", base64.StdEncoding.EncodeToString(reqBuf))
			if state.RelayState != "" {
				r.PostForm.Set("RelayState", state.RelayState)
			}
			// Inject the session cookie into the request so the IdP's
			// GetSession call finds the session we just created, avoiding a
			// second redirect to Cognito.
			// Inbound request cookie (r.AddCookie), never written to the
			// client, so Secure/HttpOnly do not apply.
			// nosemgrep: cookie-missing-secure, cookie-missing-httponly
			r.AddCookie(&http.Cookie{ //nolint:gosec // internal request cookie, never sent to client
				Name:  sessionCookieName,
				Value: sessCookie,
			})
			idp.ServeSSO(w, r)
			return
		}
	}

	http.Error(w, "unable to resume SAML flow", http.StatusInternalServerError)
}

// extractBearerToken returns the token from an "Authorization: Bearer <token>"
// header, or "" if absent or malformed.
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// resolveSource resolves the identity source bound to the SP identified by
// (tenant, entityID). Only available in multi-tenant mode (sources + apps
// configured). Tenant is a required input, not derived from the entityID,
// because a SAML entityID is unique only within a tenant — resolving it
// without the tenant would let one tenant's SP bind to another tenant's
// identity source.
func (sp *SessionProvider) resolveSource(ctx context.Context, tenantSlug, entityID string) (*tenant.IdentitySource, error) {
	if sp.apps == nil || sp.sources == nil {
		return nil, fmt.Errorf("source resolution not configured")
	}
	if tenantSlug == "" {
		return nil, fmt.Errorf("missing tenant for entity ID %q", entityID)
	}
	app, _, err := sp.apps.GetByTenantEntityID(ctx, tenantSlug, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve application for entity ID %q in tenant %q: %w", entityID, tenantSlug, err)
	}
	source, err := sp.sources.Get(ctx, tenantSlug, app.SourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity source %q for tenant %q: %w", app.SourceID, tenantSlug, err)
	}
	return source, nil
}

// verifierFor returns a cached verifier for the given Cognito pool or an error
// when poolID/region fail format validation (MF-6: SSRF input guard).
func (sp *SessionProvider) verifierFor(poolID, region string) (idTokenVerifier, error) {
	key := region + "|" + poolID
	sp.jwksMu.Lock()
	defer sp.jwksMu.Unlock()
	if sp.jwksVerifiers == nil {
		sp.jwksVerifiers = make(map[string]idTokenVerifier)
	}
	v, ok := sp.jwksVerifiers[key]
	if !ok {
		var err error
		if sp.verifierFactory != nil {
			v = sp.verifierFactory(poolID, region)
		} else {
			v, err = cognito.NewJWKSVerifier(poolID, region)
			if err != nil {
				return nil, err
			}
		}
		sp.jwksVerifiers[key] = v
	}
	return v, nil
}

// trySessionFromIDToken attempts to authenticate the SSO request directly from a
// Cognito ID token supplied in the Authorization header, bypassing the
// interactive Code+PKCE redirect.
//
// Return semantics:
//   - (nil, false): no bearer token present. The caller should fall through to
//     the normal Cognito redirect flow.
//   - (nil, true): a token was presented but is invalid (or could not be
//     verified). An error response has already been written; the caller must
//     stop. We deliberately fail closed here rather than falling back to the
//     redirect, so a bad token is a hard error instead of a silent re-login.
//   - (session, true): the token is valid. The caller should return the session
//     so the SAML IdP continues building the assertion.
//
// Security: the token is fully verified via JWKS (RS256 signature) and its iss,
// aud (== the source's Cognito app client ID), exp, and token_use claims must
// match the identity source bound to the requesting SP. Replay protection still
// applies to the AuthnRequest.
func (sp *SessionProvider) trySessionFromIDToken(w http.ResponseWriter, r *http.Request, req *crewsaml.IdpAuthnRequest) (*crewsaml.Session, bool) {
	token := extractBearerToken(r)
	if token == "" {
		return nil, false
	}

	// This path requires dynamic source resolution; the legacy static client
	// has no pool metadata for JWKS verification.
	if sp.cognitoAuth != nil || sp.apps == nil || sp.sources == nil {
		return nil, false
	}

	entityID := req.ServiceProviderMetadata.EntityID
	tenantSlug := chi.URLParam(r, "tenant")
	source, err := sp.resolveSource(r.Context(), tenantSlug, entityID)
	if err != nil {
		slog.Warn("id-token auth: failed to resolve identity source", "error", err, "entityID", entityID, "tenant", tenantSlug)
		http.Error(w, "unable to resolve identity provider", http.StatusInternalServerError)
		return nil, true
	}

	// Without pool ID and region we cannot construct the JWKS issuer URL, so we
	// cannot safely verify the token. Treat as a hard failure.
	if source.PoolID == "" || source.Region == "" {
		slog.Warn("id-token auth: identity source missing poolID/region", "sourceID", source.ID)
		http.Error(w, "identity source does not support direct token authentication", http.StatusBadRequest)
		return nil, true
	}

	jv, jvErr := sp.verifierFor(source.PoolID, source.Region)
	if jvErr != nil {
		slog.Warn("id-token auth: invalid identity source pool ID or region", "error", jvErr, "sourceID", source.ID)
		http.Error(w, "invalid identity source configuration", http.StatusBadRequest)
		return nil, true
	}
	payload, err := jv.Verify(token, source.ClientID)
	if err != nil {
		slog.Warn("id-token auth: token verification failed", "error", err, "entityID", entityID)
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return nil, true
	}

	// Replay protection on the AuthnRequest, mirroring the redirect path:
	// one atomic conditional write, fail CLOSED on replay or store error.
	if sp.replayStore != nil && req.Request.ID != "" {
		if merr := sp.replayStore.MarkSeen(r.Context(), req.Request.ID, 5*time.Minute); merr != nil {
			if errors.Is(merr, store.ErrConditionFailed) {
				slog.Warn("rejected replayed AuthnRequest", "authnRequestID", req.Request.ID)
				http.Error(w, "replayed AuthnRequest", http.StatusForbidden)
				return nil, true
			}
			slog.Error("replay store unavailable; rejecting request", "error", merr)
			http.Error(w, "replay protection unavailable", http.StatusServiceUnavailable)
			return nil, true
		}
	}

	claims := cognito.ExtractClaims(payload)
	session := buildSessionFromClaims(claims)

	// Audit the direct-token authentication.
	if sp.auditStore != nil {
		auditPayload := map[string]string{"status": "success", "method": "id_token"}
		if tenantSlug != "" {
			auditPayload["tenant"] = tenantSlug
		}
		flowID := req.Request.ID
		if flowID == "" {
			flowID = session.ID
		}
		if err := sp.auditStore.LogStep(r.Context(), tenantSlug, flowID, "sso_token_auth", entityID, claims.Email, auditPayload); err != nil {
			slog.Error("audit store log failed", "error", err)
		}
	}

	// Persist a session cookie so any follow-up requests in the same browser
	// session reuse it without re-presenting the token. Bind it to the tenant,
	// source, and SP it was issued for so it is not replayable elsewhere.
	if sessCookie, err := sp.encodeBoundSessionCookie(session, tenantSlug, source.ID, entityID); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sessCookie,
			Path:     "/",
			MaxAge:   int(session.ExpireTime.Sub(session.CreateTime).Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	return session, true
}

// tryCustomLoginRedirect handles REPLACE-mode custom login. If the SP's app has
// a custom login page configured, it persists the original SAML request context
// server-side (keyed by an opaque flow ID), redirects the browser to the custom
// login page with a return_to + state, and reports handled=true. Returns false
// to fall through to the normal Cognito Hosted UI redirect (no custom login, or
// the feature is not fully wired).
func (sp *SessionProvider) tryCustomLoginRedirect(w http.ResponseWriter, r *http.Request, req *crewsaml.IdpAuthnRequest) bool {
	// Requires dynamic resolution + a pending-login store.
	if sp.cognitoAuth != nil || sp.apps == nil || sp.sources == nil || sp.pendingStore == nil {
		return false
	}

	entityID := req.ServiceProviderMetadata.EntityID
	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		return false
	}
	app, _, err := sp.apps.GetByTenantEntityID(r.Context(), tenantSlug, entityID)
	if err != nil || app == nil || !app.HasCustomLogin() {
		return false
	}

	// Defensive: never redirect to a login URL that is not in the allowlist,
	// even though config-time validation enforces this.
	if !app.IsTrustedLoginRedirect(app.CustomLoginURL) {
		slog.Error("custom login: configured URL not in trusted allowlist",
			"entityID", entityID, "customLoginUrl", app.CustomLoginURL)
		http.Error(w, "custom login page is not a trusted redirect target", http.StatusInternalServerError)
		return true
	}

	flowID := generateFlowID()
	pending := &store.PendingLogin{
		FlowID:         flowID,
		Protocol:       "saml",
		TenantSlug:     tenantSlug,
		SourceID:       app.SourceID,
		AppID:          app.ID,
		SAMLRequestB64: base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:     req.RelayState,
		SPEntityID:     entityID,
	}
	if err := sp.pendingStore.Create(r.Context(), pending, time.Duration(cookieMaxAge)*time.Second); err != nil {
		slog.Error("custom login: failed to store pending login", "error", err, "entityID", entityID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}

	if sp.auditStore != nil && req.Request.ID != "" {
		_ = sp.auditStore.LogStep(r.Context(), tenantSlug, req.Request.ID, "sso_custom_login_redirect", entityID, "",
			map[string]string{"tenant": tenantSlug})
	}

	returnTo := sp.baseURL + "/t/" + tenantSlug + "/saml/login/complete"
	http.Redirect(w, r, buildCustomLoginURL(app.CustomLoginURL, returnTo, flowID), http.StatusFound)
	return true
}

// CompleteCustomLogin verifies a Cognito ID token presented to the SAML
// session-establish endpoint against the pending login's bound identity source,
// builds a SAML session, and returns the encoded session cookie value together
// with the (consumed) pending login. The pending login is deleted (single-use).
func (sp *SessionProvider) CompleteCustomLogin(ctx context.Context, flowID, token string) (string, *store.PendingLogin, error) {
	if sp.pendingStore == nil {
		return "", nil, fmt.Errorf("custom login not configured")
	}
	pl, err := sp.pendingStore.Get(ctx, flowID)
	if err != nil {
		return "", nil, fmt.Errorf("invalid or expired login flow")
	}
	if pl.Protocol != "saml" {
		return "", nil, fmt.Errorf("login flow protocol mismatch")
	}
	// Single-use: consume the pending login regardless of verification outcome.
	_ = sp.pendingStore.Delete(ctx, flowID)

	source, err := sp.sources.Get(ctx, pl.TenantSlug, pl.SourceID)
	if err != nil {
		return "", nil, fmt.Errorf("unable to resolve identity provider")
	}
	if source.PoolID == "" || source.Region == "" {
		return "", nil, fmt.Errorf("identity source does not support token authentication")
	}

	jv, jvErr := sp.verifierFor(source.PoolID, source.Region)
	if jvErr != nil {
		return "", nil, fmt.Errorf("invalid identity source configuration: %w", jvErr)
	}
	payload, err := jv.Verify(token, source.ClientID)
	if err != nil {
		return "", nil, fmt.Errorf("invalid id token")
	}

	claims := cognito.ExtractClaims(payload)
	session := buildSessionFromClaims(claims)

	if sp.auditStore != nil {
		_ = sp.auditStore.LogStep(ctx, pl.TenantSlug, flowID, "sso_token_auth", pl.SPEntityID, claims.Email,
			map[string]string{"status": "success", "method": "custom_login", "tenant": pl.TenantSlug})
	}

	// Bind the cookie to the pending login's tenant/source/SP so it cannot be
	// replayed against another tenant or SP once returned to the browser.
	sessCookie, err := sp.encodeBoundSessionCookie(session, pl.TenantSlug, pl.SourceID, pl.SPEntityID)
	if err != nil {
		return "", nil, fmt.Errorf("internal error")
	}
	return sessCookie, pl, nil
}

// BuildSessionCookieFromToken verifies a Cognito ID token against the identity
// source bound to the SP identified by (tenant, entityID), and returns an
// encoded saml_session cookie value for the resulting session. Used by the
// IdP-initiated flow, where there is no pending login or AuthnRequest — the
// target SP is named directly. The token's aud must equal the bound source's
// Cognito client ID. Tenant is a required input so the entityID is resolved
// only within the tenant that owns it.
func (sp *SessionProvider) BuildSessionCookieFromToken(ctx context.Context, tenantSlug, entityID, token string) (string, error) {
	if sp.apps == nil || sp.sources == nil {
		return "", fmt.Errorf("token authentication not configured")
	}
	source, err := sp.resolveSource(ctx, tenantSlug, entityID)
	if err != nil {
		return "", fmt.Errorf("unable to resolve identity provider")
	}
	if source.PoolID == "" || source.Region == "" {
		return "", fmt.Errorf("identity source does not support token authentication")
	}
	jv, jvErr := sp.verifierFor(source.PoolID, source.Region)
	if jvErr != nil {
		return "", fmt.Errorf("invalid identity source configuration: %w", jvErr)
	}
	payload, err := jv.Verify(token, source.ClientID)
	if err != nil {
		return "", fmt.Errorf("invalid id token")
	}
	session := buildSessionFromClaims(cognito.ExtractClaims(payload))
	// Bind the cookie to the tenant, bound source, and target SP so the
	// IdP-initiated session is only honoured for this tenant/SP.
	return sp.encodeBoundSessionCookie(session, tenantSlug, source.ID, entityID)
}

// buildCustomLoginURL appends return_to and state query parameters to the
// configured custom login page URL, preserving any existing query string.
func buildCustomLoginURL(loginURL, returnTo, flowID string) string {
	u, err := url.Parse(loginURL)
	if err != nil {
		return loginURL
	}
	q := u.Query()
	q.Set("return_to", returnTo)
	q.Set("state", flowID)
	u.RawQuery = q.Encode()
	return u.String()
}

// buildSessionFromClaims constructs a crewsaml.Session from extracted Cognito
// claims. Shared by the Code+PKCE callback and the direct ID-token auth path.
func buildSessionFromClaims(claims *cognito.UserClaims) *crewsaml.Session {
	session := &crewsaml.Session{
		ID:            generateFlowID(),
		CreateTime:    time.Now(),
		ExpireTime:    time.Now().Add(8 * time.Hour),
		Index:         generateFlowID(),
		NameID:        claims.Email,
		NameIDFormat:  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SubjectID:     claims.Sub,
		UserName:      claims.Sub,
		UserEmail:     claims.Email,
		UserGivenName: claims.GivenName,
		UserSurname:   claims.FamilyName,
		Groups:        claims.Groups,
	}

	for k, v := range claims.CustomAttributes {
		session.CustomAttributes = append(session.CustomAttributes, crewsaml.Attribute{
			Name: k,
			Values: []crewsaml.AttributeValue{{
				Type:  "xs:string",
				Value: v,
			}},
		})
	}

	return session
}

// sessionBindingMatches reports whether a decoded session cookie's binding is
// valid to reuse for the current request.
//
//   - Tenant is ALWAYS enforced: the cookie's tenant must equal the request path
//     tenant. This is the core cross-tenant defense (a session minted under one
//     tenant's path can never be replayed under another's) and holds in every
//     flow, so it also fails a legacy/unbound cookie (tenant "") closed on any
//     real /t/{tenant} path.
//   - SP is enforced only when BOTH the cookie carries an SP binding and the
//     request already knows its target SP. In the SP-initiated flow crewjam
//     populates req.ServiceProviderMetadata before calling GetSession, so the SP
//     is compared and a session minted for another SP in the same tenant is
//     rejected. In the IdP-initiated flow crewjam calls GetSession *before*
//     resolving the SP (metadata is nil), and the cookie was just minted and
//     injected for this exact request by HandleIdPInitiate, so skipping the SP
//     comparison there is safe and avoids breaking that flow.
func (sp *SessionProvider) sessionBindingMatches(r *http.Request, req *crewsaml.IdpAuthnRequest, env sessionEnvelope) bool {
	if env.TenantSlug != chi.URLParam(r, "tenant") {
		return false
	}
	var targetSP string
	if req != nil && req.ServiceProviderMetadata != nil {
		targetSP = req.ServiceProviderMetadata.EntityID
	}
	if env.SPEntityID != "" && targetSP != "" && env.SPEntityID != targetSP {
		return false
	}
	return true
}

// --- Cookie encoding helpers ---

func (sp *SessionProvider) signedEncode(state *flowState) (string, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return sp.signedCookie.Encode(data)
}

func (sp *SessionProvider) signedDecode(raw string) (*flowState, error) {
	data, err := sp.signedCookie.Decode(raw)
	if err != nil {
		return nil, err
	}
	var state flowState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// encodeBoundSessionCookie marshals the session together with the
// tenant/source/SP binding it was minted for and returns the signed cookie
// value. GetSession later refuses to reuse the cookie unless the request's
// tenant and target SP match this binding.
func (sp *SessionProvider) encodeBoundSessionCookie(session *crewsaml.Session, tenantSlug, sourceID, spEntityID string) (string, error) {
	env := &sessionEnvelope{
		Session:    session,
		TenantSlug: tenantSlug,
		SourceID:   sourceID,
		SPEntityID: spEntityID,
	}
	data, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return sp.signedCookie.Encode(data)
}

// encodeSessionCookie encodes an unbound session cookie. It exists for callers
// (and tests) that have no binding context; production mint sites use
// encodeBoundSessionCookie so the cookie is scoped to its tenant/source/SP.
func (sp *SessionProvider) encodeSessionCookie(session *crewsaml.Session) (string, error) {
	return sp.encodeBoundSessionCookie(session, "", "", "")
}

// decodeSessionEnvelope decodes and verifies the signed session cookie,
// returning the session together with the tenant/source/SP it is bound to. An
// expired session is rejected. A legacy cookie that marshalled a bare
// crewsaml.Session (no envelope) has no "session" field, so it fails the nil
// check below and is rejected outright — GetSession then falls through to fresh
// authentication. This fails closed: an unbindable cookie is never honoured.
func (sp *SessionProvider) decodeSessionEnvelope(raw string) (*crewsaml.Session, sessionEnvelope, error) {
	data, err := sp.signedCookie.Decode(raw)
	if err != nil {
		return nil, sessionEnvelope{}, err
	}

	var env sessionEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, sessionEnvelope{}, err
	}
	if env.Session == nil {
		return nil, sessionEnvelope{}, fmt.Errorf("session cookie missing session")
	}

	if time.Now().After(env.Session.ExpireTime) {
		return nil, sessionEnvelope{}, fmt.Errorf("session expired")
	}

	return env.Session, env, nil
}

// decodeSessionCookie decodes the signed session cookie and returns the
// embedded session, discarding the binding. Retained for callers that only need
// the session; GetSession uses decodeSessionEnvelope so it can enforce the
// binding.
func (sp *SessionProvider) decodeSessionCookie(raw string) (*crewsaml.Session, error) {
	session, _, err := sp.decodeSessionEnvelope(raw)
	return session, err
}

// generateFlowID returns a random hex string for use as flow/session IDs.
func generateFlowID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate flow ID: %v", err))
	}
	return hex.EncodeToString(b)
}
