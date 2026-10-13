package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	proxycrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

const (
	// oidcFlowCookieName holds the OIDC login flow state during the Cognito redirect.
	oidcFlowCookieName = "oidc_flow"
	// oidcFlowCookieMaxAge is the maximum age of the flow cookie (10 minutes).
	oidcFlowCookieMaxAge = 600
	// oidcLoginBindingCookieName binds a REPLACE-mode custom-login flow to the
	// browser that started it (finding M-4). Set when the user is redirected to
	// the custom login page; must be presented with a FlowID equal to the echoed
	// `state` on the hand-back to /oidc/login/complete. Without it an attacker
	// could post their own id_token + a victim's state into the victim's browser
	// and log the victim in as the attacker (login CSRF / session fixation).
	//
	// __Host- prefix: Secure, Path=/, no Domain. SameSite=None: the hand-back is
	// a cross-site top-level POST from the custom login page, which browsers do
	// not send Lax cookies on; the signed nonce <-> state comparison is the
	// security control, not SameSite.
	oidcLoginBindingCookieName = "__Host-oidc_login"
)

// oidcLoginBinding is the signed payload of the login-binding cookie.
type oidcLoginBinding struct {
	FlowID    string `json:"fid"`
	CreatedAt int64  `json:"ca"`
}

var (
	errLoginBindingMissing  = errors.New("login binding cookie missing")
	errLoginBindingInvalid  = errors.New("login binding cookie invalid")
	errLoginBindingMismatch = errors.New("login binding cookie does not match this flow")
	errLoginBindingExpired  = errors.New("login binding cookie expired")
)

// setLoginBindingCookie mints the signed __Host-oidc_login cookie for flowID.
func (h *LoginHandler) setLoginBindingCookie(w http.ResponseWriter, flowID string) error {
	data, err := json.Marshal(&oidcLoginBinding{FlowID: flowID, CreatedAt: time.Now().Unix()})
	if err != nil {
		return err
	}
	val, err := h.signedCookie.Encode(data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcLoginBindingCookieName,
		Value:    val,
		Path:     "/",
		MaxAge:   oidcFlowCookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	return nil
}

// verifyLoginBinding checks that the request carries a valid, unexpired
// __Host-oidc_login cookie minted for flowID.
func (h *LoginHandler) verifyLoginBinding(r *http.Request, flowID string) error {
	c, err := r.Cookie(oidcLoginBindingCookieName)
	if err != nil || c.Value == "" {
		return errLoginBindingMissing
	}
	data, err := h.signedCookie.Decode(c.Value)
	if err != nil {
		return fmt.Errorf("%w: %v", errLoginBindingInvalid, err)
	}
	var b oidcLoginBinding
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("%w: %v", errLoginBindingInvalid, err)
	}
	if b.FlowID == "" || b.FlowID != flowID {
		return errLoginBindingMismatch
	}
	if time.Now().Unix()-b.CreatedAt > int64(oidcFlowCookieMaxAge) {
		return errLoginBindingExpired
	}
	return nil
}

// clearLoginBindingCookie expires the __Host-oidc_login cookie. The attributes
// must match those used when it was set or the browser will not replace it.
func clearLoginBindingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcLoginBindingCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
}

// oidcFlowState is the data persisted in the flow cookie while the user
// authenticates at Cognito during an OIDC authorization flow.
type oidcFlowState struct {
	AuthRequestID string `json:"arid"`
	Verifier      string `json:"v"`
	TenantSlug    string `json:"ts"`
	SourceID      string `json:"sid"`
	CreatedAt     int64  `json:"ca"`
}

// LoginHandler holds dependencies for the OIDC login and callback handlers.
type LoginHandler struct {
	storage      *Storage
	apps         domain.AppReader
	sources      domain.SourceReader
	audit        domain.AuditRepository
	signedCookie *proxycrypto.SignedCookie
	baseURL      string
	pendingStore *store.PendingLoginStore

	// verifierFactory builds an ID-token verifier for a Cognito pool. Defaults
	// to a JWKS-backed verifier; overridable in tests.
	verifierFactory func(poolID, region string) idTokenVerifier
}

// idTokenVerifier verifies a Cognito ID token's signature and claims.
// *cognito.JWKSVerifier satisfies this interface.
type idTokenVerifier interface {
	Verify(tokenString, expectedClientID string) (map[string]interface{}, error)
}

// verifierFor returns an ID-token verifier for the given Cognito pool, or an
// error when poolID/region fail format validation. Validation prevents host
// injection via attacker-controlled tenant configuration (MF-6).
func (h *LoginHandler) verifierFor(poolID, region string) (idTokenVerifier, error) {
	if h.verifierFactory != nil {
		return h.verifierFactory(poolID, region), nil
	}
	return cognito.NewJWKSVerifier(poolID, region)
}

// LoginHandlerOption customizes a LoginHandler.
type LoginHandlerOption func(*LoginHandler)

// WithVerifierFactory overrides the ID-token verifier factory. Production leaves
// this unset so the default JWKS-backed verifier is used; it exists so callers
// outside this package (notably the root-package e2e suite, which cannot reach
// an unexported field) can inject a stub verifier for a mock Cognito pool.
func WithVerifierFactory(factory func(poolID, region string) cognito.IDTokenVerifier) LoginHandlerOption {
	return func(h *LoginHandler) {
		h.verifierFactory = func(poolID, region string) idTokenVerifier {
			return factory(poolID, region)
		}
	}
}

// NewLoginHandler creates a new LoginHandler. It returns an error if hmacKey
// is non-nil but not exactly 32 bytes (see crypto.ErrCookieKeyTooShort). Pass
// nil as hmacKey when the handler is constructed for a Lambda that does not
// serve login/callback routes; Encode/Decode will return ErrCookieSigningDisabled
// so any mis-routed request fails closed instead of operating under a weak key.
func NewLoginHandler(storage *Storage, apps domain.AppReader, sources domain.SourceReader, audit domain.AuditRepository, hmacKey []byte, baseURL string, pendingStore *store.PendingLoginStore, opts ...LoginHandlerOption) (*LoginHandler, error) {
	sc, err := proxycrypto.NewSignedCookie(hmacKey, proxycrypto.CookiePurposeOIDC)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise signed-cookie: %w", err)
	}
	h := &LoginHandler{
		storage:      storage,
		apps:         apps,
		sources:      sources,
		audit:        audit,
		signedCookie: sc,
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		pendingStore: pendingStore,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// HandleLogin handles GET /t/{tenant}/oidc/login?authRequestID=...
//
// It loads the OIDC AuthRequest, resolves the app's identity source, generates
// PKCE parameters, stores flow state in a signed cookie, and redirects the user
// to the Cognito hosted UI for authentication.
func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	if authRequestID == "" {
		http.Error(w, "missing authRequestID", http.StatusBadRequest)
		return
	}

	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Load the auth request from storage.
	authReq, err := h.storage.AuthRequestByID(ctx, authRequestID)
	if err != nil {
		slog.Error("failed to load auth request", "error", err, "authRequestID", authRequestID)
		http.Error(w, "auth request not found", http.StatusNotFound)
		return
	}

	// Look up the OIDC app. The ClientID on the auth request IS the app ID.
	clientID := authReq.GetClientID()
	app, err := h.apps.Get(ctx, tenantSlug, clientID)
	if err != nil {
		slog.Error("failed to load application", "error", err, "clientID", clientID, "tenant", tenantSlug)
		http.Error(w, "application not found", http.StatusNotFound)
		return
	}

	// REPLACE-mode custom login: if the app has a custom login page, redirect
	// there instead of to the Cognito Hosted UI. The page authenticates the
	// user and posts an ID token back to the OIDC session-establish endpoint.
	if app.HasCustomLogin() && h.pendingStore != nil {
		if !app.IsTrustedLoginRedirect(app.CustomLoginURL) {
			slog.Error("custom login: configured URL not in trusted allowlist",
				"clientID", clientID, "customLoginUrl", app.CustomLoginURL)
			http.Error(w, "custom login page is not a trusted redirect target", http.StatusInternalServerError)
			return
		}
		flowID := newFlowID()
		pending := &store.PendingLogin{
			FlowID:        flowID,
			Protocol:      "oidc",
			TenantSlug:    tenantSlug,
			SourceID:      app.SourceID,
			AppID:         app.ID,
			AuthRequestID: authRequestID,
		}
		if err := h.pendingStore.Create(ctx, pending, oidcFlowCookieMaxAge*time.Second); err != nil {
			slog.Error("custom login: failed to store pending login", "error", err, "clientID", clientID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if h.audit != nil {
			_ = h.audit.LogStep(ctx, tenantSlug, authRequestID, "oidc_custom_login_redirect", clientID, "",
				map[string]string{"tenant": tenantSlug})
		}
		// Bind this flow to the browser we are about to redirect (M-4): the
		// hand-back to /oidc/login/complete must carry this cookie with the same
		// flow ID as the echoed `state`.
		if err := h.setLoginBindingCookie(w, flowID); err != nil {
			slog.Error("custom login: failed to set login binding cookie", "error", err, "clientID", clientID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		returnTo := h.baseURL + "/t/" + tenantSlug + "/oidc/login/complete"
		// Destination is validated above via app.IsTrustedLoginRedirect against
		// the per-app trusted-redirect allowlist, so it cannot be an arbitrary host.
		// nosemgrep: open-redirect
		http.Redirect(w, r, buildCustomLoginURL(app.CustomLoginURL, returnTo, flowID), http.StatusFound)
		return
	}

	// Load the identity source for this app.
	source, err := h.sources.Get(ctx, tenantSlug, app.SourceID)
	if err != nil {
		slog.Error("failed to load identity source", "error", err, "sourceID", app.SourceID, "tenant", tenantSlug)
		http.Error(w, "identity source not found", http.StatusInternalServerError)
		return
	}

	// Build callback URL scoped to the tenant.
	callbackURL := h.baseURL + "/t/" + tenantSlug + "/oidc/callback"
	authClient, err := cognito.NewAuthClientForSource(ctx, source, callbackURL, cognito.NoSecretFetcher)
	if err != nil {
		slog.Error("failed to create auth client", "error", err, "sourceID", source.ID, "tenant", tenantSlug)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Generate PKCE verifier and challenge.
	verifier, challenge := authClient.GeneratePKCE()

	// Build flow state for the cookie.
	state := &oidcFlowState{
		AuthRequestID: authRequestID,
		Verifier:      verifier,
		TenantSlug:    tenantSlug,
		SourceID:      source.ID,
		CreatedAt:     time.Now().Unix(),
	}

	// Encode and sign the flow cookie.
	cookieValue, err := h.signedEncode(state)
	if err != nil {
		slog.Error("failed to encode flow cookie", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookieName,
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   oidcFlowCookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to Cognito authorization endpoint.
	// Use authRequestID as the OAuth2 state parameter for CSRF protection.
	// authURL is the Cognito Hosted UI authorization endpoint, built from the
	// server-side identity-source configuration (not from user-supplied input).
	authURL := authClient.AuthorizationURL(authRequestID, challenge)

	slog.Debug("OIDC login: redirecting to Cognito",
		"tenant", tenantSlug,
		"authRequestID", authRequestID,
		"cognitoDomain", source.Domain,
	)

	// Audit: OIDC login initiated
	if h.audit != nil {
		_ = h.audit.LogStep(r.Context(), tenantSlug, authRequestID, "oidc_login_initiated", authReq.GetClientID(), "", map[string]string{
			"tenant": tenantSlug,
		})
	}

	// nosemgrep: open-redirect
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback handles GET /t/{tenant}/oidc/callback?code=...&state=...
//
// It verifies the flow cookie, exchanges the authorization code for tokens via
// Cognito, completes the OIDC AuthRequest in storage, and redirects back to the
// zitadel/oidc authorize endpoint so it can issue the authorization code to the RP.
func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	callbackState := r.URL.Query().Get("state")
	if callbackState == "" {
		http.Error(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	// Load flow state from cookie.
	cookie, err := r.Cookie(oidcFlowCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing flow cookie", http.StatusBadRequest)
		return
	}

	flowState, err := h.signedDecode(cookie.Value)
	if err != nil {
		slog.Error("failed to decode flow cookie", "error", err)
		http.Error(w, "invalid flow cookie", http.StatusBadRequest)
		return
	}

	// Check expiry (10 minutes).
	if time.Now().Unix()-flowState.CreatedAt > int64(oidcFlowCookieMaxAge) {
		http.Error(w, "flow expired", http.StatusBadRequest)
		return
	}

	// CSRF protection: verify state matches the auth request ID from the cookie.
	if callbackState != flowState.AuthRequestID {
		http.Error(w, "state parameter mismatch", http.StatusForbidden)
		return
	}

	tenantSlug := flowState.TenantSlug
	ctx := r.Context()

	// Load the identity source to recreate the auth client.
	source, err := h.sources.Get(ctx, tenantSlug, flowState.SourceID)
	if err != nil {
		slog.Error("failed to load identity source for callback", "error", err,
			"tenantSlug", tenantSlug, "sourceID", flowState.SourceID)
		http.Error(w, "unable to resolve identity provider", http.StatusInternalServerError)
		return
	}

	callbackURL := h.baseURL + "/t/" + tenantSlug + "/oidc/callback"
	authClient, err := cognito.NewAuthClientForSource(ctx, source, callbackURL, cognito.NoSecretFetcher)
	if err != nil {
		slog.Error("failed to create auth client for callback", "error", err, "sourceID", source.ID, "tenant", tenantSlug)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Exchange authorization code for tokens.
	idToken, err := authClient.ExchangeCode(ctx, code, flowState.Verifier)
	if err != nil {
		slog.Error("token exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	// Verify the ID token's RS256 signature via the pool's JWKS and validate
	// its iss/aud/exp/token_use claims in-process, rather than trusting the
	// token because it arrived over the token-exchange TLS connection. This
	// mirrors the custom-login path's verification, so a tampered or
	// wrong-audience token is rejected instead of decoded and accepted.
	if source.PoolID == "" || source.Region == "" {
		slog.Error("callback: identity source missing poolID/region; cannot verify id token",
			"sourceID", source.ID, "tenant", tenantSlug)
		http.Error(w, "unable to verify id token", http.StatusInternalServerError)
		return
	}
	jv, err := h.verifierFor(source.PoolID, source.Region)
	if err != nil {
		slog.Warn("callback: invalid identity source pool ID or region", "error", err, "tenant", tenantSlug)
		http.Error(w, "invalid identity source configuration", http.StatusBadRequest)
		return
	}
	payload, err := jv.Verify(idToken, source.ClientID)
	if err != nil {
		slog.Warn("callback: id token verification failed", "error", err, "tenant", tenantSlug)
		http.Error(w, "invalid id token", http.StatusBadGateway)
		return
	}

	claims := cognito.ExtractClaims(payload)

	// Complete the auth request in storage with full Cognito claims.
	if err := h.storage.CompleteAuthRequest(ctx, flowState.AuthRequestID, claims.Sub, claims.Email, claims.GivenName, claims.FamilyName, claims.EmailVerified, claims.Groups); err != nil {
		slog.Error("failed to complete auth request", "error", err,
			"authRequestID", flowState.AuthRequestID)
		http.Error(w, "failed to complete auth request", http.StatusInternalServerError)
		return
	}

	slog.Info("OIDC login completed",
		"tenant", tenantSlug,
		"authRequestID", flowState.AuthRequestID,
		"userID", claims.Sub,
	)

	// Audit: OIDC login completed
	if h.audit != nil {
		_ = h.audit.LogStep(ctx, tenantSlug, flowState.AuthRequestID, "oidc_login_complete", source.ClientID, claims.Email, map[string]string{
			"status": "success",
			"tenant": tenantSlug,
			"sub":    claims.Sub,
		})
	}

	// Clear the flow cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect back to the zitadel/oidc authorize endpoint so it picks up the
	// completed AuthRequest and issues the authorization code to the RP.
	// Destination is built from the server-side base URL, the cookie-bound tenant
	// slug, and a URL-escaped request ID — the host is not user-controlled.
	redirectURL := h.baseURL + "/t/" + tenantSlug + "/oidc/authorize/callback?id=" + url.QueryEscape(flowState.AuthRequestID)
	// nosemgrep: open-redirect
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleLoginRedirect handles GET /login?authRequestID=...
//
// This is the root-level handler that zitadel/oidc redirects to (via Client.LoginURL).
// It loads the auth request to find the tenant slug, then redirects to the
// tenant-scoped login handler.
func (h *LoginHandler) HandleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	if authRequestID == "" {
		http.Error(w, "missing authRequestID", http.StatusBadRequest)
		return
	}

	authReq, err := h.storage.AuthRequestByID(r.Context(), authRequestID)
	if err != nil {
		slog.Error("failed to load auth request for login redirect", "error", err, "authRequestID", authRequestID)
		http.Error(w, "auth request not found", http.StatusNotFound)
		return
	}

	// Extract tenant slug from the auth request.
	concreteReq, ok := authReq.(*AuthRequest)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tenantSlug := concreteReq.TenantSlug
	if tenantSlug == "" {
		// Fall back: try to resolve tenant from the client (app).
		// The ClientID is the app ID, but without a tenant we cannot look it up
		// directly. Use a default tenant as last resort.
		tenantSlug = "default"
		slog.Warn("auth request missing tenant slug, using default",
			"authRequestID", authRequestID)
	}

	// Relative, same-origin path (leading "/t/…"); the tenant slug comes from the
	// stored auth request and the request ID is URL-escaped — no external host.
	redirectURL := fmt.Sprintf("/t/%s/oidc/login?authRequestID=%s",
		tenantSlug, url.QueryEscape(authRequestID))
	// nosemgrep: open-redirect
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// --- Cookie encoding helpers ---

func (h *LoginHandler) signedEncode(state *oidcFlowState) (string, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return h.signedCookie.Encode(data)
}

func (h *LoginHandler) signedDecode(raw string) (*oidcFlowState, error) {
	data, err := h.signedCookie.Decode(raw)
	if err != nil {
		return nil, err
	}
	var state oidcFlowState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// HandleLoginComplete handles POST /t/{tenant}/oidc/login/complete — the OIDC
// session-establish endpoint for the custom login page flow. The custom page
// authenticates the user and posts the Cognito ID token here (Authorization:
// Bearer header, or an `id_token` form field for a cross-origin browser POST),
// echoing `state` (the pending-login flow ID). The gateway verifies the token
// against the bound identity source, completes the stored AuthRequest, and
// redirects to the authorize callback so the RP receives its authorization code.
func (h *LoginHandler) HandleLoginComplete(w http.ResponseWriter, r *http.Request) {
	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if h.pendingStore == nil {
		http.Error(w, "custom login not configured", http.StatusInternalServerError)
		return
	}

	token := bearerToken(r)
	if token == "" {
		token = strings.TrimSpace(r.PostFormValue("id_token"))
	}
	if token == "" {
		http.Error(w, "missing id token", http.StatusBadRequest)
		return
	}

	flowID := r.URL.Query().Get("state")
	if flowID == "" {
		flowID = strings.TrimSpace(r.PostFormValue("state"))
	}
	if flowID == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	// M-4: the completion must come from the browser that was redirected to
	// the custom login page. Verify BEFORE touching the pending login so a
	// forged post (attacker's id_token + victim's state) neither consumes it
	// nor completes the AuthRequest; the legitimate browser can still finish.
	// Bearer is not exempt here: the attack is a browser post and Bearer is
	// merely an alternative token carrier for the same hand-back.
	if err := h.verifyLoginBinding(r, flowID); err != nil {
		slog.Warn("custom login: flow not bound to this browser", "error", err, "tenant", tenantSlug)
		http.Error(w, "login flow not bound to this browser", http.StatusForbidden)
		return
	}

	ctx := r.Context()
	pl, err := h.pendingStore.Get(ctx, flowID)
	if err != nil || pl.Protocol != "oidc" {
		http.Error(w, "invalid or expired login flow", http.StatusBadRequest)
		return
	}
	if pl.TenantSlug != tenantSlug {
		http.Error(w, "tenant mismatch", http.StatusBadRequest)
		return
	}
	// Single-use.
	_ = h.pendingStore.Delete(ctx, flowID)
	// The binding has done its job; drop it so it cannot be replayed.
	clearLoginBindingCookie(w)

	source, err := h.sources.Get(ctx, pl.TenantSlug, pl.SourceID)
	if err != nil {
		slog.Error("custom login: failed to load identity source", "error", err, "sourceID", pl.SourceID)
		http.Error(w, "unable to resolve identity provider", http.StatusInternalServerError)
		return
	}
	if source.PoolID == "" || source.Region == "" {
		http.Error(w, "identity source does not support token authentication", http.StatusBadRequest)
		return
	}

	jv, jvErr := h.verifierFor(source.PoolID, source.Region)
	if jvErr != nil {
		slog.Warn("custom login: invalid identity source pool ID or region", "error", jvErr, "tenant", tenantSlug)
		http.Error(w, "invalid identity source configuration", http.StatusBadRequest)
		return
	}
	payload, err := jv.Verify(token, source.ClientID)
	if err != nil {
		slog.Warn("custom login: token verification failed", "error", err, "tenant", tenantSlug)
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return
	}

	claims := cognito.ExtractClaims(payload)
	if err := h.storage.CompleteAuthRequest(ctx, pl.AuthRequestID, claims.Sub, claims.Email, claims.GivenName, claims.FamilyName, claims.EmailVerified, claims.Groups); err != nil {
		slog.Error("custom login: failed to complete auth request", "error", err, "authRequestID", pl.AuthRequestID)
		http.Error(w, "failed to complete auth request", http.StatusInternalServerError)
		return
	}

	if h.audit != nil {
		_ = h.audit.LogStep(ctx, pl.TenantSlug, pl.AuthRequestID, "oidc_login_complete", source.ClientID, claims.Email, map[string]string{
			"status": "success",
			"method": "custom_login",
			"tenant": pl.TenantSlug,
			"sub":    claims.Sub,
		})
	}

	// Built from the server-side base URL, the validated tenant slug, and a
	// URL-escaped request ID — the host is not user-controlled.
	redirectURL := h.baseURL + "/t/" + tenantSlug + "/oidc/authorize/callback?id=" + url.QueryEscape(pl.AuthRequestID)
	// nosemgrep: open-redirect
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// buildCustomLoginURL appends return_to + state query parameters to the
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

// bearerToken extracts a token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// newFlowID returns a random hex string used as an opaque pending-login flow ID.
func newFlowID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate flow ID: %v", err))
	}
	return hex.EncodeToString(b)
}
