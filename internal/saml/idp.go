package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	proxycrypto "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// IdPConfig holds the configuration needed to create a SAML Identity Provider.
type IdPConfig struct {
	EntityID    string
	BaseURL     string
	Signer      crypto.Signer
	Certificate *x509.Certificate
	SPProvider  *SPProvider
	SessionProv *SessionProvider
	AssertMaker *CustomAssertionMaker
}

// NewIdentityProvider creates and configures a crewjam/saml IdentityProvider.
func NewIdentityProvider(cfg IdPConfig) (*saml.IdentityProvider, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", cfg.BaseURL, err)
	}

	metadataURL := *base
	metadataURL.Path = "/saml/metadata"

	ssoURL := *base
	ssoURL.Path = "/saml/sso"

	logoutURL := *base
	logoutURL.Path = "/saml/slo"

	idp := &saml.IdentityProvider{
		Key:                     cfg.Signer,
		Signer:                  cfg.Signer,
		Certificate:             cfg.Certificate,
		Logger:                  log.Default(),
		MetadataURL:             metadataURL,
		SSOURL:                  ssoURL,
		LogoutURL:               logoutURL,
		ServiceProviderProvider: cfg.SPProvider,
		SessionProvider:         cfg.SessionProv,
		AssertionMaker:          cfg.AssertMaker,
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	// Wire the IdP back into the session provider so the callback can resume
	// the SSO flow.
	if cfg.SessionProv != nil {
		cfg.SessionProv.SetIDP(idp)
	}

	return idp, nil
}

// RegisterRoutes registers the SAML IdP HTTP handlers on the given mux.
// Kept for backward compatibility.
func RegisterRoutes(mux *http.ServeMux, idp *saml.IdentityProvider, sessionProv *SessionProvider) {
	mux.HandleFunc("GET /saml/metadata", idp.ServeMetadata)
	mux.HandleFunc("GET /saml/sso", idp.ServeSSO)
	mux.HandleFunc("POST /saml/sso", idp.ServeSSO)
	mux.HandleFunc("GET /saml/acs", sessionProv.HandleCallback)
	mux.HandleFunc("POST /saml/acs", sessionProv.HandleCallback)
	// SLO is Task 12
}

// TenantSignerFactory creates a KMSSigner for a given KMS key ID. This is used
// to create per-tenant signers when a tenant has a custom signing key configured.
type TenantSignerFactory func(kmsKeyID string) (*proxycrypto.KMSSigner, error)

// TenantIdPHandler provides tenant-scoped SAML IdP endpoints. It creates a
// per-request crewjam/saml.IdentityProvider with the correct tenant-scoped
// URLs (metadata, SSO, SLO). Supports per-tenant KMS signing keys via a
// cached signer map.
type TenantIdPHandler struct {
	signer        crypto.Signer
	certificate   *x509.Certificate
	certStore     *proxycrypto.CertStore
	spProvider    *SPProvider
	sessionProv   *SessionProvider
	assertMaker   *CustomAssertionMaker
	baseURL       string
	signerFactory TenantSignerFactory
	signerCache   sync.Map // map[string]*tenantSignerEntry
	tenants       domain.TenantReader
	apps          domain.AppReader
	claims        domain.ClaimRepository
}

// tenantSignerEntry holds a cached per-tenant signer and certificate.
type tenantSignerEntry struct {
	signer crypto.Signer
	cert   *x509.Certificate
}

// TenantIdPOption is a functional option for configuring TenantIdPHandler.
type TenantIdPOption func(*TenantIdPHandler)

// WithSigner sets the crypto signer for the IdP handler.
func WithSigner(s crypto.Signer) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.signer = s }
}

// WithCertificate sets the X.509 certificate for the IdP handler.
func WithCertificate(c *x509.Certificate) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.certificate = c }
}

// WithCertStore sets the certificate store for publishing all available
// certificates (active + next) in SAML metadata during key rotation.
func WithCertStore(cs *proxycrypto.CertStore) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.certStore = cs }
}

// WithSPProvider sets the SP metadata provider for the IdP handler.
func WithSPProvider(p *SPProvider) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.spProvider = p }
}

// WithSessionProvider sets the session provider for the IdP handler.
func WithSessionProvider(p *SessionProvider) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.sessionProv = p }
}

// WithAssertionMaker sets the custom assertion maker for the IdP handler.
func WithAssertionMaker(m *CustomAssertionMaker) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.assertMaker = m }
}

// WithBaseURL sets the base URL for tenant-scoped endpoints.
func WithBaseURL(url string) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.baseURL = url }
}

// WithTenantReader sets the tenant reader for the IdP handler.
func WithTenantReader(t domain.TenantReader) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.tenants = t }
}

// WithAppReader sets the app reader for the IdP handler.
func WithAppReader(a domain.AppReader) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.apps = a }
}

// WithClaimRepository sets the claim repository for the IdP handler.
func WithClaimRepository(c domain.ClaimRepository) TenantIdPOption {
	return func(h *TenantIdPHandler) { h.claims = c }
}

// NewTenantIdPHandler creates a new TenantIdPHandler with functional options.
func NewTenantIdPHandler(opts ...TenantIdPOption) *TenantIdPHandler {
	h := &TenantIdPHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// SetSignerFactory configures a factory for creating per-tenant KMS signers.
// When set, tenants with a custom KMSKeyID will use a dedicated signing key.
func (h *TenantIdPHandler) SetSignerFactory(factory TenantSignerFactory) {
	h.signerFactory = factory
}

// getTenantSigner returns a cached per-tenant signer and certificate, or
// creates one if the tenant has a custom KMS key and a signer factory is set.
// Falls back to the gateway-level signer if no custom key is configured.
func (h *TenantIdPHandler) getTenantSigner(kmsKeyID, entityID string) (crypto.Signer, *x509.Certificate) {
	if kmsKeyID == "" || h.signerFactory == nil {
		return h.signer, h.certificate
	}

	// Check cache
	if cached, ok := h.signerCache.Load(kmsKeyID); ok {
		entry := cached.(*tenantSignerEntry)
		return entry.signer, entry.cert
	}

	// Create new signer for this tenant
	kmsSigner, err := h.signerFactory(kmsKeyID)
	if err != nil {
		slog.Error("failed to create tenant-specific signer, falling back to gateway signer",
			"kmsKeyId", kmsKeyID,
			"error", err,
		)
		return h.signer, h.certificate
	}

	// Generate a certificate for this tenant signer
	cert, err := proxycrypto.GenerateSelfSignedCert(kmsSigner, entityID)
	if err != nil {
		slog.Error("failed to generate tenant certificate, falling back to gateway signer",
			"kmsKeyId", kmsKeyID,
			"error", err,
		)
		return h.signer, h.certificate
	}

	entry := &tenantSignerEntry{signer: kmsSigner, cert: cert}
	h.signerCache.Store(kmsKeyID, entry)

	slog.Info("created per-tenant signer", "kmsKeyId", kmsKeyID)
	return kmsSigner, cert
}

// ServeMetadata handles GET /t/{tenant}/saml/metadata.
func (h *TenantIdPHandler) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}

	// Validate that the tenant exists
	if h.tenants != nil {
		if _, err := h.tenants.Get(r.Context(), tenantSlug); err != nil {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
	}

	idp := h.buildIdP(tenantSlug)
	meta := idp.Metadata()

	// Append additional certificates (e.g. pre-staged next cert) so SPs can
	// pre-load them before rotation.
	h.appendExtraCerts(r, meta)

	buf, _ := xml.MarshalIndent(meta, "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if _, err := w.Write(buf); err != nil {
		slog.Error("failed to write metadata response", "error", err)
	}
}

// appendExtraCerts adds KeyDescriptor elements for any additional certificates
// (e.g. the pre-staged next cert during rotation) to the metadata. The active
// cert is already included by the crewjam/saml IdentityProvider; this method
// only appends certs beyond the first one returned by CertStore.GetAllCerts.
func (h *TenantIdPHandler) appendExtraCerts(r *http.Request, meta *saml.EntityDescriptor) {
	if h.certStore == nil {
		return
	}
	if len(meta.IDPSSODescriptors) == 0 {
		return
	}

	allCerts, err := h.certStore.GetAllCerts(r.Context())
	if err != nil {
		slog.Warn("failed to fetch certificates from cert store", "error", err)
		return
	}

	// The first cert (active) is already in the metadata via the IdP's
	// Certificate field. Append any remaining certs (typically the next cert).
	for _, cert := range allCerts[1:] {
		meta.IDPSSODescriptors[0].KeyDescriptors = append(
			meta.IDPSSODescriptors[0].KeyDescriptors,
			saml.KeyDescriptor{
				Use: "signing",
				KeyInfo: saml.KeyInfo{
					X509Data: saml.X509Data{
						X509Certificates: []saml.X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(cert.Raw)},
						},
					},
				},
			},
		)
	}
}

// ServeAppMetadata handles GET /t/{tenant}/saml/metadata/{appId}.
// Returns app-specific SAML IdP metadata including claim mappings as attributes.
func (h *TenantIdPHandler) ServeAppMetadata(w http.ResponseWriter, r *http.Request) {
	tenantSlug := chi.URLParam(r, "tenant")
	appID := chi.URLParam(r, "appId")
	if tenantSlug == "" || appID == "" {
		http.Error(w, "missing tenant or appId", http.StatusBadRequest)
		return
	}

	// Load application and SAML config
	app, err := h.apps.Get(r.Context(), tenantSlug, appID)
	if err != nil {
		slog.Error("failed to load app for metadata",
			"tenant", tenantSlug,
			"appId", appID,
			"error", err,
		)
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}

	samlCfg, err := h.apps.GetSAMLConfig(r.Context(), tenantSlug, appID)
	if err != nil {
		slog.Error("failed to load SAML config for metadata",
			"tenant", tenantSlug,
			"appId", appID,
			"error", err,
		)
		http.Error(w, "SAML config not found", http.StatusNotFound)
		return
	}

	// Load claim mappings
	claims, err := h.claims.GetClaimMappings(r.Context(), tenantSlug, appID)
	if err != nil {
		slog.Warn("failed to load claim mappings for metadata, continuing without attributes",
			"tenant", tenantSlug,
			"appId", appID,
			"error", err,
		)
		// Continue with empty claims - not a fatal error
		claims = []tenant.ClaimMapping{}
	}

	// Build IdP with tenant-scoped URLs
	idp := h.buildIdP(tenantSlug)
	meta := idp.Metadata()

	// Append additional certificates for rotation support
	h.appendExtraCerts(r, meta)

	buf, _ := xml.MarshalIndent(meta, "", "  ")
	baseXML := string(buf)

	// Build attribute elements from claim mappings
	var attrXML strings.Builder
	if len(claims) > 0 {
		attrXML.WriteString("\n    <!-- Attributes released to ")
		attrXML.WriteString(html.EscapeString(app.DisplayName))
		attrXML.WriteString(" -->\n")
		for _, claim := range claims {
			// Include the attribute in the metadata to indicate what will be released
			fmt.Fprintf(&attrXML, `    <saml:Attribute Name="%s" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>`,
				html.EscapeString(claim.TargetAttribute))
			attrXML.WriteString("\n")
		}
	}

	// Also include NameIDFormat from SAML config
	var nameIDXML strings.Builder
	if samlCfg.NameIDFormat != "" {
		nameIDXML.WriteString("\n    <md:NameIDFormat>")
		nameIDXML.WriteString(html.EscapeString(samlCfg.NameIDFormat))
		nameIDXML.WriteString("</md:NameIDFormat>")
	}

	// Inject app-specific elements before </IDPSSODescriptor>
	// Order: NameIDFormat, then Attributes
	insertion := nameIDXML.String() + attrXML.String()
	if insertion != "" {
		modified := strings.Replace(baseXML, "</IDPSSODescriptor>", insertion+"  </IDPSSODescriptor>", 1)
		baseXML = modified
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(baseXML))
}

// ServeSSO handles GET/POST /t/{tenant}/saml/sso.
func (h *TenantIdPHandler) ServeSSO(w http.ResponseWriter, r *http.Request) {
	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}

	// Validate that the tenant exists
	if h.tenants != nil {
		if _, err := h.tenants.Get(r.Context(), tenantSlug); err != nil {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
	}

	// Build a tenant-scoped IdP for this request only. The session provider
	// resumes the OAuth2 callback through a per-tenant IdP factory wired once at
	// route registration (see RegisterTenantRoutes), so we deliberately do NOT
	// mutate any shared IdP reference here. Mutating a shared reference per
	// request is a data race that could let a concurrent flow for another tenant
	// hijack this callback.
	idp := h.buildIdP(tenantSlug)
	idp.ServeSSO(w, r)
}

// HandleLoginComplete handles POST /t/{tenant}/saml/login/complete — the
// session-establish endpoint for the custom login page flow. The custom page
// authenticates the user and posts the Cognito ID token here (Authorization:
// Bearer header, or an `id_token` form field for a cross-origin browser POST),
// echoing the `state` (flow ID). The gateway verifies the token against the
// pending login's bound identity source, sets the SAML session cookie, and
// resumes the original SSO flow via ServeSSO (which rebuilds the tenant IdP).
func (h *TenantIdPHandler) HandleLoginComplete(w http.ResponseWriter, r *http.Request) {
	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	token := extractBearerToken(r)
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

	sessCookie, pl, err := h.sessionProv.CompleteCustomLogin(r.Context(), flowID, token)
	if err != nil {
		// This endpoint is reachable unauthenticated, so never echo the
		// internal error (it can reveal token/flow internals). Log the detail
		// server-side under a correlation id and return a generic message.
		corrID := randomID()
		slog.Warn("custom login complete failed", "error", err, "tenant", tenantSlug, "correlationId", corrID)
		http.Error(w, "invalid login request (ref: "+corrID+")", http.StatusUnauthorized)
		return
	}
	if pl.TenantSlug != tenantSlug {
		http.Error(w, "tenant mismatch", http.StatusBadRequest)
		return
	}

	// Set the session cookie on the response so subsequent browser requests
	// carry it, and inject it into this request so the resumed ServeSSO finds
	// the session instead of starting another login.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessCookie,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Reconstruct the original SAMLRequest as a POST and resume.
	r.Method = http.MethodPost
	form := url.Values{}
	form.Set("SAMLRequest", pl.SAMLRequestB64)
	if pl.RelayState != "" {
		form.Set("RelayState", pl.RelayState)
	}
	r.PostForm = form
	r.Form = nil
	// Inbound request cookie (r.AddCookie), never written to the client, so
	// Secure/HttpOnly do not apply. The response cookie above sets both.
	// nosemgrep: cookie-missing-secure, cookie-missing-httponly
	r.AddCookie(&http.Cookie{ //nolint:gosec // internal request cookie, never sent to client
		Name:  sessionCookieName,
		Value: sessCookie,
	})

	h.ServeSSO(w, r)
}

// HandleIdPInitiate handles POST /t/{tenant}/saml/idp-initiate — IdP-initiated
// SSO. The caller (e.g. the custom UI app launcher) presents a Cognito ID token
// (Authorization: Bearer or `id_token` form field) plus the target SP's
// `entityId` and an optional `relayState`. The gateway verifies the token
// against that app's bound identity source, establishes a session, and emits an
// unsolicited SAML Response (HTTP-POST auto-submit) to the SP's ACS — no prior
// AuthnRequest required.
func (h *TenantIdPHandler) HandleIdPInitiate(w http.ResponseWriter, r *http.Request) {
	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}
	if h.tenants != nil {
		if _, err := h.tenants.Get(r.Context(), tenantSlug); err != nil {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	token := extractBearerToken(r)
	if token == "" {
		token = strings.TrimSpace(r.PostFormValue("id_token"))
	}
	if token == "" {
		http.Error(w, "missing id token", http.StatusBadRequest)
		return
	}

	entityID := strings.TrimSpace(r.PostFormValue("entityId"))
	if entityID == "" {
		entityID = strings.TrimSpace(r.URL.Query().Get("entityId"))
	}
	if entityID == "" {
		http.Error(w, "missing entityId", http.StatusBadRequest)
		return
	}
	relayState := r.PostFormValue("relayState")
	if relayState == "" {
		relayState = r.URL.Query().Get("relayState")
	}

	// Enforce the per-application opt-in. IdP-initiated SSO is disabled by
	// default and must be explicitly enabled on the SP's configuration. The
	// lookup is scoped to the tenant on the path, so an entityID is only ever
	// resolved within the tenant that owns it.
	_, samlCfg, err := h.apps.GetByTenantEntityID(r.Context(), tenantSlug, entityID)
	if err != nil || samlCfg == nil {
		http.Error(w, "unknown service provider", http.StatusNotFound)
		return
	}
	if !samlCfg.AllowIDPInitiated {
		slog.Warn("idp-initiated: not enabled for application", "entityID", entityID, "tenant", tenantSlug)
		http.Error(w, "IdP-initiated SSO is not enabled for this application", http.StatusForbidden)
		return
	}

	sessCookie, err := h.sessionProv.BuildSessionCookieFromToken(r.Context(), tenantSlug, entityID, token)
	if err != nil {
		// This endpoint is reachable unauthenticated — do not leak the internal error. Log it
		// server-side under a correlation id and return a generic message.
		corrID := randomID()
		slog.Warn("idp-initiated: token verification failed", "error", err, "entityID", entityID, "tenant", tenantSlug, "correlationId", corrID)
		http.Error(w, "invalid id token (ref: "+corrID+")", http.StatusUnauthorized)
		return
	}

	// Set the session cookie + inject it so the IdP's GetSession returns the
	// session immediately (its first check is the cookie) without trying to
	// resolve an AuthnRequest that does not exist in an IdP-initiated flow.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessCookie,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// Inbound request cookie (r.AddCookie), never written to the client, so
	// Secure/HttpOnly do not apply. The response cookie above sets both.
	// nosemgrep: cookie-missing-secure, cookie-missing-httponly
	r.AddCookie(&http.Cookie{ //nolint:gosec // internal request cookie, never sent to client
		Name:  sessionCookieName,
		Value: sessCookie,
	})

	// IdP-initiated SSO completes synchronously here (ServeIDPInitiated builds
	// and auto-posts the assertion), so the IdP is local to this request and no
	// shared reference is set — avoiding the cross-request data race.
	idp := h.buildIdP(tenantSlug)
	idp.ServeIDPInitiated(w, r, entityID, relayState)
}

// buildIdP creates a crewjam/saml.IdentityProvider with tenant-scoped URLs.
// If kmsKeyID is non-empty and a signer factory is configured, a per-tenant
// signer is used. Otherwise, the gateway-level signer is used.
func (h *TenantIdPHandler) buildIdP(tenantSlug string) *saml.IdentityProvider {
	return h.buildIdPWithKey(tenantSlug, "")
}

// buildIdPWithKey creates a crewjam/saml.IdentityProvider with tenant-scoped URLs
// and optionally uses a per-tenant KMS signing key.
func (h *TenantIdPHandler) buildIdPWithKey(tenantSlug, kmsKeyID string) *saml.IdentityProvider {
	base, err := url.Parse(h.baseURL)
	if err != nil {
		slog.Error("invalid base URL in IdP handler",
			"url", h.baseURL,
			"error", err,
			"tenant", tenantSlug,
		)
		// Return a minimal IdP to avoid panics, but it will fail when used
		return &saml.IdentityProvider{
			Key:                     h.signer,
			Signer:                  h.signer,
			Certificate:             h.certificate,
			Logger:                  log.Default(),
			ServiceProviderProvider: h.spProvider,
			SessionProvider:         h.sessionProv,
			AssertionMaker:          h.assertMaker,
		}
	}

	metadataURL := *base
	metadataURL.Path = "/t/" + tenantSlug + "/saml/metadata"

	ssoURL := *base
	ssoURL.Path = "/t/" + tenantSlug + "/saml/sso"

	sloURL := *base
	sloURL.Path = "/t/" + tenantSlug + "/saml/slo"

	// Use per-tenant signer if custom KMS key is configured
	tenantSigner, tenantCert := h.getTenantSigner(kmsKeyID, metadataURL.String())

	return &saml.IdentityProvider{
		Key:                     tenantSigner,
		Signer:                  tenantSigner,
		Certificate:             tenantCert,
		Logger:                  log.Default(),
		MetadataURL:             metadataURL,
		SSOURL:                  ssoURL,
		LogoutURL:               sloURL,
		ServiceProviderProvider: h.spProvider,
		SessionProvider:         h.sessionProv,
		AssertionMaker:          h.assertMaker,
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}
}

// TenantRoutesConfig holds configuration for tenant-scoped SAML routes.
type TenantRoutesConfig struct {
	Handler     *TenantIdPHandler
	SessionProv *SessionProvider
	Sessions    domain.SessionRepository
	Tenants     domain.TenantReader
	Apps        domain.AppReader
	Claims      domain.ClaimRepository
	Audit       domain.AuditRepository
	// Replay is the one-time-use guard for SLO LogoutRequest IDs. It mirrors the
	// AuthnRequest replay store wired into the SessionProvider.
	Replay domain.ReplayRepository
}

// RegisterTenantRoutes registers tenant-scoped SAML IdP routes on a chi router.
func RegisterTenantRoutes(r chi.Router, cfg TenantRoutesConfig) {
	// Wire dependencies into the handler if not already set
	if cfg.Handler.tenants == nil && cfg.Tenants != nil {
		cfg.Handler.tenants = cfg.Tenants
	}
	if cfg.Handler.apps == nil && cfg.Apps != nil {
		cfg.Handler.apps = cfg.Apps
	}
	if cfg.Handler.claims == nil && cfg.Claims != nil {
		cfg.Handler.claims = cfg.Claims
	}

	// Wire a per-tenant IdP factory once (not per-request). The OAuth2 callback
	// rebuilds the IdP for the tenant recorded in its signed flow state, so
	// concurrent SSO flows for different tenants never share a single mutable
	// IdP reference. Guard against a nil SessionProv for handler-only test wiring.
	if cfg.SessionProv != nil {
		handler := cfg.Handler
		cfg.SessionProv.SetIDPFactory(func(tenantSlug string) *saml.IdentityProvider {
			return handler.buildIdP(tenantSlug)
		})
	}

	sloHandler := HandleSLO(cfg.Handler.baseURL, cfg.Sessions, cfg.Apps, cfg.Audit, cfg.Replay)
	r.Route("/t/{tenant}/saml", func(r chi.Router) {
		r.Get("/metadata", cfg.Handler.ServeMetadata)
		r.Get("/metadata/{appId}", cfg.Handler.ServeAppMetadata)
		r.Get("/sso", cfg.Handler.ServeSSO)
		r.Post("/sso", cfg.Handler.ServeSSO)
		r.Post("/login/complete", cfg.Handler.HandleLoginComplete)
		r.Post("/idp-initiate", cfg.Handler.HandleIdPInitiate)
		r.Get("/acs", cfg.SessionProv.HandleCallback)
		r.Post("/acs", cfg.SessionProv.HandleCallback)
		r.Get("/slo", sloHandler)
		r.Post("/slo", sloHandler)
	})

	// Federation discovery endpoint
	r.Get("/t/{tenant}/.well-known/federation-configuration", handleFederationDiscovery(cfg.Handler.baseURL))
}

// handleFederationDiscovery returns a handler for the federation discovery endpoint.
func handleFederationDiscovery(baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantSlug := chi.URLParam(r, "tenant")
		if tenantSlug == "" {
			http.Error(w, "missing tenant", http.StatusBadRequest)
			return
		}

		tenantBase := fmt.Sprintf("%s/t/%s", baseURL, tenantSlug)

		response := map[string]interface{}{
			"tenant":              tenantSlug,
			"saml_metadata_url":   fmt.Sprintf("%s/saml/metadata", tenantBase),
			"oidc_discovery_url":  fmt.Sprintf("%s/oidc/.well-known/openid-configuration", tenantBase),
			"protocols_supported": []string{"saml2.0", "oidc"},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to encode federation discovery response",
				"error", err,
				"tenant", tenantSlug,
			)
		}
	}
}
