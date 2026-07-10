package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // exercises the legacy SHA-1 opt-in path under test (MF-3); never a default.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	internalsaml "github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/saml"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBaseURL is the server-side gateway origin used to build LogoutResponse
// issuer URLs (never derived from r.Host).
const testBaseURL = "https://idp.example.com"

// sigAlgRSASHA256 is the redirect-binding SigAlg the tests sign with.
const sigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// spSigningKey holds a test SP's signing key and its self-signed certificate
// PEM, used to sign HTTP-Redirect binding LogoutRequests.
type spSigningKey struct {
	priv    *rsa.PrivateKey
	certPEM string
}

// newSPSigningKey generates an RSA signing key + self-signed cert for a test SP.
func newSPSigningKey(t *testing.T) spSigningKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return spSigningKey{priv: priv, certPEM: string(pemBytes)}
}

// deflateAndEncode deflate-compresses and base64-encodes XML for HTTP-Redirect binding.
func deflateAndEncode(t *testing.T, xmlStr string) string {
	t.Helper()
	var buf strings.Builder
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(xmlStr))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString([]byte(buf.String()))
}

// signedRedirectQuery builds a signed HTTP-Redirect binding query string for a
// LogoutRequest, mirroring the SAML 2.0 detached-signature construction
// (bindings §3.4.4.1): the signature covers "SAMLRequest=...&RelayState=...&SigAlg=..."
// over the still-percent-encoded values, in that order.
func signedRedirectQuery(t *testing.T, key spSigningKey, xmlStr, relayState string) string {
	t.Helper()
	enc := deflateAndEncode(t, xmlStr)
	query := "SAMLRequest=" + url.QueryEscape(enc)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	query += "&SigAlg=" + url.QueryEscape(sigAlgRSASHA256)

	digest := sha256.Sum256([]byte(query))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.priv, crypto.SHA256, digest[:])
	require.NoError(t, err)
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return query
}

// buildLogoutRequest creates a SAML LogoutRequest XML string.
func buildLogoutRequest(t *testing.T, issuer, nameID, destination, sessionIndex string) string {
	t.Helper()
	req := &crewsaml.LogoutRequest{
		ID:           "_test_logout_123",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  destination,
		Issuer: &crewsaml.Issuer{
			Value: issuer,
		},
		NameID: &crewsaml.NameID{
			Value: nameID,
		},
	}
	if sessionIndex != "" {
		req.SessionIndex = &crewsaml.SessionIndex{Value: sessionIndex}
	}

	data, err := req.Bytes()
	require.NoError(t, err)
	return string(data)
}

// logoutRequestOpts overrides the fields buildLogoutRequestWith would otherwise
// default, so freshness/replay tests can control the request ID and timing.
type logoutRequestOpts struct {
	id           string
	issueInstant time.Time
	notOnOrAfter *time.Time
}

// buildLogoutRequestWith is buildLogoutRequest with control over the request ID
// and freshness attributes (IssueInstant / NotOnOrAfter). A zero id or
// issueInstant falls back to the same defaults buildLogoutRequest uses.
func buildLogoutRequestWith(t *testing.T, issuer, nameID, destination, sessionIndex string, opts logoutRequestOpts) string {
	t.Helper()
	id := opts.id
	if id == "" {
		id = "_test_logout_123"
	}
	issueInstant := opts.issueInstant
	if issueInstant.IsZero() {
		issueInstant = time.Now().UTC()
	}
	req := &crewsaml.LogoutRequest{
		ID:           id,
		Version:      "2.0",
		IssueInstant: issueInstant,
		NotOnOrAfter: opts.notOnOrAfter,
		Destination:  destination,
		Issuer: &crewsaml.Issuer{
			Value: issuer,
		},
		NameID: &crewsaml.NameID{
			Value: nameID,
		},
	}
	if sessionIndex != "" {
		req.SessionIndex = &crewsaml.SessionIndex{Value: sessionIndex}
	}

	data, err := req.Bytes()
	require.NoError(t, err)
	return string(data)
}

// signedRedirectQuerySHA1 mirrors signedRedirectQuery but signs with RSA-SHA1
// under the legacy rsa-sha1 SigAlg, so tests can exercise the SHA-1 opt-in gate
// (MF-3). SHA-1 is broken for signatures; this exists only to prove the handler
// rejects it by default and honors it solely when a tenant opts in.
func signedRedirectQuerySHA1(t *testing.T, key spSigningKey, xmlStr, relayState string) string {
	t.Helper()
	const sigAlgRSASHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	enc := deflateAndEncode(t, xmlStr)
	query := "SAMLRequest=" + url.QueryEscape(enc)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	query += "&SigAlg=" + url.QueryEscape(sigAlgRSASHA1)

	digest := sha1.Sum([]byte(query)) //nolint:gosec // legacy SHA-1 opt-in path under test (MF-3).
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.priv, crypto.SHA1, digest[:])
	require.NoError(t, err)
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return query
}

// setupSLORouter creates a chi router with the SLO handler registered under /t/{tenant}/saml/slo,
// backed by in-memory stores with a pre-configured SP application. The returned
// spSigningKey is registered as the SP's signing certificate, so tests can
// produce LogoutRequests that pass signature verification.
func setupSLORouter(t *testing.T) (chi.Router, *store.SessionStore, *store.AppStore, spSigningKey) {
	t.Helper()

	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	appStore := store.NewAppStore(configDB, "test-table")
	sessionStore := store.NewSessionStore(sessionDB, "test-table")

	spKey := newSPSigningKey(t)

	// Create a registered SP
	ctx := context.Background()
	tenantStore := store.NewTenantStore(configDB, "test-table")
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "acme",
		DisplayName: "Acme Corp",
		Plan:        "free",
		Status:      "active",
	}))

	_, err := appStore.Create(ctx, "acme", &tenant.Application{
		DisplayName: "Test SP",
		Protocol:    "saml",
		SourceID:    "src-1",
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:       "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
		AcsURLs:        []string{"https://sp.example.com/saml/acs"},
		SloURL:         "https://sp.example.com/saml/slo",
		SigningCertPem: spKey.certPEM,
		NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:   "email",
	})
	require.NoError(t, err)

	auditStore := store.NewAuditStore(sessionDB, "test")
	replayStore := store.NewReplayStore(sessionDB, "test")
	r := chi.NewRouter()
	sloHandler := internalsaml.HandleSLO(testBaseURL, sessionStore, appStore, auditStore, replayStore)
	r.Get("/t/{tenant}/saml/slo", sloHandler)
	r.Post("/t/{tenant}/saml/slo", sloHandler)

	return r, sessionStore, appStore, spKey
}

// sloDestination returns the LogoutRequest Destination that addresses this
// IdP's SLO endpoint for the given tenant, built from testBaseURL exactly as
// HandleSLO expects it (destinationMatches). Tests use this so their signed
// requests are not rejected as misdirected.
func sloDestination(tenant string) string {
	return testBaseURL + "/t/" + tenant + "/saml/slo"
}

func TestHandleSLO_MissingSAMLRequest(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing SAMLRequest")
}

func TestHandleSLO_InvalidBase64(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?SAMLRequest=not-valid-base64!!!", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid SAMLRequest")
}

func TestHandleSLO_InvalidXML(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	// Valid base64 + deflate but not valid XML
	encoded := deflateAndEncode(t, "this is not xml")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?SAMLRequest="+url.QueryEscape(encoded), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// The handler should return 400 because the issuer will be empty
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSLO_UnknownIssuer(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://unknown-sp.example.com", "user@example.com", sloDestination("acme"), "")
	encoded := deflateAndEncode(t, xmlStr)

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?SAMLRequest="+url.QueryEscape(encoded), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unknown SP issuer")
}

// TestHandleSLO_UnsignedRequest_Rejected asserts that a LogoutRequest with a
// valid, known issuer but no redirect-binding signature is rejected with 403.
func TestHandleSLO_UnsignedRequest_Rejected(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_abc")
	encoded := deflateAndEncode(t, xmlStr)

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?SAMLRequest="+url.QueryEscape(encoded), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "signature verification failed")
}

// TestHandleSLO_TamperedSignature_Rejected asserts that a request whose
// signature does not match the signed query is rejected with 403.
func TestHandleSLO_TamperedSignature_Rejected(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "")
	query := signedRedirectQuery(t, spKey, xmlStr, "")
	// Flip the signature to a different (valid-base64) value.
	tampered := query[:strings.Index(query, "&Signature=")] + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("not-the-real-signature")))

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+tampered, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestHandleSLO_WrongSigningKey_Rejected asserts that a request signed by a
// key other than the SP's registered certificate is rejected with 403.
func TestHandleSLO_WrongSigningKey_Rejected(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	attackerKey := newSPSigningKey(t)
	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "")
	query := signedRedirectQuery(t, attackerKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestHandleSLO_ZipBomb_Rejected asserts that a small deflate payload that
// inflates past the cap is rejected at decode time (400), never buffered.
func TestHandleSLO_ZipBomb_Rejected(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	// 4 MB of a single repeated byte compresses to a few KB but inflates well
	// past the 512 KB cap.
	huge := bytes.Repeat([]byte("A"), 4*1024*1024)
	encoded := deflateAndEncode(t, string(huge))

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?SAMLRequest="+url.QueryEscape(encoded), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid SAMLRequest")
}

func TestHandleSLO_ValidRequest_RedirectsToSP(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_abc")
	query := signedRedirectQuery(t, spKey, xmlStr, "test-relay")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should redirect (302) to the SP's SLO URL
	assert.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	require.NotEmpty(t, location, "should have Location header")

	locURL, err := url.Parse(location)
	require.NoError(t, err)

	// Verify it redirects to the SP's SLO URL
	assert.Equal(t, "sp.example.com", locURL.Host)
	assert.Equal(t, "/saml/slo", locURL.Path)

	// Verify SAMLResponse is present
	samlResp := locURL.Query().Get("SAMLResponse")
	assert.NotEmpty(t, samlResp, "redirect should contain SAMLResponse")

	// Verify RelayState is forwarded
	assert.Equal(t, "test-relay", locURL.Query().Get("RelayState"))
}

func TestHandleSLO_ValidRequest_ResponseContainsCorrectFields(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	locURL, err := url.Parse(location)
	require.NoError(t, err)

	// Decode and verify the LogoutResponse
	samlRespEncoded := locURL.Query().Get("SAMLResponse")
	require.NotEmpty(t, samlRespEncoded)

	rawResp, err := base64.StdEncoding.DecodeString(samlRespEncoded)
	require.NoError(t, err)

	inflated, err := inflate(rawResp)
	require.NoError(t, err)

	var logoutResp crewsaml.LogoutResponse
	err = xml.Unmarshal(inflated, &logoutResp)
	require.NoError(t, err)

	assert.Equal(t, "2.0", logoutResp.Version)
	assert.Equal(t, "_test_logout_123", logoutResp.InResponseTo)
	assert.Equal(t, "https://sp.example.com/saml/slo", logoutResp.Destination)
	assert.Equal(t, crewsaml.StatusSuccess, logoutResp.Status.StatusCode.Value)
	assert.NotEmpty(t, logoutResp.ID)
	assert.NotNil(t, logoutResp.Issuer)
	// Issuer is built from the server-side baseURL, not from r.Host.
	assert.Equal(t, "https://idp.example.com/t/acme/saml/metadata", logoutResp.Issuer.Value)
}

func TestHandleSLO_WithSessionParticipants(t *testing.T) {
	r, sessionStore, _, spKey := setupSLORouter(t)

	// Add a session participant
	ctx := context.Background()
	err := sessionStore.AddParticipant(ctx, "_session_xyz", "https://sp.example.com", "user-1", "user@example.com", time.Now().Add(time.Hour))
	require.NoError(t, err)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_xyz")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should still redirect successfully
	assert.Equal(t, http.StatusFound, w.Code)
	assert.NotEmpty(t, w.Header().Get("Location"))
}

// sessionCookieName mirrors the unexported constant in the saml package. This
// external test package cannot import it, so it is duplicated here; if the
// production name ever changes, these assertions fail loudly.
const sessionCookieName = "saml_session"

// findCookie returns the Set-Cookie with the given name from a response, or nil.
func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestHandleSLO_ClearsSessionCookie asserts that a verified LogoutRequest
// actually terminates the gateway session by expiring the session cookie
// (MaxAge<0, empty value), rather than emitting a cosmetic Success response that
// leaves the session intact. A browser replaying the cleared cookie carries no
// session value, so a subsequent GetSession would find nothing.
func TestHandleSLO_ClearsSessionCookie(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_abc")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)

	cleared := findCookie(w.Result(), sessionCookieName)
	require.NotNil(t, cleared, "SLO must write a Set-Cookie clearing the session cookie")
	assert.Less(t, cleared.MaxAge, 0, "session cookie must be expired (MaxAge<0)")
	assert.Empty(t, cleared.Value, "cleared session cookie must carry no session value")
}

// TestHandleSLO_SingleParticipant_Success asserts that when the only session
// participant is the SP that issued the LogoutRequest, the whole session is
// terminated over this exchange and the response status is Success.
func TestHandleSLO_SingleParticipant_Success(t *testing.T) {
	r, sessionStore, _, spKey := setupSLORouter(t)

	ctx := context.Background()
	require.NoError(t, sessionStore.AddParticipant(ctx, "_session_solo", "https://sp.example.com", "user-1", "user@example.com", time.Now().Add(time.Hour)))

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_solo")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, crewsaml.StatusSuccess, decodeLogoutResponseStatus(t, w))
}

// TestHandleSLO_RevokesSession asserts that a verified LogoutRequest records a
// server-side revocation marker keyed by the request's SessionIndex, so a copy
// of the session cookie replayed at the (separate) SSO Lambda is rejected for
// the remainder of its lifetime rather than surviving logout.
func TestHandleSLO_RevokesSession(t *testing.T) {
	r, sessionStore, _, spKey := setupSLORouter(t)

	ctx := context.Background()
	// Not revoked before the logout exchange.
	revoked, err := sessionStore.IsSessionRevoked(ctx, "_session_revoke")
	require.NoError(t, err)
	require.False(t, revoked)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_revoke")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)

	// The SessionIndex from the LogoutRequest is now revoked server-side.
	revoked, err = sessionStore.IsSessionRevoked(ctx, "_session_revoke")
	require.NoError(t, err)
	assert.True(t, revoked, "SLO must record a server-side revocation marker for the logged-out session")
}

// TestHandleSLO_OtherParticipants_PartialLogout asserts that when the session
// was shared with another SP that this single front-channel response cannot
// reach, the LogoutResponse reports PartialLogout rather than a misleading
// Success — while still clearing the gateway session cookie.
func TestHandleSLO_OtherParticipants_PartialLogout(t *testing.T) {
	r, sessionStore, _, spKey := setupSLORouter(t)

	ctx := context.Background()
	require.NoError(t, sessionStore.AddParticipant(ctx, "_session_multi", "https://sp.example.com", "user-1", "user@example.com", time.Now().Add(time.Hour)))
	require.NoError(t, sessionStore.AddParticipant(ctx, "_session_multi", "https://other-sp.example.com", "user-1", "user@example.com", time.Now().Add(time.Hour)))

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_multi")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, crewsaml.StatusPartialLogout, decodeLogoutResponseStatus(t, w))

	// The gateway session is still terminated even on partial logout.
	cleared := findCookie(w.Result(), sessionCookieName)
	require.NotNil(t, cleared)
	assert.Less(t, cleared.MaxAge, 0)
}

// TestHandleSLO_DecodeError_NoInternalLeak asserts that a decode failure on
// this unauthenticated endpoint returns a stable generic message and never
// echoes the underlying Go error (which can reflect attacker input).
func TestHandleSLO_DecodeError_NoInternalLeak(t *testing.T) {
	r, _, _, _ := setupSLORouter(t)

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?SAMLRequest=not-valid-base64!!!", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	body := w.Body.String()
	assert.Equal(t, "invalid SAMLRequest", strings.TrimSpace(body))
	// The raw decoder error (e.g. "base64 decode: illegal base64 data ...")
	// must not reach the client.
	assert.NotContains(t, body, "base64")
	assert.NotContains(t, body, "illegal")
}

// decodeLogoutResponseStatus extracts the SAML status code from the
// LogoutResponse carried in the redirect Location's SAMLResponse parameter.
func decodeLogoutResponseStatus(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	location := w.Header().Get("Location")
	require.NotEmpty(t, location)
	locURL, err := url.Parse(location)
	require.NoError(t, err)
	samlRespEncoded := locURL.Query().Get("SAMLResponse")
	require.NotEmpty(t, samlRespEncoded)
	rawResp, err := base64.StdEncoding.DecodeString(samlRespEncoded)
	require.NoError(t, err)
	inflated, err := inflate(rawResp)
	require.NoError(t, err)
	var logoutResp crewsaml.LogoutResponse
	require.NoError(t, xml.Unmarshal(inflated, &logoutResp))
	return logoutResp.Status.StatusCode.Value
}

func TestHandleSLO_FallsBackToAcsURL(t *testing.T) {
	// Setup a router with an SP that has no SLO URL configured
	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	appStore := store.NewAppStore(configDB, "test-table")
	sessionStore := store.NewSessionStore(sessionDB, "test-table")
	tenantStore := store.NewTenantStore(configDB, "test-table")

	spKey := newSPSigningKey(t)

	ctx := context.Background()
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "beta",
		DisplayName: "Beta Corp",
		Plan:        "free",
		Status:      "active",
	}))

	_, err := appStore.Create(ctx, "beta", &tenant.Application{
		DisplayName: "No-SLO SP",
		Protocol:    "saml",
		SourceID:    "src-1",
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:       "https://noslo-sp.example.com",
		AcsURL:         "https://noslo-sp.example.com/saml/acs",
		AcsURLs:        []string{"https://noslo-sp.example.com/saml/acs"},
		SigningCertPem: spKey.certPEM,
		NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:   "email",
		// No SloURL set
	})
	require.NoError(t, err)

	auditStore := store.NewAuditStore(sessionDB, "test")
	replayStore := store.NewReplayStore(sessionDB, "test")
	r := chi.NewRouter()
	sloHandler := internalsaml.HandleSLO(testBaseURL, sessionStore, appStore, auditStore, replayStore)
	r.Get("/t/{tenant}/saml/slo", sloHandler)

	xmlStr := buildLogoutRequest(t, "https://noslo-sp.example.com", "user@example.com", sloDestination("beta"), "")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/beta/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	locURL, err := url.Parse(location)
	require.NoError(t, err)

	// Should fall back to ACS URL
	assert.Equal(t, "noslo-sp.example.com", locURL.Host)
	assert.Equal(t, "/saml/acs", locURL.Path)
}

// setupSLORouterSHA1Enabled mirrors setupSLORouter but registers the SP under a
// tenant whose SAMLConfig opts into legacy SHA-1 interop (AllowInsecureSHA1),
// so tests can prove the handler honors a SHA-1-signed LogoutRequest only for an
// opted-in tenant.
func setupSLORouterSHA1Enabled(t *testing.T) (chi.Router, spSigningKey) {
	t.Helper()

	configDB := store.NewMemoryDB()
	sessionDB := store.NewMemoryDB()
	appStore := store.NewAppStore(configDB, "test-table")
	sessionStore := store.NewSessionStore(sessionDB, "test-table")

	spKey := newSPSigningKey(t)

	ctx := context.Background()
	tenantStore := store.NewTenantStore(configDB, "test-table")
	require.NoError(t, tenantStore.Create(ctx, &tenant.Tenant{
		Slug:        "legacy",
		DisplayName: "Legacy Corp",
		Plan:        "free",
		Status:      "active",
	}))

	_, err := appStore.Create(ctx, "legacy", &tenant.Application{
		DisplayName: "Legacy SP",
		Protocol:    "saml",
		SourceID:    "src-1",
		Status:      "active",
	}, &tenant.SAMLConfig{
		EntityID:          "https://sp.example.com",
		AcsURL:            "https://sp.example.com/saml/acs",
		AcsURLs:           []string{"https://sp.example.com/saml/acs"},
		SloURL:            "https://sp.example.com/saml/slo",
		SigningCertPem:    spKey.certPEM,
		NameIDFormat:      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:      "email",
		AllowInsecureSHA1: true,
	})
	require.NoError(t, err)

	auditStore := store.NewAuditStore(sessionDB, "test")
	replayStore := store.NewReplayStore(sessionDB, "test")
	r := chi.NewRouter()
	sloHandler := internalsaml.HandleSLO(testBaseURL, sessionStore, appStore, auditStore, replayStore)
	r.Get("/t/{tenant}/saml/slo", sloHandler)

	return r, spKey
}

// TestHandleSLO_StaleRequest_Rejected asserts that a validly-signed LogoutRequest
// whose IssueInstant is older than the freshness window is rejected with 403, so
// a signed SLO URL captured from logs/history cannot be replayed indefinitely
// (MF-2).
func TestHandleSLO_StaleRequest_Rejected(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	stale := time.Now().UTC().Add(-10 * time.Minute)
	xmlStr := buildLogoutRequestWith(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "",
		logoutRequestOpts{issueInstant: stale})
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "stale or expired")
}

// TestHandleSLO_FutureRequest_Rejected asserts that a LogoutRequest whose
// IssueInstant lies further in the future than the clock-skew tolerance is
// rejected with 403 (MF-2).
func TestHandleSLO_FutureRequest_Rejected(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	future := time.Now().UTC().Add(10 * time.Minute)
	xmlStr := buildLogoutRequestWith(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "",
		logoutRequestOpts{issueInstant: future})
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "stale or expired")
}

// TestHandleSLO_ExpiredNotOnOrAfter_Rejected asserts that a fresh-IssueInstant
// LogoutRequest whose explicit NotOnOrAfter has already passed is rejected with
// 403 (MF-2).
func TestHandleSLO_ExpiredNotOnOrAfter_Rejected(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	past := time.Now().UTC().Add(-10 * time.Minute)
	xmlStr := buildLogoutRequestWith(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "",
		logoutRequestOpts{notOnOrAfter: &past})
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "stale or expired")
}

// TestHandleSLO_MismatchedDestination_Rejected asserts that a validly-signed
// LogoutRequest whose Destination addresses a different endpoint is rejected with
// 403, so a request signed for another IdP/tenant cannot be replayed here (MF-2).
func TestHandleSLO_MismatchedDestination_Rejected(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", "https://evil.example.com/t/acme/saml/slo", "")
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Destination")
}

// TestHandleSLO_ReplayedRequest_Rejected asserts the one-time-use guard: a
// validly-signed LogoutRequest succeeds once (302), and an identical replay of
// the same signed URL — same request ID — is rejected with 403 (MF-2).
func TestHandleSLO_ReplayedRequest_Rejected(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	xmlStr := buildLogoutRequestWith(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "_session_abc",
		logoutRequestOpts{id: "_replay_once_1"})
	query := signedRedirectQuery(t, spKey, xmlStr, "")

	// First use: accepted.
	req1 := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusFound, w1.Code)

	// Replay of the identical signed URL: rejected as one-time-use.
	req2 := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusForbidden, w2.Code)
	assert.Contains(t, w2.Body.String(), "replayed")
}

// TestHandleSLO_SHA1_RejectedByDefault asserts that a LogoutRequest signed with
// the legacy rsa-sha1 SigAlg is rejected with 403 when the SP's tenant has not
// opted into SHA-1 interop — SHA-1 is off by default (MF-3).
func TestHandleSLO_SHA1_RejectedByDefault(t *testing.T) {
	r, _, _, spKey := setupSLORouter(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("acme"), "")
	query := signedRedirectQuerySHA1(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "signature verification failed")
}

// TestHandleSLO_SHA1_AcceptedWhenOptedIn asserts that the same SHA-1-signed
// LogoutRequest is honored (302) when the SP's tenant explicitly opts into legacy
// SHA-1 interop via SAMLConfig.AllowInsecureSHA1 (MF-3).
func TestHandleSLO_SHA1_AcceptedWhenOptedIn(t *testing.T) {
	r, spKey := setupSLORouterSHA1Enabled(t)

	xmlStr := buildLogoutRequest(t, "https://sp.example.com", "user@example.com", sloDestination("legacy"), "")
	query := signedRedirectQuerySHA1(t, spKey, xmlStr, "")

	req := httptest.NewRequest(http.MethodGet, "/t/legacy/saml/slo?"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.NotEmpty(t, w.Header().Get("Location"))
}

// inflate decompresses deflate-compressed data.
func inflate(data []byte) ([]byte, error) {
	reader := flate.NewReader(strings.NewReader(string(data)))
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}
