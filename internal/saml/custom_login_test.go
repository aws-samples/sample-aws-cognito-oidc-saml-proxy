package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSPWithPending builds a multi-tenant SessionProvider with a pending-login
// store wired in.
func newSPWithPending(t *testing.T) (*SessionProvider, *store.SourceStore, *store.AppStore, *store.PendingLoginStore) {
	t.Helper()
	ms := store.NewMemoryStore()
	sourceStore := store.NewSourceStore(ms, "test-table")
	appStore := store.NewAppStore(ms, "test-table")
	pending := store.NewPendingLoginStore(ms, "test-table")
	sp := NewSessionProvider(
		WithSourceStore(sourceStore),
		WithAppStore(appStore),
		WithHMACKey([]byte("test-hmac-key-for-unit-tests-32b")),
		WithProviderBaseURL("https://idp.example.com"),
	)
	sp.SetPendingLoginStore(pending)
	return sp, sourceStore, appStore, pending
}

// seedCustomLoginApp creates a source + SAML app configured with a custom login
// page. Returns the source ID.
func seedCustomLoginApp(t *testing.T, sourceStore *store.SourceStore, appStore *store.AppStore, entityID, customLoginURL string, trusted []string) string {
	t.Helper()
	sourceID, err := sourceStore.Create(context.Background(), "acme", &tenant.IdentitySource{
		DisplayName: "Acme Cognito",
		Type:        "cognito",
		PoolID:      "eu-north-1_abc123",
		Region:      "eu-north-1",
		Domain:      "acme.auth.eu-north-1.amazoncognito.com",
		ClientID:    "acme-client-id",
		Status:      "active",
	})
	require.NoError(t, err)

	app := &tenant.Application{
		DisplayName:              "Custom Login App",
		Protocol:                 "saml",
		SourceID:                 sourceID,
		Status:                   "active",
		CustomLoginURL:           customLoginURL,
		TrustedLoginRedirectURIs: trusted,
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID: entityID,
		AcsURL:   "https://sp.example.com/saml/acs",
		AcsURLs:  []string{"https://sp.example.com/saml/acs"},
	}
	_, err = appStore.Create(context.Background(), "acme", app, samlCfg)
	require.NoError(t, err)
	return sourceID
}

func TestSAML_CustomLogin_RedirectReplacesCognito(t *testing.T) {
	sp, sourceStore, appStore, pending := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://login.example.com/start", []string{"https://login.example.com/"})

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	rr := httptest.NewRecorder()
	authnReq := &crewsaml.IdpAuthnRequest{
		RelayState:              "relay-xyz",
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
		Request:                 crewsaml.AuthnRequest{ID: "authn-1"},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)

	res := rr.Result()
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusFound, res.StatusCode)

	loc := res.Header.Get("Location")
	u, err := url.Parse(loc)
	require.NoError(t, err)
	// REPLACE: must go to the custom login page, NOT the Cognito domain.
	assert.Equal(t, "login.example.com", u.Host)
	assert.NotContains(t, u.Host, "amazoncognito.com")

	q := u.Query()
	flowID := q.Get("state")
	assert.NotEmpty(t, flowID)
	assert.Contains(t, q.Get("return_to"), "/t/acme/saml/login/complete")

	// Pending login was persisted with the original request context.
	pl, err := pending.Get(context.Background(), flowID)
	require.NoError(t, err)
	assert.Equal(t, "saml", pl.Protocol)
	assert.Equal(t, "acme", pl.TenantSlug)
	assert.Equal(t, entityID, pl.SPEntityID)
	assert.Equal(t, "relay-xyz", pl.RelayState)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("<samlp:AuthnRequest/>")), pl.SAMLRequestB64)
}

func TestSAML_CustomLogin_UntrustedURL_Fails(t *testing.T) {
	sp, sourceStore, appStore, _ := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	// customLoginURL is NOT covered by the allowlist (config written directly,
	// bypassing API validation) -> runtime defensive check must reject it.
	seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://evil.example.com/login", []string{"https://login.example.com/"})

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	rr := httptest.NewRecorder()
	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.NotEqual(t, http.StatusFound, rr.Code)
}

func TestSAML_CustomLogin_NoCustomURL_FallsBackToCognito(t *testing.T) {
	sp, sourceStore, appStore, _ := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	// No custom login URL -> standard Cognito redirect.
	seedCustomLoginApp(t, sourceStore, appStore, entityID, "", nil)

	req := withChiTenant(httptest.NewRequest(http.MethodGet, "/t/acme/saml/sso", nil), "acme")
	rr := httptest.NewRecorder()
	authnReq := &crewsaml.IdpAuthnRequest{
		RequestBuffer:           []byte("<samlp:AuthnRequest/>"),
		ServiceProviderMetadata: &crewsaml.EntityDescriptor{EntityID: entityID},
	}

	session := sp.GetSession(rr, req, authnReq)
	assert.Nil(t, session)
	res := rr.Result()
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusFound, res.StatusCode)
	loc := res.Header.Get("Location")
	assert.Contains(t, loc, "amazoncognito.com")
}

func TestSAML_CompleteCustomLogin_Success(t *testing.T) {
	sp, sourceStore, appStore, pending := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	sourceID := seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://login.example.com/start", []string{"https://login.example.com/"})

	require.NoError(t, pending.Create(context.Background(), &store.PendingLogin{
		FlowID:         "flow-ok",
		Protocol:       "saml",
		TenantSlug:     "acme",
		SourceID:       sourceID,
		SAMLRequestB64: base64.StdEncoding.EncodeToString([]byte("<samlp:AuthnRequest/>")),
		RelayState:     "relay-1",
		SPEntityID:     entityID,
	}, time.Minute))

	fake := &fakeVerifier{claims: map[string]interface{}{
		"sub":   "user-9",
		"email": "user9@example.com",
	}}
	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		assert.Equal(t, "eu-north-1_abc123", poolID)
		assert.Equal(t, "eu-north-1", region)
		return fake
	}

	sessCookie, pl, err := sp.CompleteCustomLogin(context.Background(), "flow-ok", "the.id.token")
	require.NoError(t, err)
	require.NotNil(t, pl)
	assert.Equal(t, "relay-1", pl.RelayState)
	// Token verified against the SP's bound identity source client ID.
	assert.Equal(t, "acme-client-id", fake.gotClientID)
	assert.Equal(t, "the.id.token", fake.gotToken)

	// Session cookie decodes to a session carrying the token claims.
	sess, err := sp.decodeSessionCookie(sessCookie)
	require.NoError(t, err)
	assert.Equal(t, "user9@example.com", sess.UserEmail)

	// Single-use: the pending login is consumed.
	_, gerr := pending.Get(context.Background(), "flow-ok")
	assert.ErrorIs(t, gerr, store.ErrNotFound)
}

func TestSAML_CompleteCustomLogin_InvalidToken_ConsumesPending(t *testing.T) {
	sp, sourceStore, appStore, pending := newSPWithPending(t)
	const entityID = "https://sp.example.com/saml"
	sourceID := seedCustomLoginApp(t, sourceStore, appStore, entityID,
		"https://login.example.com/start", []string{"https://login.example.com/"})

	require.NoError(t, pending.Create(context.Background(), &store.PendingLogin{
		FlowID: "flow-bad", Protocol: "saml", TenantSlug: "acme", SourceID: sourceID, SPEntityID: entityID,
	}, time.Minute))

	sp.verifierFactory = func(poolID, region string) idTokenVerifier {
		return &fakeVerifier{err: fmt.Errorf("signature mismatch")}
	}

	_, _, err := sp.CompleteCustomLogin(context.Background(), "flow-bad", "bad.token")
	require.Error(t, err)

	// Even on failure, the flow is single-use and consumed.
	_, gerr := pending.Get(context.Background(), "flow-bad")
	assert.ErrorIs(t, gerr, store.ErrNotFound)
}

func TestSAML_CompleteCustomLogin_MissingFlow(t *testing.T) {
	sp, _, _, _ := newSPWithPending(t)
	_, _, err := sp.CompleteCustomLogin(context.Background(), "nope", "tok")
	assert.Error(t, err)
}

func TestSAML_CompleteCustomLogin_WrongProtocol(t *testing.T) {
	sp, _, _, pending := newSPWithPending(t)
	require.NoError(t, pending.Create(context.Background(), &store.PendingLogin{
		FlowID: "flow-oidc", Protocol: "oidc", TenantSlug: "acme", SourceID: "src",
	}, time.Minute))

	_, _, err := sp.CompleteCustomLogin(context.Background(), "flow-oidc", "tok")
	assert.Error(t, err)
}
