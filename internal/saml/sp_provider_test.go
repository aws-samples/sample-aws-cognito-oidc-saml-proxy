package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAppStore() *store.AppStore {
	return store.NewAppStore(store.NewMemoryStore(), "test-table")
}

// requestForTenant builds a GET request whose context carries a chi route
// context with the given tenant path param, mirroring how the /t/{tenant}/...
// routes populate it at runtime. GetServiceProvider resolves SP metadata
// tenant-scoped, so tests must supply the tenant the app was created under.
func requestForTenant(tenantSlug string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rctx := chi.NewRouteContext()
	if tenantSlug != "" {
		rctx.URLParams.Add("tenant", tenantSlug)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func createTestApp(t *testing.T, appStore *store.AppStore, tenantSlug, entityID string, status string) string {
	t.Helper()
	app := &tenant.Application{
		DisplayName: "Test SP",
		Protocol:    "saml",
		SourceID:    "source-1",
		Status:      status,
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:           entityID,
		AcsURL:             "https://sp.example.com/saml/acs",
		AcsURLs:            []string{"https://sp.example.com/saml/acs"},
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:       "email",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       300,
	}
	id, err := appStore.Create(context.Background(), tenantSlug, app, samlCfg)
	require.NoError(t, err)
	return id
}

func TestSPProvider_GetServiceProvider_ReturnsEntityDescriptor(t *testing.T) {
	appStore := newTestAppStore()
	createTestApp(t, appStore, "acme", "https://sp.example.com/saml", "active")

	provider := NewSPProvider(appStore)
	ed, err := provider.GetServiceProvider(requestForTenant("acme"), "https://sp.example.com/saml")
	require.NoError(t, err)
	require.NotNil(t, ed)

	assert.Equal(t, "https://sp.example.com/saml", ed.EntityID)
	require.Len(t, ed.SPSSODescriptors, 1)

	spSSO := ed.SPSSODescriptors[0]
	require.Len(t, spSSO.AssertionConsumerServices, 1)
	assert.Equal(t, "https://sp.example.com/saml/acs", spSSO.AssertionConsumerServices[0].Location)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", spSSO.AssertionConsumerServices[0].Binding)
	assert.Equal(t, 0, spSSO.AssertionConsumerServices[0].Index)
}

func TestSPProvider_GetServiceProvider_UnknownSP_ReturnsErrNotExist(t *testing.T) {
	appStore := newTestAppStore()
	provider := NewSPProvider(appStore)

	ed, err := provider.GetServiceProvider(requestForTenant("acme"), "https://unknown.example.com/saml")
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, ed)
}

func TestSPProvider_GetServiceProvider_NilRequest_ReturnsErrNotExist(t *testing.T) {
	appStore := newTestAppStore()
	createTestApp(t, appStore, "acme", "https://sp.example.com/saml", "active")

	provider := NewSPProvider(appStore)
	// A request that reaches the provider without an HTTP context (and thus no
	// tenant) must fail closed rather than scan across tenants.
	ed, err := provider.GetServiceProvider(nil, "https://sp.example.com/saml")
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, ed)
}

func TestSPProvider_GetServiceProvider_MissingTenant_ReturnsErrNotExist(t *testing.T) {
	appStore := newTestAppStore()
	createTestApp(t, appStore, "acme", "https://sp.example.com/saml", "active")

	provider := NewSPProvider(appStore)
	// Empty tenant path segment: fail closed, do not resolve the SP.
	ed, err := provider.GetServiceProvider(requestForTenant(""), "https://sp.example.com/saml")
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, ed)
}

func TestSPProvider_GetServiceProvider_WrongTenant_ReturnsErrNotExist(t *testing.T) {
	appStore := newTestAppStore()
	createTestApp(t, appStore, "acme", "https://sp.example.com/saml", "active")

	provider := NewSPProvider(appStore)
	// The SP exists under "acme"; another tenant must not resolve it.
	ed, err := provider.GetServiceProvider(requestForTenant("other"), "https://sp.example.com/saml")
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, ed)
}

func TestSPProvider_GetServiceProvider_InactiveApp_ReturnsErrNotExist(t *testing.T) {
	appStore := newTestAppStore()
	createTestApp(t, appStore, "acme", "https://inactive.example.com/saml", "inactive")

	provider := NewSPProvider(appStore)
	ed, err := provider.GetServiceProvider(requestForTenant("acme"), "https://inactive.example.com/saml")
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, ed)
}

func TestSPProvider_GetServiceProvider_WithSigningCert(t *testing.T) {
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")

	app := &tenant.Application{
		DisplayName: "SP with Cert",
		Protocol:    "saml",
		SourceID:    "source-1",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:       "https://sp-cert.example.com/saml",
		AcsURL:         "https://sp-cert.example.com/saml/acs",
		AcsURLs:        []string{"https://sp-cert.example.com/saml/acs"},
		NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:   "email",
		SigningCertPem: testCertPEM,
	}
	_, err := appStore.Create(context.Background(), "acme", app, samlCfg)
	require.NoError(t, err)

	provider := NewSPProvider(appStore)
	ed, err := provider.GetServiceProvider(requestForTenant("acme"), "https://sp-cert.example.com/saml")
	require.NoError(t, err)
	require.NotNil(t, ed)

	spSSO := ed.SPSSODescriptors[0]
	require.Len(t, spSSO.KeyDescriptors, 1)
	assert.Equal(t, "signing", spSSO.RoleDescriptor.KeyDescriptors[0].Use)
}

// createEncryptionCertApp seeds an SP with a stored encryption certificate and
// the given EncryptAssertion flag.
func createEncryptionCertApp(t *testing.T, appStore *store.AppStore, entityID string, encrypt bool) {
	t.Helper()
	_, err := appStore.Create(context.Background(), "acme", &tenant.Application{
		DisplayName: "SP with enc cert", Protocol: "saml", SourceID: "source-1", Status: "active",
	}, &tenant.SAMLConfig{
		EntityID:          entityID,
		AcsURL:            "https://sp-enc.example.com/saml/acs",
		AcsURLs:           []string{"https://sp-enc.example.com/saml/acs"},
		SigningCertPem:    testCertPEM,
		EncryptionCertPem: testCertPEM,
		SignResponse:      true,
		SignAssertion:     true,
		EncryptAssertion:  encrypt,
	})
	require.NoError(t, err)
}

// TestBuildEntityDescriptor_EncryptionKeyDescriptorFollowsFlag is the M-8
// regression: crewjam encrypts whenever the SP descriptor carries an
// encryption cert, so a stored certificate must only be advertised when the
// administrator actually enabled EncryptAssertion.
func TestBuildEntityDescriptor_EncryptionKeyDescriptorFollowsFlag(t *testing.T) {
	uses := func(ed *saml.EntityDescriptor) []string {
		var out []string
		for _, kd := range ed.SPSSODescriptors[0].KeyDescriptors {
			out = append(out, kd.Use)
		}
		return out
	}

	t.Run("flag off: cert stored but not advertised", func(t *testing.T) {
		appStore := newTestAppStore()
		createEncryptionCertApp(t, appStore, "https://sp-enc-off.example.com/saml", false)
		ed, err := NewSPProvider(appStore).GetServiceProvider(requestForTenant("acme"), "https://sp-enc-off.example.com/saml")
		require.NoError(t, err)
		assert.Equal(t, []string{"signing"}, uses(ed))
	})

	t.Run("flag on: encryption descriptor advertised", func(t *testing.T) {
		appStore := newTestAppStore()
		createEncryptionCertApp(t, appStore, "https://sp-enc-on.example.com/saml", true)
		ed, err := NewSPProvider(appStore).GetServiceProvider(requestForTenant("acme"), "https://sp-enc-on.example.com/saml")
		require.NoError(t, err)
		assert.Equal(t, []string{"signing", "encryption"}, uses(ed))
	})

	t.Run("flag on without a cert: nothing to advertise", func(t *testing.T) {
		ed := buildEntityDescriptor(&tenant.SAMLConfig{
			EntityID: "https://sp.example.com/saml", AcsURL: "https://sp.example.com/acs", EncryptAssertion: true,
		})
		assert.Empty(t, ed.SPSSODescriptors[0].KeyDescriptors)
	})
}

// TestSPProvider_GetServiceProvider_WantAuthnRequestsSigned_FailsClosed is the
// M-8 regression: an SP that requires signed AuthnRequests is refused with an
// error that is NOT os.ErrNotExist, so crewjam answers 500 (logged) rather than
// silently serving an SP whose requests are never verified.
func TestSPProvider_GetServiceProvider_WantAuthnRequestsSigned_FailsClosed(t *testing.T) {
	appStore := newTestAppStore()
	_, err := appStore.Create(context.Background(), "acme", &tenant.Application{
		DisplayName: "Signed-request SP", Protocol: "saml", SourceID: "source-1", Status: "active",
	}, &tenant.SAMLConfig{
		EntityID:                "https://sp-signed.example.com/saml",
		AcsURL:                  "https://sp-signed.example.com/saml/acs",
		AcsURLs:                 []string{"https://sp-signed.example.com/saml/acs"},
		SignResponse:            true,
		SignAssertion:           true,
		WantAuthnRequestsSigned: true,
	})
	require.NoError(t, err)

	ed, err := NewSPProvider(appStore).GetServiceProvider(requestForTenant("acme"), "https://sp-signed.example.com/saml")
	assert.Nil(t, ed)
	require.Error(t, err)
	assert.ErrorIs(t, err, errAuthnRequestSignatureUnsupported)
	assert.NotErrorIs(t, err, os.ErrNotExist)
}

func TestSPProvider_GetServiceProvider_MultipleACSURLs(t *testing.T) {
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")

	app := &tenant.Application{
		DisplayName: "Multi ACS SP",
		Protocol:    "saml",
		SourceID:    "source-1",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID: "https://multi-acs.example.com/saml",
		AcsURL:   "https://multi-acs.example.com/saml/acs1",
		AcsURLs: []string{
			"https://multi-acs.example.com/saml/acs1",
			"https://multi-acs.example.com/saml/acs2",
		},
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource: "email",
	}
	_, err := appStore.Create(context.Background(), "acme", app, samlCfg)
	require.NoError(t, err)

	provider := NewSPProvider(appStore)
	ed, err := provider.GetServiceProvider(requestForTenant("acme"), "https://multi-acs.example.com/saml")
	require.NoError(t, err)

	spSSO := ed.SPSSODescriptors[0]
	require.Len(t, spSSO.AssertionConsumerServices, 2)
	assert.Equal(t, 0, spSSO.AssertionConsumerServices[0].Index)
	assert.Equal(t, 1, spSSO.AssertionConsumerServices[1].Index)
	assert.True(t, *spSSO.AssertionConsumerServices[0].IsDefault)
	assert.False(t, *spSSO.AssertionConsumerServices[1].IsDefault)
}

// testCertPEM is a self-signed certificate used only in tests.
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgS0jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4qne60TB3pOYaBy/YFq4VVfv+IzLHzNoYfKwLaKxKICHMP+ZsXFMIGljKMCqmM5
ACYJyFHOAAl1EFa8CDQBR6sLftBK2aOrDClSiNQ2MnJiO/GXpEOKFtjBMQqbMeKl
A33GqPmBWwUNiGeVraIkAuTMhJF2MFcEv5sjGPDHqXGiTn5Lz3ZTC6nI0TDIaEPR
YLSHhkkfTk5Lsa4MjE3dCjP+cZKfRWguRxufER96m7NrqPa/VhJ5vafxDHO/eTxv
Jx+mBw/sByKL4Nc0g3jRBa8p8bn2sSJXTib1gxuJPcjxR5fSsPuB8Nxw8PDAqBKn
r8XN/gPxFCfBMgXFPKnhAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFzZ15yBfHnM
TKPFY11S4qGm7TDDQZ11Kb0m19mih5mrSjZqD+oXoDBYL8/MtJLOATYnynlXmQOd
VkPajNB0v1RQ+e+8t/1KuA3M7cA3p6M+XJxOBK5GdbmHgjLnJfA7koZ6oM2mW1vH
TN9J8YadTM3P4RP7SeVavgI34Md5GkCi//RpJBBiClAyB4EpG5YBNPxK3o5fM8qP
dfBq/XPbJyN/MGBQGE7aMRPMFGVYHYiIKMhGLB+3RXJIL8KPTBhpf/sdzDnCfTk0
vM4MFSeY4jFvJ+plVJHb4DXF4VYokTSCHiMF9X4DjF+nNbvvBPaVjEXPIgSE5Y5C
0dBDHlBs0rA=
-----END CERTIFICATE-----`
