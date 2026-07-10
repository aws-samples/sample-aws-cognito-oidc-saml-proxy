package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertPEM creates a self-signed certificate and returns it as PEM bytes.
func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func newTestIntegrationAPI(t *testing.T, certPEM []byte) (humatest.TestAPI, *store.AppStore) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))

	memStore := store.NewMemoryStore()
	appStore := store.NewAppStore(memStore, "test")
	certSvc := service.NewCertificateService(certPEM)

	api.UseMiddleware(injectTenantMiddleware(testTenantSlug))

	RegisterIntegrationRoutes(api, appStore, "https://proxy.example.com", certSvc)

	return api, appStore
}

func TestIntegrationInfo_SAMLApp(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	api, appStore := newTestIntegrationAPI(t, certPEM)

	app := &tenant.Application{
		DisplayName: "SAML App",
		Protocol:    "saml",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:           "https://sp.example.com",
		AcsURL:             "https://sp.example.com/acs",
		NameIDFormat:       "persistent",
		NameIDSource:       "sub",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
	}

	id, err := appStore.Create(context.Background(), testTenantSlug, app, samlCfg)
	require.NoError(t, err)

	resp := api.Get("/api/v1/applications/" + id + "/integration")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Check application info
	appInfo := result["application"].(map[string]interface{})
	assert.Equal(t, id, appInfo["id"])
	assert.Equal(t, "SAML App", appInfo["displayName"])
	assert.Equal(t, "saml", appInfo["protocol"])

	// Check SAML integration details
	saml := result["saml"].(map[string]interface{})
	assert.Contains(t, saml["metadataUrl"], "/t/test-tenant/saml/metadata")
	assert.Contains(t, saml["ssoUrl"], "/t/test-tenant/saml/sso")
	assert.Contains(t, saml["sloUrl"], "/t/test-tenant/saml/slo")
	assert.NotEmpty(t, saml["certificateFingerprint"])
	assert.Equal(t, "persistent", saml["nameIdFormat"])

	// Check quick start snippets exist
	quickStart := result["quickStart"].(map[string]interface{})
	assert.NotEmpty(t, quickStart["spring-boot"])
	assert.NotEmpty(t, quickStart["nextauth"])
	assert.NotEmpty(t, quickStart["aws-cli"])
	assert.NotEmpty(t, quickStart["python-saml"])
	assert.NotEmpty(t, quickStart["onelogin-saml"])
}

func TestIntegrationInfo_OIDCApp(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	api, appStore := newTestIntegrationAPI(t, certPEM)

	app := &tenant.Application{
		DisplayName: "OIDC App",
		Protocol:    "oidc",
		Status:      "active",
	}

	id, err := appStore.Create(context.Background(), testTenantSlug, app, nil)
	require.NoError(t, err)

	resp := api.Get("/api/v1/applications/" + id + "/integration")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	// Check OIDC integration details
	oidc := result["oidc"].(map[string]interface{})
	assert.Contains(t, oidc["discoveryUrl"], "/t/test-tenant/oidc/.well-known/openid-configuration")
	assert.Equal(t, id, oidc["clientId"])
	assert.Contains(t, oidc["authorizationUrl"], "/t/test-tenant/oidc/authorize")
	assert.Contains(t, oidc["tokenUrl"], "/t/test-tenant/oidc/token")

	// Check quick start snippets exist
	quickStart := result["quickStart"].(map[string]interface{})
	assert.NotEmpty(t, quickStart["nextauth"])
	assert.NotEmpty(t, quickStart["spring-boot"])
	assert.NotEmpty(t, quickStart["python-authlib"])
}

func TestIntegrationInfo_AppNotFound(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	api, _ := newTestIntegrationAPI(t, certPEM)

	resp := api.Get("/api/v1/applications/nonexistent/integration")
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestCalculateCertFingerprint_ValidCert(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	certSvc := service.NewCertificateService(certPEM)
	certInfo, err := certSvc.GetInfo()
	require.NoError(t, err)
	assert.NotEmpty(t, certInfo.Fingerprint)
	// SHA-256 fingerprint with colons: 64 hex chars + 31 colons = 95 chars
	assert.Contains(t, certInfo.Fingerprint, ":")
}

func TestCalculateCertFingerprint_InvalidPEM(t *testing.T) {
	certSvc := service.NewCertificateService([]byte("not valid PEM"))
	_, err := certSvc.GetInfo()
	assert.Error(t, err)
}
