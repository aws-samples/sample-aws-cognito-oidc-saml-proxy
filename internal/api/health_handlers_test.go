package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/middleware"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestHealthAPI builds a health-routes test API with NO caller groups in
// context. It is the right helper for read-only (GET) health and cert-list
// tests that pre-date the MF-8 gate.
func newTestHealthAPI(t *testing.T, certPEM []byte) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	certSvc := service.NewCertificateService(certPEM)
	RegisterHealthRoutes(api, certSvc, nil)
	return api
}

// newTestHealthAPIAs builds a health-routes test API that injects the given
// caller groups via middleware.SetGroups so the MF-8 GlobalOperatorGroup gate
// fires correctly in tests. certMgr may be nil to exercise the 501 path.
func newTestHealthAPIAs(t *testing.T, certPEM []byte, groups []string, certMgr *service.CertManager) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	certSvc := service.NewCertificateService(certPEM)
	api.UseMiddleware(injectGroups(groups))
	RegisterHealthRoutes(api, certSvc, certMgr)
	return api
}

// injectGroups returns a Huma middleware that stores a caller group slice on
// the request context — standing in for the RequireAuth + SetGroups chain that
// runs in production.
func injectGroups(groups []string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		goCtx := middleware.SetGroups(ctx.Context(), groups)
		next(huma.WithContext(ctx, goCtx))
	}
}

// generateTestCert creates a self-signed test certificate
func generateTestCert(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test SAML IdP",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

func TestHealthCheck(t *testing.T) {
	api := newTestHealthAPI(t, nil)

	resp := api.Get("/api/v1/health")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
	assert.NotEmpty(t, result["timestamp"])
}

func TestCertificateHealth_ReturnsCertArray(t *testing.T) {
	// Generate a certificate valid for 365 days
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	certPEM := generateTestCert(t, notBefore, notAfter)

	api := newTestHealthAPI(t, certPEM)

	resp := api.Get("/api/v1/health/certificates")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result struct {
		Certificates []map[string]interface{} `json:"certificates"`
	}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	require.Len(t, result.Certificates, 1, "expected exactly one certificate entry")
	cert := result.Certificates[0]

	// Verify lifecycle fields
	assert.NotEmpty(t, cert["id"])
	assert.Equal(t, "active", cert["status"])

	// Verify certificate details
	assert.Equal(t, "Test SAML IdP", cert["subject"])
	assert.Equal(t, "Test SAML IdP", cert["issuer"]) // Self-signed cert
	assert.NotEmpty(t, cert["notBefore"])
	assert.NotEmpty(t, cert["notAfter"])
	assert.NotEmpty(t, cert["fingerprint"])
	assert.Contains(t, cert["fingerprint"].(string), ":")
	assert.InDelta(t, 365, cert["daysRemaining"].(float64), 1)
	assert.False(t, cert["isExpired"].(bool))
	assert.NotEmpty(t, cert["pemBase64"])

	// Verify id is derived from fingerprint (first 8 hex chars without colons)
	fp := cert["fingerprint"].(string)
	expectedID := ""
	for _, c := range fp {
		if c != ':' {
			expectedID += string(c)
		}
	}
	if len(expectedID) > 8 {
		expectedID = expectedID[:8]
	}
	assert.Equal(t, expectedID, cert["id"])

	// Verify pemBase64 is valid base64
	pemBase64Str := cert["pemBase64"].(string)
	decoded, err := base64.StdEncoding.DecodeString(pemBase64Str)
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

func TestCertificateHealth_NoCert(t *testing.T) {
	api := newTestHealthAPI(t, nil)

	resp := api.Get("/api/v1/health/certificates")
	assert.Equal(t, http.StatusServiceUnavailable, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result["detail"].(string), "certificate not available")
}

func TestCertificateHealth_ExpiredCert(t *testing.T) {
	// Generate an expired certificate
	notBefore := time.Now().Add(-365 * 24 * time.Hour)
	notAfter := time.Now().Add(-1 * 24 * time.Hour)
	certPEM := generateTestCert(t, notBefore, notAfter)

	api := newTestHealthAPI(t, certPEM)

	resp := api.Get("/api/v1/health/certificates")
	assert.Equal(t, http.StatusOK, resp.Code)

	var result struct {
		Certificates []map[string]interface{} `json:"certificates"`
	}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)

	require.Len(t, result.Certificates, 1)
	cert := result.Certificates[0]
	assert.Equal(t, "active", cert["status"])
	assert.True(t, cert["isExpired"].(bool))
	assert.True(t, cert["daysRemaining"].(float64) < 0)
}

// --- MF-8: GlobalOperatorGroup gate on cert lifecycle POST handlers ----------

// TestCertificateCSR_NotConfigured_Returns501 verifies that a global operator
// calling the CSR endpoint with cert management not wired gets a 501 (not a
// 403). The cert-management check is reached only after the authz gate passes.
func TestCertificateCSR_NotConfigured_Returns501(t *testing.T) {
	api := newTestHealthAPIAs(t, nil, []string{middleware.GlobalOperatorGroup}, nil)

	resp := api.Post("/api/v1/certificates/csr", map[string]any{"role": "active"})
	assert.Equal(t, http.StatusNotImplemented, resp.Code)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result["detail"].(string), "certificate management not configured")
}

// TestCertificateImport_NotConfigured_Returns501 — same, for the import path.
func TestCertificateImport_NotConfigured_Returns501(t *testing.T) {
	api := newTestHealthAPIAs(t, nil, []string{middleware.GlobalOperatorGroup}, nil)

	resp := api.Post("/api/v1/certificates/import", map[string]any{"role": "active", "certPem": "x"})
	assert.Equal(t, http.StatusNotImplemented, resp.Code)
}

// TestCertificatePromoteBackup_NotConfigured_Returns501 — same, for promote.
func TestCertificatePromoteBackup_NotConfigured_Returns501(t *testing.T) {
	api := newTestHealthAPIAs(t, nil, []string{middleware.GlobalOperatorGroup}, nil)

	resp := api.Post("/api/v1/certificates/promote-backup")
	assert.Equal(t, http.StatusNotImplemented, resp.Code)
}

// TestCertificateCSR_PerTenantAdmin_Returns403 is the MF-8 regression: a caller
// that holds the per-tenant Admins group (but NOT GlobalOperatorGroup) must not
// be able to drive CSR generation — the endpoint acts on the shared KMS key and
// would affect every tenant. The gate fires BEFORE the configuration check, so
// the response is 403, not 501.
func TestCertificateCSR_PerTenantAdmin_Returns403(t *testing.T) {
	api := newTestHealthAPIAs(t, nil, []string{"Admins"}, nil)

	resp := api.Post("/api/v1/certificates/csr", map[string]any{"role": "active"})
	assert.Equal(t, http.StatusForbidden, resp.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Contains(t, result["detail"].(string), "gateway-global operation reserved for global operators")
}

// TestCertificateImport_PerTenantAdmin_Returns403 — same, for import-certificate.
// import pins a CA leaf onto the shared signing key, changing the trust anchor
// for every tenant's SAML metadata consumer.
func TestCertificateImport_PerTenantAdmin_Returns403(t *testing.T) {
	api := newTestHealthAPIAs(t, nil, []string{"Admins"}, nil)

	resp := api.Post("/api/v1/certificates/import", map[string]any{"role": "active", "certPem": "x"})
	assert.Equal(t, http.StatusForbidden, resp.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Contains(t, result["detail"].(string), "gateway-global operation reserved for global operators")
}

// TestCertificatePromoteBackup_PerTenantAdmin_Returns403 — same, for
// promote-backup. Promoting the backup cert changes which cert is active for
// the WHOLE IdP — a gateway-global side effect.
func TestCertificatePromoteBackup_PerTenantAdmin_Returns403(t *testing.T) {
	api := newTestHealthAPIAs(t, nil, []string{"Admins"}, nil)

	resp := api.Post("/api/v1/certificates/promote-backup")
	assert.Equal(t, http.StatusForbidden, resp.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Contains(t, result["detail"].(string), "gateway-global operation reserved for global operators")
}
