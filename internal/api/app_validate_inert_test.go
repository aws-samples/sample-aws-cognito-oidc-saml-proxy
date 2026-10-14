package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// M-8 regressions: configuration fields the protocol path cannot honour are
// refused with 422 instead of being stored as inert promises, and the fields
// that ARE honoured are bounded.

func TestCreateApplication_SignResponseFalse_Rejected(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)

	for _, body := range []string{
		`{"displayName":"SP","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs","signResponse":false}}`,
		`{"displayName":"SP","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs","signAssertion":false}}`,
	} {
		resp := api.Post("/api/v1/applications", strings.NewReader(body))
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())
		assert.Contains(t, resp.Body.String(), "always signs")
	}

	// Nothing was persisted by the refused requests.
	apps, err := appStore.List(context.Background(), testTenantSlug)
	require.NoError(t, err)
	assert.Empty(t, apps)

	// Explicit true (what the frontend now always sends) is accepted.
	resp := api.Post("/api/v1/applications", strings.NewReader(
		`{"displayName":"SP","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs","signResponse":true,"signAssertion":true}}`))
	assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
}

func TestCreateApplication_EncryptAssertionWithoutCert_Rejected(t *testing.T) {
	api, _, _ := newTestAPIWithMiddleware(t)

	resp := api.Post("/api/v1/applications", strings.NewReader(
		`{"displayName":"SP","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs","encryptAssertion":true}}`))
	assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())
	assert.Contains(t, resp.Body.String(), "encryption certificate")
}

func TestCreateApplication_SessionDurationOutOfBounds_Rejected(t *testing.T) {
	api, _, _ := newTestAPIWithMiddleware(t)

	cases := map[string]string{
		"sessionDurationSec too low":  `"sessionDurationSec":10`,
		"sessionDurationSec too high": `"sessionDurationSec":100000`,
		"clockSkewSec too high":       `"clockSkewSec":601`,
		"clockSkewSec negative":       `"clockSkewSec":-1`,
	}
	for name, field := range cases {
		t.Run(name, func(t *testing.T) {
			resp := api.Post("/api/v1/applications", strings.NewReader(
				`{"displayName":"SP","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs",`+field+`}}`))
			assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())
			assert.Contains(t, resp.Body.String(), "must be between")
		})
	}

	// In-bounds values and 0 (default) are accepted.
	resp := api.Post("/api/v1/applications", strings.NewReader(
		`{"displayName":"SP","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs","sessionDurationSec":300,"clockSkewSec":0}}`))
	assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
}

func TestCreateOIDCApplication_TokenLifetimeOutOfBounds_Rejected(t *testing.T) {
	api, _, _ := newTestAPIWithMiddleware(t)

	for _, field := range []string{`"accessTokenLifetimeSec":5`, `"idTokenLifetimeSec":5`, `"accessTokenLifetimeSec":90000`} {
		resp := api.Post("/api/v1/applications", strings.NewReader(
			`{"displayName":"RP","protocol":"oidc","oidc":{"redirectURIs":["https://app.example.com/cb"],"grantTypes":["authorization_code"],"responseTypes":["code"],"scopes":["openid"],"tokenEndpointAuthMethod":"none",`+field+`}}`))
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())
		assert.Contains(t, resp.Body.String(), "must be between 60 and 86400")
	}
}

func TestUpdateApplication_RefusesInertSAMLFields(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)
	id, err := appStore.Create(context.Background(), testTenantSlug,
		&tenant.Application{DisplayName: "SP", Protocol: "saml", Status: "active"},
		&tenant.SAMLConfig{EntityID: "https://sp.example.com", AcsURL: "https://sp.example.com/acs", SignResponse: true, SignAssertion: true, SessionDurationSec: 3600, ClockSkewSec: 180})
	require.NoError(t, err)

	for _, field := range []string{`"signResponse":false`, `"encryptAssertion":true`, `"sessionDurationSec":10`} {
		resp := api.Put("/api/v1/applications/"+id, strings.NewReader(
			`{"displayName":"SP renamed","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs",`+field+`}}`))
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())
	}

	// A refused update must not have touched the application record either.
	app, err := appStore.Get(context.Background(), testTenantSlug, id)
	require.NoError(t, err)
	assert.Equal(t, "SP", app.DisplayName)
}

func TestUpdateOIDCApplication_TokenLifetimeOutOfBounds_Rejected(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)
	id, err := appStore.Create(context.Background(), testTenantSlug,
		&tenant.Application{DisplayName: "RP", Protocol: "oidc", Status: "active"}, nil)
	require.NoError(t, err)

	resp := api.Put("/api/v1/applications/"+id, strings.NewReader(
		`{"displayName":"RP","protocol":"oidc","oidc":{"redirectURIs":["https://app.example.com/cb"],"tokenEndpointAuthMethod":"none","accessTokenLifetimeSec":5}}`))
	assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())
}

// TestUpdateApplication_PreservesImportedCertificates: the update input never
// carries the SP certificates (only metadata import writes them), so an edit
// must carry them forward rather than wipe them — and once a cert is stored,
// encryptAssertion may be switched on.
func TestUpdateApplication_PreservesImportedCertificates(t *testing.T) {
	api, appStore, _ := newTestAPIWithMiddleware(t)
	ctx := context.Background()
	id, err := appStore.Create(ctx, testTenantSlug,
		&tenant.Application{DisplayName: "SP", Protocol: "saml", Status: "active"},
		&tenant.SAMLConfig{
			EntityID: "https://sp.example.com", AcsURL: "https://sp.example.com/acs",
			SigningCertPem:    "-----BEGIN CERTIFICATE-----\nsigning\n-----END CERTIFICATE-----",
			EncryptionCertPem: "-----BEGIN CERTIFICATE-----\nencryption\n-----END CERTIFICATE-----",
			SignResponse:      true, SignAssertion: true, SessionDurationSec: 3600, ClockSkewSec: 180,
		})
	require.NoError(t, err)

	// Plain edit (new display name, encryption still off).
	resp := api.Put("/api/v1/applications/"+id, strings.NewReader(
		`{"displayName":"SP renamed","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs","sessionDurationSec":7200}}`))
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	cfg, err := appStore.GetSAMLConfig(ctx, testTenantSlug, id)
	require.NoError(t, err)
	assert.Contains(t, cfg.SigningCertPem, "signing")
	assert.Contains(t, cfg.EncryptionCertPem, "encryption")
	assert.Equal(t, 7200, cfg.SessionDurationSec)
	assert.False(t, cfg.EncryptAssertion)

	// With a stored encryption cert the flag can now be enabled.
	resp = api.Put("/api/v1/applications/"+id, strings.NewReader(
		`{"displayName":"SP renamed","protocol":"saml","saml":{"entityId":"https://sp.example.com","acsUrl":"https://sp.example.com/acs","encryptAssertion":true}}`))
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	cfg, err = appStore.GetSAMLConfig(ctx, testTenantSlug, id)
	require.NoError(t, err)
	assert.True(t, cfg.EncryptAssertion)
	assert.Contains(t, cfg.EncryptionCertPem, "encryption", "second edit must keep the cert too")
}

func TestCreateTenant_KMSKeyRejected(t *testing.T) {
	api, tenantStore := newTestTenantAPI(t)

	for _, body := range []string{
		`{"slug":"acme","displayName":"Acme","kmsKeyId":"1234abcd-12ab-34cd-56ef-1234567890ab"}`,
		`{"slug":"acme","displayName":"Acme","kmsKeyArn":"arn:aws:kms:eu-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"}`,
	} {
		resp := api.Post("/api/v1/tenants", strings.NewReader(body))
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())
		assert.Contains(t, resp.Body.String(), "per-tenant KMS signing keys are not supported")
	}
	_, err := tenantStore.Get(context.Background(), "acme")
	assert.Error(t, err, "refused tenant must not be created")
}

func TestUpdateTenant_KMSKeyRejected(t *testing.T) {
	api, tenantStore := newTestTenantAPI(t)
	require.NoError(t, tenantStore.Create(context.Background(), &tenant.Tenant{
		Slug: "acme", DisplayName: "Acme", Status: "active", Plan: "standard",
	}))

	resp := api.Put("/api/v1/tenants/acme", strings.NewReader(`{"displayName":"Acme 2","kmsKeyId":"1234abcd-12ab-34cd-56ef-1234567890ab"}`))
	assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())

	got, err := tenantStore.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, "Acme", got.DisplayName, "refused update must not be applied")
	assert.Empty(t, got.KMSKeyID)
}

// TestValidateSAMLConfig_InertFields: the /validate endpoint reports stored
// records that promise behaviour the gateway does not deliver as errors.
func TestValidateSAMLConfig_InertFields(t *testing.T) {
	base := func() *tenant.SAMLConfig {
		return &tenant.SAMLConfig{
			EntityID: "https://sp.example.com", AcsURL: "https://sp.example.com/acs",
			NameIDFormat: "persistent", SignResponse: true, SignAssertion: true,
			SessionDurationSec: 3600, ClockSkewSec: 180,
		}
	}

	errs, _ := validateSAMLConfig(base())
	assert.Empty(t, errs)

	cfg := base()
	cfg.SignResponse = false
	errs, _ = validateSAMLConfig(cfg)
	assert.Contains(t, errs, errSigningAlwaysOnValid)

	cfg = base()
	cfg.SignAssertion = false
	errs, _ = validateSAMLConfig(cfg)
	assert.Contains(t, errs, errSigningAlwaysOnValid)

	cfg = base()
	cfg.EncryptAssertion = true
	errs, _ = validateSAMLConfig(cfg)
	assert.Contains(t, errs, errEncryptionNeedsCert)

	cfg = base()
	cfg.WantAuthnRequestsSigned = true
	errs, _ = validateSAMLConfig(cfg)
	assert.Contains(t, errs, errWantAuthnReqSigned)

	cfg = base()
	cfg.SessionDurationSec = 100000
	cfg.ClockSkewSec = 601
	errs, _ = validateSAMLConfig(cfg)
	assert.Len(t, errs, 2)
}

func TestValidateSAMLConfigInput_Table(t *testing.T) {
	f := false
	tr := true
	cases := []struct {
		name     string
		in       *SAMLConfigInput
		existing *tenant.SAMLConfig
		wantErrs int
	}{
		{"nil input", nil, nil, 0},
		{"empty input", &SAMLConfigInput{}, nil, 0},
		{"explicit true signing", &SAMLConfigInput{SignResponse: &tr, SignAssertion: &tr}, nil, 0},
		{"signResponse false", &SAMLConfigInput{SignResponse: &f}, nil, 1},
		{"signAssertion false", &SAMLConfigInput{SignAssertion: &f}, nil, 1},
		{"both false -> one error", &SAMLConfigInput{SignResponse: &f, SignAssertion: &f}, nil, 1},
		{"encrypt on create", &SAMLConfigInput{EncryptAssertion: &tr}, nil, 1},
		{"encrypt on update without cert", &SAMLConfigInput{EncryptAssertion: &tr}, &tenant.SAMLConfig{}, 1},
		{"encrypt on update with cert", &SAMLConfigInput{EncryptAssertion: &tr}, &tenant.SAMLConfig{EncryptionCertPem: "pem"}, 0},
		{"encrypt false never needs cert", &SAMLConfigInput{EncryptAssertion: &f}, nil, 0},
		{"durations in range", &SAMLConfigInput{SessionDurationSec: 86400, ClockSkewSec: 600}, nil, 0},
		{"durations default", &SAMLConfigInput{SessionDurationSec: 0, ClockSkewSec: 0}, nil, 0},
		{"durations out of range", &SAMLConfigInput{SessionDurationSec: 299, ClockSkewSec: 601}, nil, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Len(t, validateSAMLConfigInput(tc.in, tc.existing), tc.wantErrs)
		})
	}
}

func TestValidateOIDCConfigInput_Table(t *testing.T) {
	assert.Empty(t, validateOIDCConfigInput(nil))
	assert.Empty(t, validateOIDCConfigInput(&OIDCConfigInput{}))
	assert.Empty(t, validateOIDCConfigInput(&OIDCConfigInput{IDTokenLifetimeSec: 60, AccessTokenLifetimeSec: 86400}))
	assert.Len(t, validateOIDCConfigInput(&OIDCConfigInput{IDTokenLifetimeSec: 59}), 1)
	assert.Len(t, validateOIDCConfigInput(&OIDCConfigInput{AccessTokenLifetimeSec: 86401}), 1)
	assert.Len(t, validateOIDCConfigInput(&OIDCConfigInput{IDTokenLifetimeSec: -1, AccessTokenLifetimeSec: 1}), 2)
}
