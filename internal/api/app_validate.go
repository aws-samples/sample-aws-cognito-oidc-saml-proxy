package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// knownNameIDFormats is the set of recognized SAML NameID formats.
var knownNameIDFormats = map[string]bool{
	"persistent":  true,
	"transient":   true,
	"email":       true,
	"unspecified": true,
}

// registerValidateAppRoute registers the validate-application endpoint.
func registerValidateAppRoute(api huma.API, apps domain.AppReader) {
	huma.Register(api, huma.Operation{
		OperationID: "validate-application",
		Method:      http.MethodPost,
		Path:        "/api/v1/applications/{id}/validate",
		Summary:     "Validate application SAML configuration",
		Description: "Validates the SAML configuration of an application and returns any errors or warnings",
		Tags:        []string{"Applications"},
	}, func(ctx context.Context, input *ValidateAppInput) (*ValidateAppOutput, error) {
		slug, ok := tenantSlugFromContext(ctx)
		if !ok {
			return nil, huma.Error403Forbidden("tenant context required")
		}

		app, err := apps.Get(ctx, slug, input.ID)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error404NotFound("application not found")
			}
			return nil, huma.Error500InternalServerError("failed to get application", err)
		}

		if !strings.EqualFold(app.Protocol, "saml") {
			return nil, huma.Error400BadRequest("validation is only supported for SAML applications")
		}

		samlCfg, err := apps.GetSAMLConfig(ctx, slug, input.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to get SAML config", err)
		}

		validationErrors, warnings := validateSAMLConfig(samlCfg)

		out := &ValidateAppOutput{}
		out.Body.Valid = len(validationErrors) == 0
		out.Body.Errors = validationErrors
		out.Body.Warnings = warnings
		return out, nil
	})
}

// validateSAMLConfig checks a SAML configuration and returns errors and warnings.
func validateSAMLConfig(cfg *tenant.SAMLConfig) (validationErrors []string, warnings []string) {
	if cfg.EntityID == "" {
		validationErrors = append(validationErrors, "entityId is required")
	}

	if cfg.AcsURL == "" {
		validationErrors = append(validationErrors, "acsUrl is required")
	} else if _, err := url.ParseRequestURI(cfg.AcsURL); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("acsUrl is not a valid URL: %v", err))
	}

	if cfg.NameIDFormat != "" && !knownNameIDFormats[cfg.NameIDFormat] {
		validationErrors = append(validationErrors, fmt.Sprintf("unrecognized nameIdFormat %q; expected one of: persistent, transient, email, unspecified", cfg.NameIDFormat))
	}

	if cfg.SigningCertPem != "" {
		if errs, warns := validatePEMCert(cfg.SigningCertPem, "signing"); len(errs) > 0 || len(warns) > 0 {
			validationErrors = append(validationErrors, errs...)
			warnings = append(warnings, warns...)
		}
	}

	if cfg.EncryptionCertPem != "" {
		if errs, warns := validatePEMCert(cfg.EncryptionCertPem, "encryption"); len(errs) > 0 || len(warns) > 0 {
			validationErrors = append(validationErrors, errs...)
			warnings = append(warnings, warns...)
		}
	}

	// The gateway always signs both the response and the assertion; a stored
	// record claiming otherwise describes behaviour that does not exist (M-8).
	if !cfg.SignResponse || !cfg.SignAssertion {
		validationErrors = append(validationErrors, errSigningAlwaysOnValid)
	}

	if cfg.EncryptAssertion && cfg.EncryptionCertPem == "" {
		validationErrors = append(validationErrors, errEncryptionNeedsCert)
	}

	// Not settable through the API, but an imported or migrated record may
	// carry it. The SSO path refuses such an SP (SPProvider fails closed), so
	// surface that here rather than letting the admin discover it at login.
	if cfg.WantAuthnRequestsSigned {
		validationErrors = append(validationErrors, errWantAuthnReqSigned)
	}

	if cfg.SessionDurationSec <= 0 {
		warnings = append(warnings, "sessionDurationSec should be positive")
	} else if msg := rangeError("sessionDurationSec", cfg.SessionDurationSec, tenant.SessionDurationMinSec, tenant.SessionDurationMaxSec); msg != "" {
		validationErrors = append(validationErrors, msg)
	}

	if msg := rangeError("clockSkewSec", cfg.ClockSkewSec, tenant.ClockSkewMinSec, tenant.ClockSkewMaxSec); msg != "" {
		validationErrors = append(validationErrors, msg)
	}

	// Ensure slices are non-nil for JSON marshalling.
	if validationErrors == nil {
		validationErrors = []string{}
	}
	if warnings == nil {
		warnings = []string{}
	}
	return validationErrors, warnings
}

// Refusal messages for SAML configuration the gateway cannot honour (M-8).
// Shared by validateSAMLConfigInput (create/update, 422) so tests and docs can
// reference one wording.
const (
	errSigningAlwaysOn      = "the gateway always signs both the SAML response and the assertion; omit signResponse/signAssertion or set them to true"
	errEncryptionNeedsCert  = "encryptAssertion requires an SP encryption certificate; import the SP metadata that contains one"
	errPerTenantKMSKey      = "per-tenant KMS signing keys are not supported; all tenants sign with the gateway key"
	errWantAuthnReqSigned   = "wantAuthnRequestsSigned=true cannot be honoured: AuthnRequest signature verification is not implemented; the SSO endpoint refuses this SP"
	errSigningAlwaysOnValid = "signResponse and signAssertion must both be true: the gateway always signs the SAML response and the assertion"
)

// validateSAMLConfigInput checks the SAML block of a create/update request
// against what the protocol path actually enforces, so a stored configuration
// never promises behaviour the gateway does not deliver (finding M-8). existing
// is the stored config on update (nil on create); it supplies the imported
// certificates the input itself never carries. Returns human-readable errors
// (empty when acceptable); callers answer 422.
func validateSAMLConfigInput(s *SAMLConfigInput, existing *tenant.SAMLConfig) []string {
	var errs []string
	if s == nil {
		return errs
	}

	// Signing is unconditional. Refuse an explicit false rather than silently
	// storing a flag the IdP ignores.
	if (s.SignResponse != nil && !*s.SignResponse) || (s.SignAssertion != nil && !*s.SignAssertion) {
		errs = append(errs, errSigningAlwaysOn)
	}

	// Encryption needs the SP's certificate, which only metadata import stores.
	// On create nothing can be stored yet, so the flag is always refused.
	if s.EncryptAssertion != nil && *s.EncryptAssertion {
		if existing == nil || existing.EncryptionCertPem == "" {
			errs = append(errs, errEncryptionNeedsCert)
		}
	}

	// 0 means "use the default" for both durations.
	if s.SessionDurationSec != 0 {
		if msg := rangeError("sessionDurationSec", s.SessionDurationSec, tenant.SessionDurationMinSec, tenant.SessionDurationMaxSec); msg != "" {
			errs = append(errs, msg)
		}
	}
	if s.ClockSkewSec != 0 {
		if msg := rangeError("clockSkewSec", s.ClockSkewSec, tenant.ClockSkewMinSec, tenant.ClockSkewMaxSec); msg != "" {
			errs = append(errs, msg)
		}
	}
	return errs
}

// validateOIDCConfigInput bounds the token lifetimes of a create/update
// request (0 means "use the default"). Returns human-readable errors; callers
// answer 422.
func validateOIDCConfigInput(o *OIDCConfigInput) []string {
	var errs []string
	if o == nil {
		return errs
	}
	if o.IDTokenLifetimeSec != 0 {
		if msg := rangeError("idTokenLifetimeSec", o.IDTokenLifetimeSec, tenant.TokenLifetimeMinSec, tenant.TokenLifetimeMaxSec); msg != "" {
			errs = append(errs, msg)
		}
	}
	if o.AccessTokenLifetimeSec != 0 {
		if msg := rangeError("accessTokenLifetimeSec", o.AccessTokenLifetimeSec, tenant.TokenLifetimeMinSec, tenant.TokenLifetimeMaxSec); msg != "" {
			errs = append(errs, msg)
		}
	}
	return errs
}

// rangeError returns a message when v lies outside [lo, hi], else "".
func rangeError(field string, v, lo, hi int) string {
	if v < lo || v > hi {
		return fmt.Sprintf("%s must be between %d and %d seconds", field, lo, hi)
	}
	return ""
}

// validatePEMCert checks a PEM-encoded certificate for validity and expiry.
func validatePEMCert(pemData, label string) (errs []string, warns []string) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return []string{fmt.Sprintf("%s certificate is not valid PEM", label)}, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []string{fmt.Sprintf("%s certificate failed to parse: %v", label, err)}, nil
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		errs = append(errs, fmt.Sprintf("%s certificate expired on %s", label, cert.NotAfter.Format(time.RFC3339)))
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		warns = append(warns, fmt.Sprintf("%s certificate expires soon: %s", label, cert.NotAfter.Format(time.RFC3339)))
	}

	return errs, warns
}

// validateLoginConfig validates the custom-login-page configuration on an
// application. Returns a list of human-readable errors (empty when valid).
//
// Rules:
//   - Each trustedLoginRedirectUris entry must be a valid https URL.
//   - If customLoginUrl is set, it must be a valid https URL AND be covered by
//     the trustedLoginRedirectUris allowlist (defense against open redirect).
func validateLoginConfig(app *tenant.Application) []string {
	var errs []string

	for _, entry := range app.TrustedLoginRedirectURIs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(entry)
		if err != nil || u.Host == "" {
			errs = append(errs, fmt.Sprintf("trustedLoginRedirectUris entry %q is not a valid URL", entry))
			continue
		}
		if !strings.EqualFold(u.Scheme, "https") {
			errs = append(errs, fmt.Sprintf("trustedLoginRedirectUris entry %q must use https", entry))
		}
	}

	custom := strings.TrimSpace(app.CustomLoginURL)
	if custom == "" {
		return errs
	}

	u, err := url.Parse(custom)
	if err != nil || u.Host == "" {
		errs = append(errs, fmt.Sprintf("customLoginUrl %q is not a valid URL", custom))
		return errs
	}
	if !strings.EqualFold(u.Scheme, "https") {
		errs = append(errs, "customLoginUrl must use https")
	}
	if len(app.TrustedLoginRedirectURIs) == 0 {
		errs = append(errs, "customLoginUrl requires at least one trustedLoginRedirectUris entry that covers it")
	} else if !app.IsTrustedLoginRedirect(custom) {
		errs = append(errs, "customLoginUrl must be covered by trustedLoginRedirectUris")
	}

	return errs
}
