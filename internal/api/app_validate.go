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

	if !cfg.SignResponse && !cfg.SignAssertion {
		warnings = append(warnings, "neither signResponse nor signAssertion is enabled")
	}

	if cfg.SessionDurationSec <= 0 {
		warnings = append(warnings, "sessionDurationSec should be positive")
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
