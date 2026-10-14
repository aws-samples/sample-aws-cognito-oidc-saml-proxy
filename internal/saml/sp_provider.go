package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// SPProvider implements saml.ServiceProviderProvider by looking up SP metadata
// from the AppStore (multi-tenant).
type SPProvider struct {
	appStore *store.AppStore
}

// NewSPProvider creates a new SPProvider.
func NewSPProvider(appStore *store.AppStore) *SPProvider {
	return &SPProvider{appStore: appStore}
}

// GetServiceProvider returns the EntityDescriptor for the SP identified by
// serviceProviderID (the SP's entity ID). Returns os.ErrNotExist when the SP
// is unknown or inactive.
//
// The lookup is scoped to the tenant on the request path (/t/{tenant}/...): a
// SAML entityID is unique only within a tenant, so resolving it without the
// tenant would let one tenant's SP metadata satisfy another tenant's request.
// A request that reaches this provider without a tenant path segment is
// treated as an unknown SP rather than falling back to a cross-tenant scan.
func (p *SPProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	if r == nil {
		return nil, os.ErrNotExist
	}
	tenantSlug := chi.URLParam(r, "tenant")
	if tenantSlug == "" {
		return nil, os.ErrNotExist
	}

	app, samlCfg, err := p.appStore.GetByTenantEntityID(r.Context(), tenantSlug, serviceProviderID)
	if err != nil {
		return nil, os.ErrNotExist
	}

	if app.Status != "active" {
		return nil, os.ErrNotExist
	}

	if samlCfg == nil {
		return nil, os.ErrNotExist
	}

	// Fail closed on a setting the gateway cannot honour (finding M-8). An SP
	// whose metadata demands signed AuthnRequests expects the IdP to verify the
	// signature; this IdP does not, so serving it would silently accept forged
	// requests the SP's administrator believes are rejected. A non-ErrNotExist
	// error makes crewjam return 500 and log the reason instead of 404.
	if samlCfg.WantAuthnRequestsSigned {
		slog.Error("saml sp: WantAuthnRequestsSigned is set but AuthnRequest signature verification is not implemented; refusing SP",
			"tenant", tenantSlug, "entityID", serviceProviderID, "appID", app.ID)
		return nil, errAuthnRequestSignatureUnsupported
	}

	return buildEntityDescriptor(samlCfg), nil
}

// errAuthnRequestSignatureUnsupported is returned by GetServiceProvider for an
// SP that requires signed AuthnRequests. It deliberately does not wrap
// os.ErrNotExist so crewjam treats it as a server error, not an unknown SP.
var errAuthnRequestSignatureUnsupported = errors.New("saml sp requires signed AuthnRequests (WantAuthnRequestsSigned) but AuthnRequest signature verification is not implemented")

// buildEntityDescriptor converts a tenant.SAMLConfig to a saml.EntityDescriptor.
func buildEntityDescriptor(cfg *tenant.SAMLConfig) *saml.EntityDescriptor {
	ed := &saml.EntityDescriptor{
		EntityID: cfg.EntityID,
	}

	spSSO := saml.SPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			},
		},
	}

	// Add ACS endpoints. Use AcsURLs if available, fall back to single AcsURL.
	acsURLs := cfg.AcsURLs
	if len(acsURLs) == 0 && cfg.AcsURL != "" {
		acsURLs = []string{cfg.AcsURL}
	}
	for i, acsURL := range acsURLs {
		isDefault := i == 0
		spSSO.AssertionConsumerServices = append(spSSO.AssertionConsumerServices, saml.IndexedEndpoint{
			Binding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
			Location:  acsURL,
			Index:     i,
			IsDefault: &isDefault,
		})
	}

	// Add signing key descriptor if present.
	if cfg.SigningCertPem != "" {
		if kd, err := buildKeyDescriptor(cfg.SigningCertPem, "signing"); err == nil {
			spSSO.KeyDescriptors = append(spSSO.KeyDescriptors, kd)
		}
	}

	// Advertise the encryption key descriptor only when the administrator
	// enabled EncryptAssertion AND an encryption certificate is stored. crewjam
	// encrypts whenever the SP descriptor carries an encryption cert, so a
	// stored certificate alone must not switch encryption on behind the flag's
	// back (finding M-8). The API refuses EncryptAssertion without a cert.
	if cfg.EncryptAssertion && cfg.EncryptionCertPem != "" {
		if kd, err := buildKeyDescriptor(cfg.EncryptionCertPem, "encryption"); err == nil {
			spSSO.KeyDescriptors = append(spSSO.KeyDescriptors, kd)
		}
	}

	ed.SPSSODescriptors = []saml.SPSSODescriptor{spSSO}
	return ed
}

// buildKeyDescriptor parses a PEM certificate and creates a saml.KeyDescriptor.
func buildKeyDescriptor(certPEM string, use string) (saml.KeyDescriptor, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return saml.KeyDescriptor{}, os.ErrNotExist
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return saml.KeyDescriptor{}, err
	}

	return saml.KeyDescriptor{
		Use: use,
		KeyInfo: saml.KeyInfo{
			X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{
					{Data: base64.StdEncoding.EncodeToString(cert.Raw)},
				},
			},
		},
	}, nil
}
