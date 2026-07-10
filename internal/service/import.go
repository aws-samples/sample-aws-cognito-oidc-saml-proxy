package service

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/safehttp"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// MetadataFetcher fetches SP metadata XML from a URL.
type MetadataFetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// HTTPMetadataFetcher fetches metadata over HTTP.
type HTTPMetadataFetcher struct{}

// Fetch retrieves SAML metadata from the specified URL. The URL is fetched
// through an SSRF-hardened client that refuses non-public destinations, so a
// metadata URL cannot be used to reach internal services or the instance
// metadata endpoint. Metadata is trust material (signing certificates and
// endpoint URLs), so the fetch is restricted to https — a plaintext http://
// URL is refused to stop an on-path attacker from swapping the signing cert.
func (f *HTTPMetadataFetcher) Fetch(ctx context.Context, metadataURL string) ([]byte, error) {
	if err := safehttp.ValidateTrustURL(metadataURL); err != nil {
		return nil, fmt.Errorf("metadata URL rejected: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build metadata request: %w", err)
	}

	resp, err := safehttp.TrustClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata URL returned status %d", resp.StatusCode)
	}

	// Limit to 1MB to prevent memory exhaustion
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// MetadataImportService handles importing SAML SP metadata and creating applications.
type MetadataImportService struct {
	apps    domain.AppWriter
	fetcher MetadataFetcher
}

// NewMetadataImportService creates a new metadata import service.
func NewMetadataImportService(apps domain.AppWriter, fetcher MetadataFetcher) *MetadataImportService {
	return &MetadataImportService{
		apps:    apps,
		fetcher: fetcher,
	}
}

// ImportResult contains the created application and its configuration.
type ImportResult struct {
	AppID      string
	App        *tenant.Application
	SAMLConfig *tenant.SAMLConfig
}

// Import fetches SP metadata from a URL, parses it, and creates an application.
func (s *MetadataImportService) Import(ctx context.Context, tenantSlug, metadataURL, sourceID, displayName string) (*ImportResult, error) {
	if metadataURL == "" {
		return nil, fmt.Errorf("metadataUrl is required")
	}

	// Fetch metadata XML
	body, err := s.fetcher.Fetch(ctx, metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}

	// Parse EntityDescriptor
	var entity saml.EntityDescriptor
	if err := xml.Unmarshal(body, &entity); err != nil {
		return nil, fmt.Errorf("failed to parse metadata XML: %w", err)
	}

	if entity.EntityID == "" {
		return nil, fmt.Errorf("metadata does not contain an entityID")
	}

	// Extract ACS URLs from the first SPSSODescriptor
	var acsURL string
	var acsURLs []string
	var signingCertPEM, encryptionCertPEM string

	if len(entity.SPSSODescriptors) > 0 {
		sp := entity.SPSSODescriptors[0]

		// Extract ACS URLs
		for _, acs := range sp.AssertionConsumerServices {
			acsURLs = append(acsURLs, acs.Location)
		}
		if len(acsURLs) > 0 {
			acsURL = acsURLs[0]
			acsURLs = acsURLs[1:]
		}

		// Extract signing and encryption certificates from KeyDescriptors
		for _, kd := range sp.KeyDescriptors {
			if len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
				continue
			}
			certData := kd.KeyInfo.X509Data.X509Certificates[0].Data
			pemBlock := toPEM(certData)

			switch strings.ToLower(kd.Use) {
			case "signing":
				signingCertPEM = pemBlock
			case "encryption":
				encryptionCertPEM = pemBlock
			default:
				// If use is unspecified, treat as both signing and encryption
				if signingCertPEM == "" {
					signingCertPEM = pemBlock
				}
				if encryptionCertPEM == "" {
					encryptionCertPEM = pemBlock
				}
			}
		}
	}

	// Use entity ID as display name if not provided
	if displayName == "" {
		displayName = entity.EntityID
	}

	// Create application
	app := &tenant.Application{
		DisplayName: displayName,
		Protocol:    "saml",
		SourceID:    sourceID,
		Status:      "active",
	}

	// Create SAML configuration with sensible defaults
	samlCfg := &tenant.SAMLConfig{
		EntityID:           entity.EntityID,
		AcsURL:             acsURL,
		AcsURLs:            acsURLs,
		MetadataURL:        metadataURL,
		SigningCertPem:     signingCertPEM,
		EncryptionCertPem:  encryptionCertPEM,
		NameIDFormat:       "persistent",
		NameIDSource:       "sub",
		SignResponse:       true,
		SignAssertion:      true,
		EncryptAssertion:   false,
		SessionDurationSec: 3600,
		ClockSkewSec:       180,
	}

	// Create the application in the repository
	id, err := s.apps.Create(ctx, tenantSlug, app, samlCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create application: %w", err)
	}

	return &ImportResult{
		AppID:      id,
		App:        app,
		SAMLConfig: samlCfg,
	}, nil
}

// toPEM converts base64-encoded certificate data to PEM format.
func toPEM(base64Data string) string {
	// Clean whitespace from the base64 data
	cleaned := strings.Join(strings.Fields(base64Data), "")
	return "-----BEGIN CERTIFICATE-----\n" + cleaned + "\n-----END CERTIFICATE-----"
}
