package service

import (
	"context"
	"strings"
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// mockMetadataFetcher returns predefined metadata for testing.
type mockMetadataFetcher struct {
	data []byte
	err  error
}

func (m *mockMetadataFetcher) Fetch(_ context.Context, _ string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.data, nil
}

// mockAppWriter records creates for verification.
type mockAppWriter struct {
	created   []*tenant.Application
	createdID string
}

func (m *mockAppWriter) Create(_ context.Context, tenantSlug string, app *tenant.Application, samlCfg *tenant.SAMLConfig) (string, error) {
	m.created = append(m.created, app)
	if m.createdID == "" {
		m.createdID = "app_test123"
	}
	return m.createdID, nil
}

func (m *mockAppWriter) Update(_ context.Context, _ string, _ *tenant.Application) error {
	return nil
}

func (m *mockAppWriter) UpdateSAMLConfig(_ context.Context, _, _ string, _ *tenant.SAMLConfig) error {
	return nil
}

func (m *mockAppWriter) UpdateOIDCConfig(_ context.Context, _, _ string, _ *tenant.OIDCConfig) error {
	return nil
}

func (m *mockAppWriter) SetStatus(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *mockAppWriter) Delete(_ context.Context, _, _ string) error {
	return nil
}

func TestMetadataImportService_Import(t *testing.T) {
	// Valid SAML SP metadata with entity ID, ACS URL, and certificates
	validMetadata := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIBkTCB+wIJAKHHCgVZU7POMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRlc3RzcDAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMMBnRlc3RzcDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIBkTCB+wIJAKHHCgVZU7POMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRlc3RzcDAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMMBnRlc3RzcDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://sp.example.com/acs"
                              index="0" isDefault="true"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://sp.example.com/acs-backup"
                              index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`)

	t.Run("successful import", func(t *testing.T) {
		fetcher := &mockMetadataFetcher{data: validMetadata}
		appWriter := &mockAppWriter{}
		svc := NewMetadataImportService(appWriter, fetcher)

		result, err := svc.Import(context.Background(), "tenant1", "https://sp.example.com/metadata", "src_cognito", "Test App")
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		if result.AppID != "app_test123" {
			t.Errorf("expected appID=app_test123, got %s", result.AppID)
		}

		if result.App.DisplayName != "Test App" {
			t.Errorf("expected displayName=Test App, got %s", result.App.DisplayName)
		}

		if result.App.Protocol != "saml" {
			t.Errorf("expected protocol=saml, got %s", result.App.Protocol)
		}

		if result.SAMLConfig.EntityID != "https://sp.example.com" {
			t.Errorf("expected entityID=https://sp.example.com, got %s", result.SAMLConfig.EntityID)
		}

		if result.SAMLConfig.AcsURL != "https://sp.example.com/acs" {
			t.Errorf("expected acsURL=https://sp.example.com/acs, got %s", result.SAMLConfig.AcsURL)
		}

		if len(result.SAMLConfig.AcsURLs) != 1 || result.SAMLConfig.AcsURLs[0] != "https://sp.example.com/acs-backup" {
			t.Errorf("expected secondary ACS URL, got %v", result.SAMLConfig.AcsURLs)
		}

		if !strings.Contains(result.SAMLConfig.SigningCertPem, "BEGIN CERTIFICATE") {
			t.Errorf("expected PEM-formatted signing cert, got %s", result.SAMLConfig.SigningCertPem)
		}

		if !strings.Contains(result.SAMLConfig.EncryptionCertPem, "BEGIN CERTIFICATE") {
			t.Errorf("expected PEM-formatted encryption cert, got %s", result.SAMLConfig.EncryptionCertPem)
		}
	})

	t.Run("defaults display name to entity ID", func(t *testing.T) {
		fetcher := &mockMetadataFetcher{data: validMetadata}
		appWriter := &mockAppWriter{}
		svc := NewMetadataImportService(appWriter, fetcher)

		result, err := svc.Import(context.Background(), "tenant1", "https://sp.example.com/metadata", "src_cognito", "")
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		if result.App.DisplayName != "https://sp.example.com" {
			t.Errorf("expected displayName to default to entityID, got %s", result.App.DisplayName)
		}
	})

	t.Run("empty metadata URL", func(t *testing.T) {
		fetcher := &mockMetadataFetcher{data: validMetadata}
		appWriter := &mockAppWriter{}
		svc := NewMetadataImportService(appWriter, fetcher)

		_, err := svc.Import(context.Background(), "tenant1", "", "src_cognito", "Test App")
		if err == nil {
			t.Fatal("expected error for empty metadata URL")
		}
	})

	t.Run("invalid XML", func(t *testing.T) {
		fetcher := &mockMetadataFetcher{data: []byte("not xml")}
		appWriter := &mockAppWriter{}
		svc := NewMetadataImportService(appWriter, fetcher)

		_, err := svc.Import(context.Background(), "tenant1", "https://sp.example.com/metadata", "src_cognito", "Test App")
		if err == nil {
			t.Fatal("expected error for invalid XML")
		}
	})

	t.Run("missing entity ID", func(t *testing.T) {
		noEntityID := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://sp.example.com/acs"
                              index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`)
		fetcher := &mockMetadataFetcher{data: noEntityID}
		appWriter := &mockAppWriter{}
		svc := NewMetadataImportService(appWriter, fetcher)

		_, err := svc.Import(context.Background(), "tenant1", "https://sp.example.com/metadata", "src_cognito", "Test App")
		if err == nil {
			t.Fatal("expected error for missing entity ID")
		}
	})
}

func TestHTTPMetadataFetcher_Fetch(t *testing.T) {
	// HTTPMetadataFetcher is tested via integration tests
	// Unit test would require starting a test HTTP server
	t.Skip("HTTPMetadataFetcher requires integration testing")
}
