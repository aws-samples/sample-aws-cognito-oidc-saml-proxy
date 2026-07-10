package service

import (
	"context"
	"strings"
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// mockAppReader provides test applications.
type mockAppReader struct {
	app *tenant.Application
	err error
}

func (m *mockAppReader) Get(_ context.Context, _, _ string) (*tenant.Application, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.app, nil
}

func (m *mockAppReader) GetByTenantEntityID(_ context.Context, _, _ string) (*tenant.Application, *tenant.SAMLConfig, error) {
	return nil, nil, nil
}

func (m *mockAppReader) GetSAMLConfig(_ context.Context, _, _ string) (*tenant.SAMLConfig, error) {
	return nil, nil
}

func (m *mockAppReader) GetOIDCConfig(_ context.Context, _, _ string) (*tenant.OIDCConfig, error) {
	return nil, nil
}

func (m *mockAppReader) List(_ context.Context, _ string) ([]*tenant.Application, error) {
	return nil, nil
}

// mockClaimRepository provides test claim and role mappings.
type mockClaimRepository struct {
	claimMappings []tenant.ClaimMapping
	roleMappings  []tenant.RoleMapping
}

func (m *mockClaimRepository) GetClaimMappings(_ context.Context, _, _ string) ([]tenant.ClaimMapping, error) {
	return m.claimMappings, nil
}

func (m *mockClaimRepository) PutClaimMappings(_ context.Context, _, _ string, _ []tenant.ClaimMapping) error {
	return nil
}

func (m *mockClaimRepository) GetRoleMappings(_ context.Context, _, _ string) ([]tenant.RoleMapping, error) {
	return m.roleMappings, nil
}

func (m *mockClaimRepository) PutRoleMappings(_ context.Context, _, _ string, _ []tenant.RoleMapping) error {
	return nil
}

func TestPreviewService_Preview_SAML(t *testing.T) {
	appReader := &mockAppReader{
		app: &tenant.Application{
			ID:          "app_123",
			DisplayName: "Test SAML App",
			Protocol:    "saml",
		},
	}

	claimRepo := &mockClaimRepository{
		claimMappings: []tenant.ClaimMapping{
			{TargetAttribute: "email", SourceType: "cognito", SourceAttribute: "email"},
			{TargetAttribute: "firstName", SourceType: "static", DefaultValue: "John"},
			{TargetAttribute: "role", SourceType: "groupMapping"},
		},
		roleMappings: []tenant.RoleMapping{
			{CognitoGroup: "admins", MappedValue: "admin"},
			{CognitoGroup: "users", MappedValue: "user"},
		},
	}

	svc := NewPreviewService(appReader, claimRepo)

	testUser := TestUserClaims{
		Sub:    "user_123",
		Email:  "test@example.com",
		Groups: []string{"admins", "users"},
	}

	result, err := svc.Preview(context.Background(), "tenant1", "app_123", testUser)
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}

	if result.Protocol != "saml" {
		t.Errorf("expected protocol=saml, got %s", result.Protocol)
	}

	// Verify preview contains expected SAML structure
	if !strings.Contains(result.Preview, `<saml:Assertion`) {
		t.Error("preview should contain SAML Assertion element")
	}

	if !strings.Contains(result.Preview, `<saml:AttributeStatement>`) {
		t.Error("preview should contain AttributeStatement")
	}

	// Verify cognito source mapping
	if !strings.Contains(result.Preview, `<saml:Attribute Name="email">`) {
		t.Error("preview should contain email attribute")
	}
	if !strings.Contains(result.Preview, `<saml:AttributeValue>test@example.com</saml:AttributeValue>`) {
		t.Error("preview should contain email value")
	}

	// Verify static mapping
	if !strings.Contains(result.Preview, `<saml:Attribute Name="firstName">`) {
		t.Error("preview should contain firstName attribute")
	}
	if !strings.Contains(result.Preview, `<saml:AttributeValue>John</saml:AttributeValue>`) {
		t.Error("preview should contain firstName value")
	}

	// Verify group mapping
	if !strings.Contains(result.Preview, `<saml:Attribute Name="role">`) {
		t.Error("preview should contain role attribute")
	}
	if !strings.Contains(result.Preview, `<saml:AttributeValue>admin</saml:AttributeValue>`) {
		t.Error("preview should contain admin role")
	}
	if !strings.Contains(result.Preview, `<saml:AttributeValue>user</saml:AttributeValue>`) {
		t.Error("preview should contain user role")
	}
}

func TestPreviewService_Preview_OIDC(t *testing.T) {
	appReader := &mockAppReader{
		app: &tenant.Application{
			ID:          "app_456",
			DisplayName: "Test OIDC App",
			Protocol:    "oidc",
		},
	}

	claimRepo := &mockClaimRepository{
		claimMappings: []tenant.ClaimMapping{
			{TargetAttribute: "email", SourceType: "cognito", SourceAttribute: "email"},
			{TargetAttribute: "company", SourceType: "static", DefaultValue: "Acme Corp"},
			{TargetAttribute: "roles", SourceType: "groupMapping"},
		},
		roleMappings: []tenant.RoleMapping{
			{CognitoGroup: "developers", MappedValue: "developer"},
		},
	}

	svc := NewPreviewService(appReader, claimRepo)

	testUser := TestUserClaims{
		Sub:    "user_456",
		Email:  "dev@example.com",
		Groups: []string{"developers"},
	}

	result, err := svc.Preview(context.Background(), "tenant1", "app_456", testUser)
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}

	if result.Protocol != "oidc" {
		t.Errorf("expected protocol=oidc, got %s", result.Protocol)
	}

	// Verify JSON structure
	if !strings.Contains(result.Preview, `"email"`) {
		t.Error("preview should contain email claim")
	}
	if !strings.Contains(result.Preview, `"dev@example.com"`) {
		t.Error("preview should contain email value")
	}

	// Verify static mapping
	if !strings.Contains(result.Preview, `"company"`) {
		t.Error("preview should contain company claim")
	}
	if !strings.Contains(result.Preview, `"Acme Corp"`) {
		t.Error("preview should contain company value")
	}

	// Verify group mapping as array
	if !strings.Contains(result.Preview, `"roles"`) {
		t.Error("preview should contain roles claim")
	}
	if !strings.Contains(result.Preview, `"developer"`) {
		t.Error("preview should contain developer role")
	}
}

func TestPreviewService_Preview_DefaultValues(t *testing.T) {
	appReader := &mockAppReader{
		app: &tenant.Application{
			ID:       "app_789",
			Protocol: "saml",
		},
	}

	claimRepo := &mockClaimRepository{
		claimMappings: []tenant.ClaimMapping{
			// Missing cognito attribute should fall back to default
			{TargetAttribute: "department", SourceType: "cognito", SourceAttribute: "department", DefaultValue: "Engineering"},
		},
		roleMappings: []tenant.RoleMapping{},
	}

	svc := NewPreviewService(appReader, claimRepo)

	testUser := TestUserClaims{
		Sub:    "user_789",
		Email:  "test@example.com",
		Groups: []string{},
	}

	result, err := svc.Preview(context.Background(), "tenant1", "app_789", testUser)
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}

	// Verify default value is used
	if !strings.Contains(result.Preview, `"department"`) && !strings.Contains(result.Preview, `Name="department"`) {
		t.Error("preview should contain department attribute")
	}
	if !strings.Contains(result.Preview, "Engineering") {
		t.Error("preview should use default value Engineering")
	}
}

func TestPreviewService_Preview_XMLEscaping(t *testing.T) {
	appReader := &mockAppReader{
		app: &tenant.Application{
			ID:       "app_escape",
			Protocol: "saml",
		},
	}

	claimRepo := &mockClaimRepository{
		claimMappings: []tenant.ClaimMapping{
			{TargetAttribute: "note", SourceType: "static", DefaultValue: `<script>alert("xss")</script>`},
		},
		roleMappings: []tenant.RoleMapping{},
	}

	svc := NewPreviewService(appReader, claimRepo)

	testUser := TestUserClaims{
		Sub:    "user_escape",
		Email:  "test@example.com",
		Groups: []string{},
	}

	result, err := svc.Preview(context.Background(), "tenant1", "app_escape", testUser)
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}

	// Verify XML escaping
	if strings.Contains(result.Preview, `<script>`) {
		t.Error("preview should escape XML special characters")
	}
	if !strings.Contains(result.Preview, `&lt;script&gt;`) {
		t.Error("preview should contain escaped XML")
	}
}
