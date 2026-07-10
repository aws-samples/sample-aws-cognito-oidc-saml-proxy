package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpRequestForTenant builds an *http.Request whose context carries a chi
// route context with the given tenant path param. MakeAssertion resolves the
// app's claim/role mappings tenant-scoped from req.HTTPRequest, so assertion
// tests must attach a request carrying the tenant the app was created under.
func httpRequestForTenant(tenantSlug string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/t/"+tenantSlug+"/saml/sso", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenant", tenantSlug)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// newAssertionTestFixture creates stores with an app, claim mappings, and
// role mappings for assertion maker tests.
func newAssertionTestFixture(t *testing.T) (*store.AppStore, *store.ClaimStore, string) {
	t.Helper()
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")

	app := &tenant.Application{
		DisplayName: "Test SP",
		Protocol:    "saml",
		SourceID:    "source-1",
		Status:      "active",
	}
	samlCfg := &tenant.SAMLConfig{
		EntityID:           "https://sp.example.com/saml",
		AcsURL:             "https://sp.example.com/saml/acs",
		AcsURLs:            []string{"https://sp.example.com/saml/acs"},
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		NameIDSource:       "email",
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       300,
	}
	id, err := appStore.Create(context.Background(), "acme", app, samlCfg)
	require.NoError(t, err)
	return appStore, claimStore, id
}

func TestAssertionMaker_CognitoSourceAttribute(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)

	// Add email claim mapping.
	err := claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{
			Name:            "mail",
			SourceType:      "cognito",
			SourceAttribute: "email",
			TargetAttribute: "urn:oid:0.9.2342.19200300.100.1.3",
		},
	})
	require.NoError(t, err)

	maker := NewAssertionMaker(appStore, claimStore)

	session := &saml.Session{
		UserEmail:     "user@example.com",
		UserGivenName: "Jane",
		UserSurname:   "Doe",
		Groups:        []string{"Admins"},
	}

	req := &saml.IdpAuthnRequest{
		HTTPRequest: httpRequestForTenant("acme"),
		ServiceProviderMetadata: &saml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
		Assertion: &saml.Assertion{
			AttributeStatements: []saml.AttributeStatement{{}},
		},
		Now: time.Now(),
	}

	err = maker.MakeAssertion(req, session)
	require.NoError(t, err)

	// Find the email attribute in the assertion.
	found := findAttribute(req.Assertion, "urn:oid:0.9.2342.19200300.100.1.3")
	require.NotNil(t, found)
	require.Len(t, found.Values, 1)
	assert.Equal(t, "user@example.com", found.Values[0].Value)
}

func TestAssertionMaker_GroupToRoleMapping(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)

	// Add a groupMapping claim.
	err := claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{
			Name:            "role",
			SourceType:      "groupMapping",
			TargetAttribute: "https://app.example.com/role",
		},
	})
	require.NoError(t, err)

	// Map Cognito groups to SP roles.
	err = claimStore.PutRoleMappings(context.Background(), "acme", appID, []tenant.RoleMapping{
		{CognitoGroup: "Admins", MappedValue: "admin"},
		{CognitoGroup: "Viewers", MappedValue: "viewer"},
	})
	require.NoError(t, err)

	maker := NewAssertionMaker(appStore, claimStore)

	session := &saml.Session{
		UserEmail: "user@example.com",
		Groups:    []string{"Admins", "Viewers", "UnmappedGroup"},
	}

	req := &saml.IdpAuthnRequest{
		HTTPRequest: httpRequestForTenant("acme"),
		ServiceProviderMetadata: &saml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
		Assertion: &saml.Assertion{
			AttributeStatements: []saml.AttributeStatement{{}},
		},
		Now: time.Now(),
	}

	err = maker.MakeAssertion(req, session)
	require.NoError(t, err)

	found := findAttribute(req.Assertion, "https://app.example.com/role")
	require.NotNil(t, found)
	// Should have two mapped values (admin, viewer). UnmappedGroup is excluded.
	assert.Len(t, found.Values, 2)

	values := make(map[string]bool)
	for _, v := range found.Values {
		values[v.Value] = true
	}
	assert.True(t, values["admin"])
	assert.True(t, values["viewer"])
}

func TestAssertionMaker_StaticAttribute(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)

	err := claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{
			Name:            "tenant",
			SourceType:      "static",
			TargetAttribute: "https://app.example.com/tenant",
			DefaultValue:    "acme-corp",
		},
	})
	require.NoError(t, err)

	maker := NewAssertionMaker(appStore, claimStore)

	session := &saml.Session{
		UserEmail: "user@example.com",
	}

	req := &saml.IdpAuthnRequest{
		HTTPRequest: httpRequestForTenant("acme"),
		ServiceProviderMetadata: &saml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
		Assertion: &saml.Assertion{
			AttributeStatements: []saml.AttributeStatement{{}},
		},
		Now: time.Now(),
	}

	err = maker.MakeAssertion(req, session)
	require.NoError(t, err)

	found := findAttribute(req.Assertion, "https://app.example.com/tenant")
	require.NotNil(t, found)
	require.Len(t, found.Values, 1)
	assert.Equal(t, "acme-corp", found.Values[0].Value)
}

func TestAssertionMaker_CognitoCustomAttribute(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)

	err := claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{
			Name:            "department",
			SourceType:      "cognito",
			SourceAttribute: "department",
			TargetAttribute: "https://app.example.com/department",
		},
	})
	require.NoError(t, err)

	maker := NewAssertionMaker(appStore, claimStore)

	session := &saml.Session{
		UserEmail: "user@example.com",
		CustomAttributes: []saml.Attribute{
			{
				Name:   "department",
				Values: []saml.AttributeValue{{Value: "Engineering"}},
			},
		},
	}

	req := &saml.IdpAuthnRequest{
		HTTPRequest: httpRequestForTenant("acme"),
		ServiceProviderMetadata: &saml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
		Assertion: &saml.Assertion{
			AttributeStatements: []saml.AttributeStatement{{}},
		},
		Now: time.Now(),
	}

	err = maker.MakeAssertion(req, session)
	require.NoError(t, err)

	found := findAttribute(req.Assertion, "https://app.example.com/department")
	require.NotNil(t, found)
	require.Len(t, found.Values, 1)
	assert.Equal(t, "Engineering", found.Values[0].Value)
}

func TestAssertionMaker_UnknownEntityID_SkipsCustomAttributes(t *testing.T) {
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")

	maker := NewAssertionMaker(appStore, claimStore)

	session := &saml.Session{
		UserEmail: "user@example.com",
	}

	req := &saml.IdpAuthnRequest{
		ServiceProviderMetadata: &saml.EntityDescriptor{
			EntityID: "https://unknown.example.com/saml",
		},
		Assertion: &saml.Assertion{
			AttributeStatements: []saml.AttributeStatement{{}},
		},
		Now: time.Now(),
	}

	err := maker.MakeAssertion(req, session)
	require.NoError(t, err, "should succeed even with unknown entity ID")
	// No extra attributes added.
	assert.Empty(t, req.Assertion.AttributeStatements[0].Attributes)
}

func TestResolveSessionField_AllBranches(t *testing.T) {
	session := &saml.Session{
		UserEmail:      "user@example.com",
		UserGivenName:  "Jane",
		UserSurname:    "Doe",
		UserCommonName: "Jane Doe",
		SubjectID:      "subject-001",
		UserName:       "jdoe",
	}
	custom := map[string]string{
		"department": "Engineering",
	}

	tests := []struct {
		source   string
		expected string
	}{
		{"email", "user@example.com"},
		{"given_name", "Jane"},
		{"family_name", "Doe"},
		{"name", "Jane Doe"},
		{"common_name", "Jane Doe"},
		{"sub", "subject-001"},
		{"username", "jdoe"},
		{"department", "Engineering"},
		{"nonexistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			result := resolveSessionField(session, tt.source, custom)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// findAttribute searches the assertion's attribute statements for an attribute
// with the given name.
func findAttribute(assertion *saml.Assertion, name string) *saml.Attribute {
	for _, stmt := range assertion.AttributeStatements {
		for i := range stmt.Attributes {
			if stmt.Attributes[i].Name == name {
				return &stmt.Attributes[i]
			}
		}
	}
	return nil
}
