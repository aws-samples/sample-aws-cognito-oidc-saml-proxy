package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		HTTPRequest: httpRequestForTenant("acme"),
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
	// An unresolvable app releases nothing: no AttributeStatement at all (and
	// certainly not the pre-populated / default one).
	assert.Empty(t, req.Assertion.AttributeStatements)
}

// richSession is a session carrying every kind of user data the gateway knows
// about, so a test can prove that only the mapped parts are released.
func richSession() *saml.Session {
	return &saml.Session{
		ID:            "sess-1",
		NameID:        "user@example.com",
		NameIDFormat:  tenant.NameIDFormatEmail,
		SubjectID:     "sub-123",
		UserName:      "sub-123",
		UserEmail:     "user@example.com",
		UserGivenName: "Jane",
		UserSurname:   "Doe",
		Groups:        []string{"Admins", "Viewers"},
		CustomAttributes: []saml.Attribute{
			{Name: "department", Values: []saml.AttributeValue{{Value: "Engineering"}}},
			{Name: "cost_center", Values: []saml.AttributeValue{{Value: "CC-42"}}},
		},
	}
}

// defaultMakerRequest builds an IdpAuthnRequest with NO pre-populated
// assertion, so MakeAssertion runs crewjam's DefaultAssertionMaker first —
// which is exactly what emits the default attribute set in production.
func defaultMakerRequest(t *testing.T) *saml.IdpAuthnRequest {
	t.Helper()
	signer, cert := generateTestCert(t)
	return &saml.IdpAuthnRequest{
		IDP: &saml.IdentityProvider{
			Key:         signer,
			Certificate: cert,
			MetadataURL: mustURL(t, "https://idp.example.com/t/acme/saml/metadata"),
			SSOURL:      mustURL(t, "https://idp.example.com/t/acme/saml/sso"),
		},
		HTTPRequest: httpRequestForTenant("acme"),
		ServiceProviderMetadata: &saml.EntityDescriptor{
			EntityID: "https://sp.example.com/saml",
		},
		SPSSODescriptor: &saml.SPSSODescriptor{},
		ACSEndpoint: &saml.IndexedEndpoint{
			Binding:  saml.HTTPPostBinding,
			Location: "https://sp.example.com/saml/acs",
		},
		Request: saml.AuthnRequest{ID: "_req-1", IssueInstant: time.Now()},
		Now:     time.Now(),
	}
}

// crewjam DefaultAssertionMaker attribute names that must never reach an SP
// unless an administrator mapped them.
var crewjamDefaultAttributeNames = []string{
	"urn:oid:0.9.2342.19200300.100.1.1", // uid
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.6",  // eduPersonPrincipalName
	"urn:oid:0.9.2342.19200300.100.1.3", // mail
	"urn:oid:2.5.4.42",                  // givenName
	"urn:oid:2.5.4.4",                   // sn
	"urn:oid:2.5.4.3",                   // cn
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.1",  // eduPersonAffiliation
	"urn:oasis:names:tc:SAML:attribute:subject-id",
}

// TestAssertionMaker_ReleasesOnlyMappedAttributes is the M-7 regression: with
// a rich session and a single mapping (email -> a custom target name), the
// assertion carries exactly that one attribute. None of crewjam's defaults, the
// raw groups or the unmapped custom:* attributes leak.
func TestAssertionMaker_ReleasesOnlyMappedAttributes(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)
	require.NoError(t, claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{Name: "email", SourceType: "cognito", SourceAttribute: "email", TargetAttribute: "https://app.example.com/email"},
	}))
	// Role mappings exist, but no groupMapping claim releases them.
	require.NoError(t, claimStore.PutRoleMappings(context.Background(), "acme", appID, []tenant.RoleMapping{
		{CognitoGroup: "Admins", MappedValue: "admin"},
	}))

	req := defaultMakerRequest(t)
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, richSession()))

	require.Len(t, req.Assertion.AttributeStatements, 1)
	attrs := req.Assertion.AttributeStatements[0].Attributes
	require.Len(t, attrs, 1, "exactly the one mapped attribute is released")
	assert.Equal(t, "https://app.example.com/email", attrs[0].Name)
	require.Len(t, attrs[0].Values, 1)
	assert.Equal(t, "user@example.com", attrs[0].Values[0].Value)

	for _, name := range crewjamDefaultAttributeNames {
		assert.Nil(t, findAttribute(req.Assertion, name), "crewjam default %s must not be released", name)
	}
	for _, name := range []string{"department", "cost_center", "custom:department", "groups", "cognito:groups", "admin"} {
		assert.Nil(t, findAttribute(req.Assertion, name), "unmapped %s must not be released", name)
	}
	// Nothing anywhere in the statement mentions the unmapped values.
	for _, a := range attrs {
		for _, v := range a.Values {
			assert.NotEqual(t, "Engineering", v.Value)
			assert.NotEqual(t, "CC-42", v.Value)
			assert.NotEqual(t, "Admins", v.Value)
			assert.NotEqual(t, "Jane", v.Value)
			assert.NotEqual(t, "Doe", v.Value)
		}
	}
	// Subject and AuthnStatement from the default maker are kept.
	require.NotNil(t, req.Assertion.Subject)
	require.NotNil(t, req.Assertion.Subject.NameID)
	assert.Equal(t, "user@example.com", req.Assertion.Subject.NameID.Value)
	assert.NotEmpty(t, req.Assertion.AuthnStatements)
}

// TestAssertionMaker_NoMappings_NoAttributeStatement: an app with no mappings
// gets a Subject-only assertion — no AttributeStatement element at all, even
// though the default maker produced one.
func TestAssertionMaker_NoMappings_NoAttributeStatement(t *testing.T) {
	appStore, claimStore, _ := newAssertionTestFixture(t)

	req := defaultMakerRequest(t)
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, richSession()))

	assert.Empty(t, req.Assertion.AttributeStatements)
	require.NotNil(t, req.Assertion.Subject)
	assert.Equal(t, "user@example.com", req.Assertion.Subject.NameID.Value)
}

// TestAssertionMaker_PrepopulatedStatementIsReplaced: a caller-supplied
// assertion that already carries attributes does not get them appended to —
// the statement is rebuilt from the mappings alone.
func TestAssertionMaker_PrepopulatedStatementIsReplaced(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)
	require.NoError(t, claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{Name: "sub", SourceType: "cognito", SourceAttribute: "sub", TargetAttribute: "https://app.example.com/id"},
	}))

	req := &saml.IdpAuthnRequest{
		HTTPRequest:             httpRequestForTenant("acme"),
		ServiceProviderMetadata: &saml.EntityDescriptor{EntityID: "https://sp.example.com/saml"},
		Assertion: &saml.Assertion{
			AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
				{Name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.1", Values: []saml.AttributeValue{{Value: "member"}}},
			}}},
		},
		Now: time.Now(),
	}
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, richSession()))

	require.Len(t, req.Assertion.AttributeStatements, 1)
	require.Len(t, req.Assertion.AttributeStatements[0].Attributes, 1)
	assert.Equal(t, "https://app.example.com/id", req.Assertion.AttributeStatements[0].Attributes[0].Name)
	assert.Nil(t, findAttribute(req.Assertion, "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"))
}

// TestAssertionMaker_AttributeSourceTypeAlias: the registration wizard stores
// SourceType "attribute"; it must resolve exactly like "cognito".
func TestAssertionMaker_AttributeSourceTypeAlias(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)
	require.NoError(t, claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{Name: "mail", SourceType: "attribute", SourceAttribute: "email", TargetAttribute: "urn:oid:0.9.2342.19200300.100.1.3"},
		{Name: "dept", SourceType: "attribute", SourceAttribute: "department", TargetAttribute: "https://app.example.com/department"},
	}))

	req := defaultMakerRequest(t)
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, richSession()))

	mail := findAttribute(req.Assertion, "urn:oid:0.9.2342.19200300.100.1.3")
	require.NotNil(t, mail, "wizard 'attribute' mapping must resolve")
	require.Len(t, mail.Values, 1)
	assert.Equal(t, "user@example.com", mail.Values[0].Value)

	dept := findAttribute(req.Assertion, "https://app.example.com/department")
	require.NotNil(t, dept)
	assert.Equal(t, "Engineering", dept.Values[0].Value)

	// Still only the two mapped attributes.
	require.Len(t, req.Assertion.AttributeStatements, 1)
	assert.Len(t, req.Assertion.AttributeStatements[0].Attributes, 2)
	assert.Nil(t, findAttribute(req.Assertion, "cost_center"))
}

// TestAssertionMaker_NoTenantOnRequest_NoAttributeStatement: without a tenant
// the app cannot be resolved safely, so nothing is released (and the default
// maker's statement is not kept either).
func TestAssertionMaker_NoTenantOnRequest_NoAttributeStatement(t *testing.T) {
	appStore, claimStore, appID := newAssertionTestFixture(t)
	require.NoError(t, claimStore.PutClaimMappings(context.Background(), "acme", appID, []tenant.ClaimMapping{
		{Name: "email", SourceType: "cognito", SourceAttribute: "email", TargetAttribute: "https://app.example.com/email"},
	}))

	req := defaultMakerRequest(t)
	req.HTTPRequest = httptest.NewRequest(http.MethodPost, "/saml/sso", nil) // no chi tenant param
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, richSession()))
	assert.Empty(t, req.Assertion.AttributeStatements)
}

// newTimingTestFixture seeds an app whose SAML config carries the given
// ClockSkewSec (SessionDurationSec is irrelevant here: the session's
// ExpireTime is what MakeAssertion copies into SessionNotOnOrAfter).
func newTimingTestFixture(t *testing.T, clockSkewSec int) (*store.AppStore, *store.ClaimStore) {
	t.Helper()
	ms := store.NewMemoryStore()
	appStore := store.NewAppStore(ms, "test-table")
	claimStore := store.NewClaimStore(ms, "test-table")
	_, err := appStore.Create(context.Background(), "acme", &tenant.Application{
		DisplayName: "Timing SP", Protocol: "saml", SourceID: "source-1", Status: "active",
	}, &tenant.SAMLConfig{
		EntityID:           "https://sp.example.com/saml",
		AcsURL:             "https://sp.example.com/saml/acs",
		AcsURLs:            []string{"https://sp.example.com/saml/acs"},
		SignResponse:       true,
		SignAssertion:      true,
		SessionDurationSec: 3600,
		ClockSkewSec:       clockSkewSec,
	})
	require.NoError(t, err)
	return appStore, claimStore
}

// TestAssertionMaker_SessionNotOnOrAfter_EqualsSessionExpiry is the M-8
// regression for SessionDurationSec on the wire: the AuthnStatement advertises
// the session's expiry so the SP's session cannot outlive the gateway's.
func TestAssertionMaker_SessionNotOnOrAfter_EqualsSessionExpiry(t *testing.T) {
	appStore, claimStore := newTimingTestFixture(t, 180)
	session := richSession()
	session.CreateTime = time.Now().Truncate(time.Second)
	session.ExpireTime = session.CreateTime.Add(45 * time.Minute)

	req := defaultMakerRequest(t)
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, session))

	require.Len(t, req.Assertion.AuthnStatements, 1)
	got := req.Assertion.AuthnStatements[0].SessionNotOnOrAfter
	require.NotNil(t, got, "AuthnStatement must carry SessionNotOnOrAfter")
	assert.True(t, got.Equal(session.ExpireTime), "SessionNotOnOrAfter=%v want %v", got, session.ExpireTime)

	// The attribute is actually serialised (crewjam omits it when nil).
	el := req.Assertion.Element()
	authn := el.FindElement("./saml:AuthnStatement")
	require.NotNil(t, authn)
	assert.NotEmpty(t, authn.SelectAttrValue("SessionNotOnOrAfter", ""))
}

// TestAssertionMaker_NotBefore_HonoursClockSkew is the M-8 regression for
// ClockSkewSec: Conditions.NotBefore is Now minus the SP's configured skew
// instead of crewjam's fixed 180s.
func TestAssertionMaker_NotBefore_HonoursClockSkew(t *testing.T) {
	cases := []struct {
		name    string
		skewSec int
		want    time.Duration
	}{
		{"60s configured", 60, 60 * time.Second},
		{"0 -> default 180s", 0, 180 * time.Second},
		{"clamped to 600s", 5000, 600 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			appStore, claimStore := newTimingTestFixture(t, tc.skewSec)
			req := defaultMakerRequest(t)
			// The SP's request predates Now by more than any skew so the
			// IssueInstant floor never kicks in.
			req.Request.IssueInstant = req.Now.Add(-time.Hour)
			require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, richSession()))

			require.NotNil(t, req.Assertion.Conditions)
			assert.True(t, req.Assertion.Conditions.NotBefore.Equal(req.Now.Add(-tc.want)),
				"NotBefore=%v want Now-%v (%v)", req.Assertion.Conditions.NotBefore, tc.want, req.Now.Add(-tc.want))
		})
	}
}

// TestAssertionMaker_NotBefore_NeverPredatesRequest keeps crewjam's rule: the
// skew allowance cannot move NotBefore before the SP's own IssueInstant.
func TestAssertionMaker_NotBefore_NeverPredatesRequest(t *testing.T) {
	appStore, claimStore := newTimingTestFixture(t, 600)
	req := defaultMakerRequest(t)
	req.Request.IssueInstant = req.Now.Add(-10 * time.Second)
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, richSession()))
	assert.True(t, req.Assertion.Conditions.NotBefore.Equal(req.Request.IssueInstant))
}

// TestAssertionMaker_UnknownApp_DefaultTiming: when the SP cannot be resolved
// the maker still emits a sane window (default skew) and the session expiry.
func TestAssertionMaker_UnknownApp_DefaultTiming(t *testing.T) {
	appStore, claimStore := newTimingTestFixture(t, 60)
	session := richSession()
	session.ExpireTime = time.Now().Add(time.Hour)
	req := defaultMakerRequest(t)
	req.ServiceProviderMetadata.EntityID = "https://unknown.example.com/saml"
	req.Request.IssueInstant = req.Now.Add(-time.Hour)
	require.NoError(t, NewAssertionMaker(appStore, claimStore).MakeAssertion(req, session))
	assert.True(t, req.Assertion.Conditions.NotBefore.Equal(req.Now.Add(-180*time.Second)))
	require.NotNil(t, req.Assertion.AuthnStatements[0].SessionNotOnOrAfter)
	assert.True(t, req.Assertion.AuthnStatements[0].SessionNotOnOrAfter.Equal(session.ExpireTime))
}

func mustURL(t *testing.T, raw string) url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return *u
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
