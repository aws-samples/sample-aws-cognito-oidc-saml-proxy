package saml

import (
	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

// CustomAssertionMaker implements saml.AssertionMaker with per-application
// attribute mapping. It delegates to DefaultAssertionMaker for the base
// assertion, then appends custom attributes based on the app's configured
// claim and role mappings from the multi-tenant ClaimStore.
type CustomAssertionMaker struct {
	appStore   *store.AppStore
	claimStore *store.ClaimStore
}

// NewAssertionMaker creates a new CustomAssertionMaker.
func NewAssertionMaker(appStore *store.AppStore, claimStore *store.ClaimStore) *CustomAssertionMaker {
	return &CustomAssertionMaker{
		appStore:   appStore,
		claimStore: claimStore,
	}
}

// MakeAssertion builds the SAML assertion. It first calls the default maker
// (when the assertion is not yet populated), then enriches it with per-app
// attribute mappings from the claim store.
func (m *CustomAssertionMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	// Build the base assertion using the library default, unless the caller
	// has already provided one (e.g. in tests).
	if req.Assertion == nil {
		if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
			return err
		}
	}

	entityID := req.ServiceProviderMetadata.EntityID

	// Resolve the tenant from the request path (/t/{tenant}/...). The custom
	// attribute mappings are per-app within a tenant, and a SAML entityID is
	// unique only within a tenant, so the lookup must be tenant-scoped. Without
	// a tenant we cannot safely resolve the app, so skip enrichment and return
	// the already-valid base assertion rather than risk resolving another
	// tenant's app.
	if req.HTTPRequest == nil {
		return nil
	}
	tenantSlug := chi.URLParam(req.HTTPRequest, "tenant")
	if tenantSlug == "" {
		return nil
	}
	ctx := req.HTTPRequest.Context()

	// Look up the app within this tenant to get its ID for querying mappings.
	app, _, err := m.appStore.GetByTenantEntityID(ctx, tenantSlug, entityID)
	if err != nil {
		// If we can't find the app, skip custom attributes -- the base assertion
		// is already valid.
		return nil
	}

	claimMappings, err := m.claimStore.GetClaimMappings(ctx, tenantSlug, app.ID)
	if err != nil {
		return nil // non-fatal: proceed with base assertion
	}

	roleMappings, err := m.claimStore.GetRoleMappings(ctx, tenantSlug, app.ID)
	if err != nil {
		return nil // non-fatal
	}

	// Build a role lookup map: cognitoGroup -> mappedValue.
	roleMap := make(map[string]string, len(roleMappings))
	for _, rm := range roleMappings {
		roleMap[rm.CognitoGroup] = rm.MappedValue
	}

	// Build a lookup for session custom attributes.
	sessionCustom := make(map[string]string)
	for _, attr := range session.CustomAttributes {
		if len(attr.Values) > 0 {
			sessionCustom[attr.Name] = attr.Values[0].Value
		}
	}

	var attrs []saml.Attribute
	for _, cm := range claimMappings {
		attr := saml.Attribute{
			Name:       cm.TargetAttribute,
			NameFormat: nameFormatOrDefault(""),
		}

		switch cm.SourceType {
		case "cognito":
			val := resolveSessionField(session, cm.SourceAttribute, sessionCustom)
			if val == "" && cm.DefaultValue != "" {
				val = cm.DefaultValue
			}
			if val != "" {
				attr.Values = []saml.AttributeValue{{
					Type:  "xs:string",
					Value: val,
				}}
			}

		case "groupMapping":
			var values []saml.AttributeValue
			for _, group := range session.Groups {
				if mapped, ok := roleMap[group]; ok {
					values = append(values, saml.AttributeValue{
						Type:  "xs:string",
						Value: mapped,
					})
				}
			}
			if len(values) > 0 {
				attr.Values = values
			}

		case "static":
			if cm.DefaultValue != "" {
				attr.Values = []saml.AttributeValue{{
					Type:  "xs:string",
					Value: cm.DefaultValue,
				}}
			}
		}

		if len(attr.Values) > 0 {
			attrs = append(attrs, attr)
		}
	}

	if len(attrs) > 0 {
		if len(req.Assertion.AttributeStatements) == 0 {
			req.Assertion.AttributeStatements = []saml.AttributeStatement{{}}
		}
		req.Assertion.AttributeStatements[0].Attributes = append(
			req.Assertion.AttributeStatements[0].Attributes,
			attrs...,
		)
	}

	return nil
}

// resolveSessionField maps a Cognito source attribute name to the corresponding
// session field value.
func resolveSessionField(session *saml.Session, source string, custom map[string]string) string {
	switch source {
	case "email":
		return session.UserEmail
	case "given_name":
		return session.UserGivenName
	case "family_name":
		return session.UserSurname
	case "name", "common_name":
		return session.UserCommonName
	case "sub":
		return session.SubjectID
	case "username":
		return session.UserName
	default:
		// Try custom attributes.
		if v, ok := custom[source]; ok {
			return v
		}
		return ""
	}
}

// nameFormatOrDefault returns a sensible NameFormat, defaulting to URI format.
func nameFormatOrDefault(nf string) string {
	if nf != "" {
		return nf
	}
	return "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
}
