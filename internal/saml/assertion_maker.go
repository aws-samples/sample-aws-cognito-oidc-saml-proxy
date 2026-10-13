package saml

import (
	"log/slog"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// CustomAssertionMaker implements saml.AssertionMaker with per-application
// attribute mapping. It delegates to DefaultAssertionMaker for the Subject,
// Conditions and AuthnStatement, then REPLACES the AttributeStatement with
// exactly the attributes the app's claim and role mappings release. Nothing
// else about the user is disclosed to an SP (finding M-7): no crewjam default
// attributes (uid/eduPersonPrincipalName/mail/givenName/sn/eduPersonAffiliation/
// subject-id), no raw Cognito groups and no custom:* attributes unless an
// administrator mapped them for that application.
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
// (when the assertion is not yet populated), then discards whatever
// AttributeStatement that produced and attaches one built exclusively from the
// app's claim/role mappings — or none at all when nothing is mapped or the app
// cannot be resolved.
func (m *CustomAssertionMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	// Build the base assertion using the library default, unless the caller
	// has already provided one (e.g. in tests).
	if req.Assertion == nil {
		if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
			return err
		}
	}

	// Only mapped attributes are ever released. Drop the default maker's
	// statement (and any pre-populated one) before deciding what to add.
	req.Assertion.AttributeStatements = nil

	attrs := m.mappedAttributes(req, session)
	if len(attrs) > 0 {
		req.Assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: attrs}}
	}
	return nil
}

// mappedAttributes resolves the app's claim/role mappings for the request and
// evaluates them against the session. It returns nil — i.e. release nothing —
// when the tenant, app or mappings cannot be resolved; it never falls back to
// the crewjam defaults.
func (m *CustomAssertionMaker) mappedAttributes(req *saml.IdpAuthnRequest, session *saml.Session) []saml.Attribute {
	var entityID string
	if req.ServiceProviderMetadata != nil {
		entityID = req.ServiceProviderMetadata.EntityID
	}

	// Resolve the tenant from the request path (/t/{tenant}/...). The custom
	// attribute mappings are per-app within a tenant, and a SAML entityID is
	// unique only within a tenant, so the lookup must be tenant-scoped. Without
	// a tenant we cannot safely resolve the app, so release no attributes rather
	// than risk resolving another tenant's app.
	if req.HTTPRequest == nil {
		slog.Warn("assertion: no HTTP request in context; releasing no attributes", "entityID", entityID)
		return nil
	}
	tenantSlug := chi.URLParam(req.HTTPRequest, "tenant")
	if tenantSlug == "" {
		slog.Warn("assertion: no tenant on request path; releasing no attributes", "entityID", entityID)
		return nil
	}
	ctx := req.HTTPRequest.Context()

	// Look up the app within this tenant to get its ID for querying mappings.
	app, _, err := m.appStore.GetByTenantEntityID(ctx, tenantSlug, entityID)
	if err != nil {
		slog.Warn("assertion: cannot resolve application; releasing no attributes",
			"error", err, "entityID", entityID, "tenant", tenantSlug)
		return nil
	}

	claimMappings, err := m.claimStore.GetClaimMappings(ctx, tenantSlug, app.ID)
	if err != nil {
		slog.Warn("assertion: cannot load claim mappings; releasing no attributes",
			"error", err, "appID", app.ID, "tenant", tenantSlug)
		return nil
	}

	roleMappings, err := m.claimStore.GetRoleMappings(ctx, tenantSlug, app.ID)
	if err != nil {
		slog.Warn("assertion: cannot load role mappings; releasing no attributes",
			"error", err, "appID", app.ID, "tenant", tenantSlug)
		return nil
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

		switch {
		case tenant.IsCognitoSource(cm.SourceType):
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

		case cm.SourceType == "groupMapping":
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

		case cm.SourceType == "static":
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

	return attrs
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
