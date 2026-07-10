package service

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// TestUserClaims represents test user data for preview generation.
type TestUserClaims struct {
	Sub    string
	Email  string
	Groups []string
}

// PreviewResult contains the protocol and preview output.
type PreviewResult struct {
	Protocol string
	Preview  string
}

// PreviewService generates previews of claim mappings with test user data.
type PreviewService struct {
	apps   domain.AppReader
	claims domain.ClaimRepository
}

// NewPreviewService creates a new preview service.
func NewPreviewService(apps domain.AppReader, claims domain.ClaimRepository) *PreviewService {
	return &PreviewService{
		apps:   apps,
		claims: claims,
	}
}

// Preview generates a preview of claim mappings for the specified application using test user data.
func (s *PreviewService) Preview(ctx context.Context, tenantSlug, appID string, user TestUserClaims) (*PreviewResult, error) {
	// Load application
	app, err := s.apps.Get(ctx, tenantSlug, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get application: %w", err)
	}

	// Load claim mappings
	claimMappings, err := s.claims.GetClaimMappings(ctx, tenantSlug, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim mappings: %w", err)
	}

	// Load role mappings
	roleMappings, err := s.claims.GetRoleMappings(ctx, tenantSlug, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role mappings: %w", err)
	}

	// Build role lookup map: cognitoGroup -> mappedValue
	roleMap := make(map[string]string, len(roleMappings))
	for _, rm := range roleMappings {
		roleMap[rm.CognitoGroup] = rm.MappedValue
	}

	// Build test user data map for resolving cognito source attributes
	testUserData := map[string]string{
		"sub":   user.Sub,
		"email": user.Email,
	}

	var preview string
	if strings.EqualFold(app.Protocol, "saml") {
		preview = buildSAMLPreview(claimMappings, roleMap, testUserData, user.Groups)
	} else {
		preview = buildOIDCPreview(claimMappings, roleMap, testUserData, user.Groups)
	}

	return &PreviewResult{
		Protocol: app.Protocol,
		Preview:  preview,
	}, nil
}

// buildSAMLPreview creates a simplified SAML assertion XML preview.
func buildSAMLPreview(claimMappings []tenant.ClaimMapping, roleMap map[string]string, testUserData map[string]string, groups []string) string {
	var sb strings.Builder
	sb.WriteString(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`)
	sb.WriteString("\n  <saml:AttributeStatement>")

	for _, cm := range claimMappings {
		var values []string

		switch cm.SourceType {
		case "cognito":
			val := resolveTestUserField(cm.SourceAttribute, testUserData)
			if val == "" && cm.DefaultValue != "" {
				val = cm.DefaultValue
			}
			if val != "" {
				values = append(values, val)
			}

		case "groupMapping":
			for _, group := range groups {
				if mapped, ok := roleMap[group]; ok {
					values = append(values, mapped)
				}
			}

		case "static":
			if cm.DefaultValue != "" {
				values = append(values, cm.DefaultValue)
			}
		}

		if len(values) > 0 {
			// Escape the attribute name for XML attribute context (not Go %q,
			// which emits \" and would let a crafted TargetAttribute break out of
			// the attribute and inject arbitrary markup). xml.EscapeText
			// escapes the double-quote delimiter, so the value is safe inside "...".
			fmt.Fprintf(&sb, "\n    <saml:Attribute Name=\"%s\">", xmlEscapeText(cm.TargetAttribute))
			for _, v := range values {
				fmt.Fprintf(&sb, "\n      <saml:AttributeValue>%s</saml:AttributeValue>", xmlEscapeText(v))
			}
			sb.WriteString("\n    </saml:Attribute>")
		}
	}

	sb.WriteString("\n  </saml:AttributeStatement>")
	sb.WriteString("\n</saml:Assertion>")
	return sb.String()
}

// buildOIDCPreview creates a JSON preview of OIDC token claims.
func buildOIDCPreview(claimMappings []tenant.ClaimMapping, roleMap map[string]string, testUserData map[string]string, groups []string) string {
	claims := make(map[string]interface{})

	for _, cm := range claimMappings {
		var value interface{}

		switch cm.SourceType {
		case "cognito":
			val := resolveTestUserField(cm.SourceAttribute, testUserData)
			if val == "" && cm.DefaultValue != "" {
				val = cm.DefaultValue
			}
			if val != "" {
				value = val
			}

		case "groupMapping":
			var mappedValues []string
			for _, group := range groups {
				if mapped, ok := roleMap[group]; ok {
					mappedValues = append(mappedValues, mapped)
				}
			}
			if len(mappedValues) > 0 {
				value = mappedValues
			}

		case "static":
			if cm.DefaultValue != "" {
				value = cm.DefaultValue
			}
		}

		if value != nil {
			claims[cm.TargetAttribute] = value
		}
	}

	// Marshal to pretty JSON
	data, _ := json.MarshalIndent(claims, "", "  ")
	return string(data)
}

// resolveTestUserField resolves a Cognito source attribute from test user data.
func resolveTestUserField(source string, testUserData map[string]string) string {
	if val, ok := testUserData[source]; ok {
		return val
	}
	return ""
}

// xmlEscapeText escapes XML special characters.
func xmlEscapeText(s string) string {
	var buf strings.Builder
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return s // fallback to unescaped
	}
	return buf.String()
}
