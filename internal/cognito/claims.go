package cognito

import "strings"

// UserClaims represents extracted claims from a Cognito ID token.
type UserClaims struct {
	Sub   string
	Email string
	// EmailVerified mirrors the token's `email_verified` claim and is the
	// authority on whether Email may be used as an identifier. The SAML layer
	// issues an emailAddress NameID only when this is true; an unverified email
	// is user-chosen at sign-up and falls back to a persistent NameID = Sub
	// (finding M-6). A missing claim is treated as false.
	EmailVerified    bool
	GivenName        string
	FamilyName       string
	Groups           []string
	CustomAttributes map[string]string
}

// ExtractClaims extracts standard and custom claims from a Cognito JWT payload.
func ExtractClaims(payload map[string]interface{}) *UserClaims {
	claims := &UserClaims{
		Groups:           []string{},
		CustomAttributes: make(map[string]string),
	}

	// Extract standard claims
	if sub, ok := payload["sub"].(string); ok {
		claims.Sub = sub
	}

	if email, ok := payload["email"].(string); ok {
		claims.Email = email
	}

	if emailVerified, ok := payload["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}

	if givenName, ok := payload["given_name"].(string); ok {
		claims.GivenName = givenName
	}

	if familyName, ok := payload["family_name"].(string); ok {
		claims.FamilyName = familyName
	}

	// Extract cognito:groups
	if groups, ok := payload["cognito:groups"].([]interface{}); ok {
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				claims.Groups = append(claims.Groups, groupStr)
			}
		}
	}

	// Extract custom attributes (prefixed with "custom:")
	for key, value := range payload {
		if strings.HasPrefix(key, "custom:") {
			if valueStr, ok := value.(string); ok {
				// Strip the "custom:" prefix
				attributeName := strings.TrimPrefix(key, "custom:")
				claims.CustomAttributes[attributeName] = valueStr
			}
		}
	}

	return claims
}
