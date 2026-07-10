package cognito

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractClaims_Standard(t *testing.T) {
	payload := map[string]interface{}{
		"sub":                "12345678-1234-1234-1234-123456789012",
		"email":              "user@example.com",
		"email_verified":     true,
		"given_name":         "John",
		"family_name":        "Doe",
		"cognito:groups":     []interface{}{"admin", "developers"},
		"custom:department":  "Engineering",
		"custom:employee_id": "EMP001",
	}

	claims := ExtractClaims(payload)

	assert.NotNil(t, claims)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", claims.Sub)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "John", claims.GivenName)
	assert.Equal(t, "Doe", claims.FamilyName)
	assert.Equal(t, []string{"admin", "developers"}, claims.Groups)
	assert.Equal(t, map[string]string{
		"department":  "Engineering",
		"employee_id": "EMP001",
	}, claims.CustomAttributes)
}

func TestExtractClaims_MissingOptional(t *testing.T) {
	payload := map[string]interface{}{
		"sub":   "12345678-1234-1234-1234-123456789012",
		"email": "user@example.com",
	}

	claims := ExtractClaims(payload)

	assert.NotNil(t, claims)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", claims.Sub)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.False(t, claims.EmailVerified)
	assert.Equal(t, "", claims.GivenName)
	assert.Equal(t, "", claims.FamilyName)
	assert.Empty(t, claims.Groups)
	assert.Empty(t, claims.CustomAttributes)
}

func TestExtractClaims_EmptyPayload(t *testing.T) {
	payload := map[string]interface{}{}

	claims := ExtractClaims(payload)

	assert.NotNil(t, claims)
	assert.Equal(t, "", claims.Sub)
	assert.Equal(t, "", claims.Email)
	assert.False(t, claims.EmailVerified)
	assert.Equal(t, "", claims.GivenName)
	assert.Equal(t, "", claims.FamilyName)
	assert.Empty(t, claims.Groups)
	assert.Empty(t, claims.CustomAttributes)
}

func TestExtractClaims_CustomAttributesOnly(t *testing.T) {
	payload := map[string]interface{}{
		"sub":           "12345678-1234-1234-1234-123456789012",
		"email":         "user@example.com",
		"custom:org_id": "ORG-123",
		"custom:role":   "manager",
		"custom:tier":   "premium",
	}

	claims := ExtractClaims(payload)

	assert.NotNil(t, claims)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", claims.Sub)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, map[string]string{
		"org_id": "ORG-123",
		"role":   "manager",
		"tier":   "premium",
	}, claims.CustomAttributes)
}

func TestExtractClaims_GroupsAsStringArray(t *testing.T) {
	payload := map[string]interface{}{
		"sub":            "12345678-1234-1234-1234-123456789012",
		"email":          "user@example.com",
		"cognito:groups": []interface{}{"group1", "group2", "group3"},
	}

	claims := ExtractClaims(payload)

	assert.NotNil(t, claims)
	assert.Equal(t, []string{"group1", "group2", "group3"}, claims.Groups)
}
