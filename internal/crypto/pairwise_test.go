package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPairwiseID_DifferentSPsDifferentIDs(t *testing.T) {
	cognitoSub := "12345678-1234-1234-1234-123456789012"
	secret := "test-secret-key"
	scope := "example.com"

	sp1EntityID := "https://sp1.example.com/saml/metadata"
	sp2EntityID := "https://sp2.example.com/saml/metadata"

	id1 := PairwiseID(cognitoSub, sp1EntityID, secret, scope)
	id2 := PairwiseID(cognitoSub, sp2EntityID, secret, scope)

	// Different SPs should produce different IDs for the same user
	assert.NotEqual(t, id1, id2, "Different SPs should produce different pairwise IDs")
}

func TestPairwiseID_StableIDs(t *testing.T) {
	cognitoSub := "12345678-1234-1234-1234-123456789012"
	spEntityID := "https://sp.example.com/saml/metadata"
	secret := "test-secret-key"
	scope := "example.com"

	// Generate the same ID multiple times
	id1 := PairwiseID(cognitoSub, spEntityID, secret, scope)
	id2 := PairwiseID(cognitoSub, spEntityID, secret, scope)
	id3 := PairwiseID(cognitoSub, spEntityID, secret, scope)

	// Same inputs should produce stable IDs
	assert.Equal(t, id1, id2, "Same inputs should produce identical pairwise IDs")
	assert.Equal(t, id1, id3, "Same inputs should produce identical pairwise IDs")
}

func TestPairwiseID_ScopePrefix(t *testing.T) {
	cognitoSub := "12345678-1234-1234-1234-123456789012"
	spEntityID := "https://sp.example.com/saml/metadata"
	secret := "test-secret-key"
	scope := "example.com"

	id := PairwiseID(cognitoSub, spEntityID, secret, scope)

	// Should contain @scope suffix
	assert.True(t, strings.HasSuffix(id, "@"+scope),
		"Pairwise ID should end with @scope suffix")
}

func TestPairwiseID_Format(t *testing.T) {
	cognitoSub := "12345678-1234-1234-1234-123456789012"
	spEntityID := "https://sp.example.com/saml/metadata"
	secret := "test-secret-key"
	scope := "example.com"

	id := PairwiseID(cognitoSub, spEntityID, secret, scope)

	// Should have format: base32encodeddata@scope
	parts := strings.Split(id, "@")
	assert.Len(t, parts, 2, "Pairwise ID should have format data@scope")
	assert.Equal(t, scope, parts[1], "Scope part should match input scope")

	// Base32 part should be lowercase and non-empty
	base32Part := parts[0]
	assert.NotEmpty(t, base32Part, "Base32 part should not be empty")
	assert.Equal(t, strings.ToLower(base32Part), base32Part,
		"Base32 part should be lowercase")

	// Base32 should not contain padding
	assert.False(t, strings.Contains(base32Part, "="),
		"Base32 encoding should not contain padding")
}

func TestPairwiseID_DifferentUsersSameProvider(t *testing.T) {
	spEntityID := "https://sp.example.com/saml/metadata"
	secret := "test-secret-key"
	scope := "example.com"

	user1Sub := "11111111-1111-1111-1111-111111111111"
	user2Sub := "22222222-2222-2222-2222-222222222222"

	id1 := PairwiseID(user1Sub, spEntityID, secret, scope)
	id2 := PairwiseID(user2Sub, spEntityID, secret, scope)

	// Different users should produce different IDs for the same SP
	assert.NotEqual(t, id1, id2, "Different users should produce different pairwise IDs")
}

func TestPairwiseID_DifferentSecrets(t *testing.T) {
	cognitoSub := "12345678-1234-1234-1234-123456789012"
	spEntityID := "https://sp.example.com/saml/metadata"
	scope := "example.com"

	secret1 := "secret-key-1"
	secret2 := "secret-key-2"

	id1 := PairwiseID(cognitoSub, spEntityID, secret1, scope)
	id2 := PairwiseID(cognitoSub, spEntityID, secret2, scope)

	// Different secrets should produce different IDs
	assert.NotEqual(t, id1, id2, "Different secrets should produce different pairwise IDs")
}

func TestPairwiseID_DifferentScopes(t *testing.T) {
	cognitoSub := "12345678-1234-1234-1234-123456789012"
	spEntityID := "https://sp.example.com/saml/metadata"
	secret := "test-secret-key"

	scope1 := "example.com"
	scope2 := "another.example.com"

	id1 := PairwiseID(cognitoSub, spEntityID, secret, scope1)
	id2 := PairwiseID(cognitoSub, spEntityID, secret, scope2)

	// Different scopes should produce different IDs (different suffixes)
	assert.NotEqual(t, id1, id2, "Different scopes should produce different pairwise IDs")
	assert.True(t, strings.HasSuffix(id1, "@"+scope1))
	assert.True(t, strings.HasSuffix(id2, "@"+scope2))
}
