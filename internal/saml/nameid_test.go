package saml

import (
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/cognito"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func verifiedClaims() *cognito.UserClaims {
	return &cognito.UserClaims{Sub: "sub-1", Email: "user@example.com", EmailVerified: true}
}

func unverifiedClaims() *cognito.UserClaims {
	return &cognito.UserClaims{Sub: "sub-1", Email: "user@example.com", EmailVerified: false}
}

func TestResolveNameID(t *testing.T) {
	const sessionID = "session-abc"
	tests := []struct {
		name       string
		claims     *cognito.UserClaims
		cfg        *tenant.SAMLConfig
		wantValue  string
		wantFormat string
		wantReason string
	}{
		{
			name:       "verified email + email format -> email",
			claims:     verifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatEmail, NameIDSource: "email"},
			wantValue:  "user@example.com",
			wantFormat: tenant.NameIDFormatEmail,
		},
		{
			name:       "verified email + short code format",
			claims:     verifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: "email", NameIDSource: "email"},
			wantValue:  "user@example.com",
			wantFormat: tenant.NameIDFormatEmail,
		},
		{
			// M-6 regression: an unverified email must never become the subject.
			name:       "UNVERIFIED email + email format -> persistent sub",
			claims:     unverifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatEmail, NameIDSource: "email"},
			wantValue:  "sub-1",
			wantFormat: tenant.NameIDFormatPersistent,
			wantReason: nameIDReasonEmailUnverified,
		},
		{
			name:       "email format but token has no email -> persistent sub",
			claims:     &cognito.UserClaims{Sub: "sub-1", EmailVerified: true},
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatEmail, NameIDSource: "email"},
			wantValue:  "sub-1",
			wantFormat: tenant.NameIDFormatPersistent,
			wantReason: nameIDReasonEmailUnverified,
		},
		{
			name:       "email format with sub source still needs verified email",
			claims:     unverifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatEmail, NameIDSource: "sub"},
			wantValue:  "sub-1",
			wantFormat: tenant.NameIDFormatPersistent,
			wantReason: nameIDReasonEmailUnverified,
		},
		{
			name:       "persistent -> sub regardless of verified email",
			claims:     verifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatPersistent, NameIDSource: "sub"},
			wantValue:  "sub-1",
			wantFormat: tenant.NameIDFormatPersistent,
		},
		{
			name:       "transient -> session ID",
			claims:     verifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatTransient},
			wantValue:  sessionID,
			wantFormat: tenant.NameIDFormatTransient,
		},
		{
			name:       "source email + unspecified format + unverified -> sub",
			claims:     unverifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatUnspecified, NameIDSource: "email"},
			wantValue:  "sub-1",
			wantFormat: tenant.NameIDFormatPersistent,
			wantReason: nameIDReasonEmailUnverified,
		},
		{
			name:       "source email + unspecified format + verified -> email",
			claims:     verifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: "", NameIDSource: "Email"},
			wantValue:  "user@example.com",
			wantFormat: tenant.NameIDFormatEmail,
		},
		{
			name:       "unspecified format + sub source -> sub, format unchanged",
			claims:     verifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: "unspecified", NameIDSource: "sub"},
			wantValue:  "sub-1",
			wantFormat: tenant.NameIDFormatUnspecified,
		},
		{
			name:       "custom format passthrough -> sub",
			claims:     verifiedClaims(),
			cfg:        &tenant.SAMLConfig{NameIDFormat: "urn:example:custom", NameIDSource: ""},
			wantValue:  "sub-1",
			wantFormat: "urn:example:custom",
		},
		{
			name:       "nil cfg -> unspecified sub",
			claims:     verifiedClaims(),
			cfg:        nil,
			wantValue:  "sub-1",
			wantFormat: tenant.NameIDFormatUnspecified,
		},
		{
			name:       "missing sub -> no_subject",
			claims:     &cognito.UserClaims{Email: "user@example.com", EmailVerified: true},
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatEmail, NameIDSource: "email"},
			wantValue:  "",
			wantFormat: "",
			wantReason: nameIDReasonNoSubject,
		},
		{
			name:       "nil claims -> no_subject",
			claims:     nil,
			cfg:        &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatPersistent},
			wantReason: nameIDReasonNoSubject,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, format, reason := resolveNameID(tt.claims, tt.cfg, sessionID)
			assert.Equal(t, tt.wantValue, value, "value")
			assert.Equal(t, tt.wantFormat, format, "format")
			assert.Equal(t, tt.wantReason, reason, "reason")
		})
	}
}

func TestBuildSessionFromClaims_EmailNameIDRequiresVerifiedEmail(t *testing.T) {
	cfg := &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatEmail, NameIDSource: "email"}

	verified, err := buildSessionFromClaims(verifiedClaims(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", verified.NameID)
	assert.Equal(t, tenant.NameIDFormatEmail, verified.NameIDFormat)

	// M-6 regression.
	unverified, err := buildSessionFromClaims(unverifiedClaims(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "sub-1", unverified.NameID)
	assert.Equal(t, tenant.NameIDFormatPersistent, unverified.NameIDFormat)
	// The rest of the session is unchanged: the email is still available to
	// attribute mappings, just not as the subject.
	assert.Equal(t, "user@example.com", unverified.UserEmail)
	assert.Equal(t, "sub-1", unverified.SubjectID)
}

func TestBuildSessionFromClaims_Transient_DiffersPerSession(t *testing.T) {
	cfg := &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatTransient}

	s1, err := buildSessionFromClaims(verifiedClaims(), cfg)
	require.NoError(t, err)
	s2, err := buildSessionFromClaims(verifiedClaims(), cfg)
	require.NoError(t, err)

	assert.Equal(t, tenant.NameIDFormatTransient, s1.NameIDFormat)
	assert.Equal(t, s1.ID, s1.NameID, "transient NameID is the session ID")
	assert.Equal(t, s2.ID, s2.NameID)
	assert.NotEqual(t, s1.NameID, s2.NameID, "transient NameIDs must differ between sessions")
}

func TestBuildSessionFromClaims_Persistent_IsSub(t *testing.T) {
	cfg := &tenant.SAMLConfig{NameIDFormat: "persistent", NameIDSource: "sub"}
	s, err := buildSessionFromClaims(verifiedClaims(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "sub-1", s.NameID)
	assert.Equal(t, tenant.NameIDFormatPersistent, s.NameIDFormat)
}

func TestBuildSessionFromClaims_MissingSub_Error(t *testing.T) {
	cfg := &tenant.SAMLConfig{NameIDFormat: tenant.NameIDFormatEmail, NameIDSource: "email"}
	s, err := buildSessionFromClaims(&cognito.UserClaims{Email: "user@example.com", EmailVerified: true}, cfg)
	require.ErrorIs(t, err, errNoSubject)
	assert.Nil(t, s)
}
