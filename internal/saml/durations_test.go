package saml

import (
	"testing"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildSessionFromClaims_HonoursSessionDuration is the M-8 regression for
// SessionDurationSec: the session (and therefore the saml_session cookie and
// SessionNotOnOrAfter) lasts exactly as long as the SP configured, bounded to
// [300s, 24h], with 8h when unset or when no config is available.
func TestBuildSessionFromClaims_HonoursSessionDuration(t *testing.T) {
	cases := []struct {
		name string
		cfg  *tenant.SAMLConfig
		want time.Duration
	}{
		{"configured 3600 -> 1h", &tenant.SAMLConfig{SessionDurationSec: 3600}, time.Hour},
		{"0 -> default 8h", &tenant.SAMLConfig{SessionDurationSec: 0}, 8 * time.Hour},
		{"nil cfg -> default 8h", nil, 8 * time.Hour},
		{"10 -> clamped to 300s", &tenant.SAMLConfig{SessionDurationSec: 10}, 300 * time.Second},
		{"negative -> clamped to 300s", &tenant.SAMLConfig{SessionDurationSec: -5}, 300 * time.Second},
		{"999999 -> clamped to 24h", &tenant.SAMLConfig{SessionDurationSec: 999999}, 24 * time.Hour},
		{"86400 -> 24h", &tenant.SAMLConfig{SessionDurationSec: 86400}, 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := buildSessionFromClaims(verifiedClaims(), tc.cfg)
			require.NoError(t, err)
			assert.Equal(t, tc.want, s.ExpireTime.Sub(s.CreateTime))
		})
	}
}

func TestSessionDuration_Bounds(t *testing.T) {
	assert.Equal(t, 8*time.Hour, sessionDuration(nil))
	assert.Equal(t, 8*time.Hour, sessionDuration(&tenant.SAMLConfig{}))
	assert.Equal(t, 300*time.Second, sessionDuration(&tenant.SAMLConfig{SessionDurationSec: 1}))
	assert.Equal(t, 45*time.Minute, sessionDuration(&tenant.SAMLConfig{SessionDurationSec: 2700}))
	assert.Equal(t, 24*time.Hour, sessionDuration(&tenant.SAMLConfig{SessionDurationSec: 1 << 30}))
}

func TestClockSkew_Bounds(t *testing.T) {
	assert.Equal(t, 180*time.Second, clockSkew(nil))
	assert.Equal(t, 180*time.Second, clockSkew(&tenant.SAMLConfig{}), "0 means default")
	assert.Equal(t, 60*time.Second, clockSkew(&tenant.SAMLConfig{ClockSkewSec: 60}))
	assert.Equal(t, 0*time.Second, clockSkew(&tenant.SAMLConfig{ClockSkewSec: -30}), "negative clamps to 0")
	assert.Equal(t, 600*time.Second, clockSkew(&tenant.SAMLConfig{ClockSkewSec: 600}))
	assert.Equal(t, 600*time.Second, clockSkew(&tenant.SAMLConfig{ClockSkewSec: 99999}), "clamps to 600")
}
