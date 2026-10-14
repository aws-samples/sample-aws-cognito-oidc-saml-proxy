package saml

import (
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// Defaults for the per-application SAML timing fields. The bounds live in the
// tenant package (tenant.SessionDuration*Sec, tenant.ClockSkew*Sec) so the
// management API refuses out-of-range values with 422 (finding M-8); the
// protocol path clamps anyway so a record written by an older API or imported
// directly can never yield a zero-length or multi-day session.
const (
	// defaultSessionDuration applies when SessionDurationSec is 0 or the SAML
	// config is unavailable (legacy single-tenant path).
	defaultSessionDuration = 8 * time.Hour
	// defaultClockSkew matches crewjam's MaxClockSkew, which the default
	// assertion maker uses when the SP has no explicit setting.
	defaultClockSkew = 180 * time.Second
)

// sessionDuration returns the SAML session lifetime for an SP: its configured
// SessionDurationSec clamped to [tenant.SessionDurationMinSec,
// tenant.SessionDurationMaxSec], or defaultSessionDuration when cfg is nil or
// the field is 0.
func sessionDuration(cfg *tenant.SAMLConfig) time.Duration {
	if cfg == nil || cfg.SessionDurationSec == 0 {
		return defaultSessionDuration
	}
	return clampSeconds(cfg.SessionDurationSec, tenant.SessionDurationMinSec, tenant.SessionDurationMaxSec)
}

// clockSkew returns the Conditions.NotBefore allowance for an SP: its
// configured ClockSkewSec clamped to [tenant.ClockSkewMinSec,
// tenant.ClockSkewMaxSec], or defaultClockSkew when cfg is nil or the field is
// 0 (the API stores 0 as "use the default", mirroring SessionDurationSec).
func clockSkew(cfg *tenant.SAMLConfig) time.Duration {
	if cfg == nil || cfg.ClockSkewSec == 0 {
		return defaultClockSkew
	}
	return clampSeconds(cfg.ClockSkewSec, tenant.ClockSkewMinSec, tenant.ClockSkewMaxSec)
}

// clampSeconds converts a seconds value to a Duration bounded by [lo, hi].
func clampSeconds(sec, lo, hi int) time.Duration {
	if sec < lo {
		sec = lo
	}
	if sec > hi {
		sec = hi
	}
	return time.Duration(sec) * time.Second
}
