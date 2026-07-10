package api

import (
	"testing"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

func TestValidateLoginConfig(t *testing.T) {
	cases := []struct {
		name      string
		app       *tenant.Application
		wantValid bool
	}{
		{
			name:      "no custom login is valid",
			app:       &tenant.Application{},
			wantValid: true,
		},
		{
			name: "custom login covered by allowlist",
			app: &tenant.Application{
				CustomLoginURL:           "https://login.example.com/start",
				TrustedLoginRedirectURIs: []string{"https://login.example.com/"},
			},
			wantValid: true,
		},
		{
			name: "custom login without allowlist is invalid",
			app: &tenant.Application{
				CustomLoginURL: "https://login.example.com/start",
			},
			wantValid: false,
		},
		{
			name: "custom login not covered by allowlist is invalid",
			app: &tenant.Application{
				CustomLoginURL:           "https://login.example.com/start",
				TrustedLoginRedirectURIs: []string{"https://other.example.com/"},
			},
			wantValid: false,
		},
		{
			name: "non-https custom login is invalid",
			app: &tenant.Application{
				CustomLoginURL:           "http://login.example.com/start",
				TrustedLoginRedirectURIs: []string{"http://login.example.com/"},
			},
			wantValid: false,
		},
		{
			name: "non-https allowlist entry is invalid",
			app: &tenant.Application{
				TrustedLoginRedirectURIs: []string{"http://login.example.com/"},
			},
			wantValid: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateLoginConfig(tc.app)
			gotValid := len(errs) == 0
			if gotValid != tc.wantValid {
				t.Fatalf("validateLoginConfig valid=%v want %v (errs=%v)", gotValid, tc.wantValid, errs)
			}
		})
	}
}
