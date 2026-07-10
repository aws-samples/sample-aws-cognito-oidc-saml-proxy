package tenant

import "testing"

func TestApplication_HasCustomLogin(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"set", "https://login.example.com/start", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Application{CustomLoginURL: tc.url}
			if got := a.HasCustomLogin(); got != tc.want {
				t.Fatalf("HasCustomLogin()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestApplication_IsTrustedLoginRedirect(t *testing.T) {
	allow := []string{"https://login.example.com/", "https://auth.corp.example/sso"}

	cases := []struct {
		name      string
		candidate string
		allowlist []string
		want      bool
	}{
		{"exact match", "https://login.example.com/", allow, true},
		{"prefix match", "https://login.example.com/start?x=1", allow, true},
		{"second entry prefix", "https://auth.corp.example/sso/begin", allow, true},
		{"http not allowed", "http://login.example.com/start", allow, false},
		{"different host", "https://evil.example.com/start", allow, false},
		{"host prefix confusion", "https://login.example.com.evil.com/", allow, false},
		{"empty candidate", "", allow, false},
		{"empty allowlist", "https://login.example.com/", nil, false},
		{"not a url", "://nope", allow, false},

		// Component matching must defeat these string-prefix bypasses.
		{"host suffix bypass no trailing slash", "https://login.example.com.evil.com/x", []string{"https://login.example.com"}, false},
		{"userinfo bypass", "https://login.example.com@evil.com/x", allow, false},
		{"userinfo bypass no path", "https://auth.corp.example@evil.com", allow, false},
		{"path segment confusion", "https://auth.corp.example/ssoevil", allow, false},
		{"exact host no path with bare-host allow", "https://login.example.com/anything", []string{"https://login.example.com"}, true},
		{"port mismatch", "https://login.example.com:8443/start", allow, false},
		{"case-insensitive host", "https://LOGIN.EXAMPLE.COM/start", allow, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Application{TrustedLoginRedirectURIs: tc.allowlist}
			if got := a.IsTrustedLoginRedirect(tc.candidate); got != tc.want {
				t.Fatalf("IsTrustedLoginRedirect(%q)=%v want %v", tc.candidate, got, tc.want)
			}
		})
	}
}
