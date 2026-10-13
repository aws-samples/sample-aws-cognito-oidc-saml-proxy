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

// TestApplication_IsTrustedBrowserOrigin covers the M-4 origin allow-list used
// to gate browser form posts to the IdP-initiated SSO endpoint.
func TestApplication_IsTrustedBrowserOrigin(t *testing.T) {
	app := &Application{
		CustomLoginURL:           "https://login.example.com/start",
		TrustedLoginRedirectURIs: []string{"https://login.example.com/", "https://launcher.corp.example:8443/apps/"},
	}

	cases := []struct {
		name   string
		app    *Application
		origin string
		want   bool
	}{
		{"custom login origin", app, "https://login.example.com", true},
		{"custom login origin trailing slash", app, "https://login.example.com/", true},
		{"trusted redirect origin with port", app, "https://launcher.corp.example:8443", true},
		{"case-insensitive host", app, "https://LOGIN.EXAMPLE.COM", true},
		{"case-insensitive scheme", app, "HTTPS://login.example.com", true},
		{"surrounding whitespace", app, "  https://login.example.com  ", true},

		{"different host", app, "https://evil.example", false},
		{"host suffix confusion", app, "https://login.example.com.evil.example", false},
		{"port mismatch", app, "https://launcher.corp.example", false},
		{"port mismatch explicit", app, "https://login.example.com:8443", false},
		{"http scheme", app, "http://login.example.com", false},
		{"userinfo", app, "https://login.example.com@evil.example", false},
		{"origin with path", app, "https://login.example.com/start", false},
		{"origin with query", app, "https://login.example.com?x=1", false},
		{"null origin", app, "null", false},
		{"empty origin", app, "", false},
		{"not a url", app, "://nope", false},

		{"no login urls configured", &Application{}, "https://login.example.com", false},
		{"only custom login url", &Application{CustomLoginURL: "https://only.example/x"}, "https://only.example", true},
		{"http allow-list entry ignored", &Application{TrustedLoginRedirectURIs: []string{"http://plain.example/"}}, "http://plain.example", false},
		{"userinfo allow-list entry ignored", &Application{TrustedLoginRedirectURIs: []string{"https://[email protected]/"}}, "https://evil.example", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.app.IsTrustedBrowserOrigin(tc.origin); got != tc.want {
				t.Fatalf("IsTrustedBrowserOrigin(%q)=%v want %v", tc.origin, got, tc.want)
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
