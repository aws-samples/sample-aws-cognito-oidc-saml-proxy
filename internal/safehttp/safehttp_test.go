package safehttp

import (
	"errors"
	"testing"
)

func TestValidateURL_AllowsPublicHTTPS(t *testing.T) {
	for _, u := range []string{
		"https://cognito-idp.eu-north-1.amazonaws.com/pool/.well-known/openid-configuration",
		"http://example.com/metadata",
		"https://1.1.1.1/x",
	} {
		if err := ValidateURL(u); err != nil {
			t.Errorf("expected %q to be allowed, got %v", u, err)
		}
	}
}

func TestValidateURL_BlocksNonPublicAndBadScheme(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/x",            // loopback
		"http://localhost/x",            // loopback name -> parsed as IP literal? no, name; scheme ok, host present -> allowed here, dial-time blocks. skip below.
		"http://169.254.169.254/latest", // instance metadata (link-local)
		"http://10.0.0.5/x",             // private
		"http://192.168.1.1/x",          // private
		"http://172.16.0.1/x",           // private
		"http://100.64.0.1/x",           // CGNAT
		"http://[::1]/x",                // IPv6 loopback
		"file:///etc/passwd",            // bad scheme
		"gopher://evil/x",               // bad scheme
		"ftp://internal/x",              // bad scheme
		"https://",                      // missing host
	}
	for _, u := range cases {
		if u == "http://localhost/x" {
			// localhost is a name, not an IP literal; ValidateURL cannot
			// resolve it — the dialer control blocks it at connect time.
			continue
		}
		err := ValidateURL(u)
		if err == nil {
			t.Errorf("expected %q to be blocked, got nil", u)
			continue
		}
		var blocked *ErrBlockedDestination
		if !errors.As(err, &blocked) {
			t.Errorf("expected ErrBlockedDestination for %q, got %T: %v", u, err, err)
		}
	}
}

func TestValidateTrustURL_RejectsPlainHTTP(t *testing.T) {
	// Trust-material fetches (SAML metadata) must be https-only so an on-path
	// attacker cannot MITM a plaintext URL and swap the signing certificate.
	httpURLs := []string{
		"http://example.com/metadata",
		"http://metadata.idp.example.org/saml",
		"http://1.1.1.1/x",
	}
	for _, u := range httpURLs {
		err := ValidateTrustURL(u)
		if err == nil {
			t.Errorf("expected trust validation to reject %q, got nil", u)
			continue
		}
		var blocked *ErrBlockedDestination
		if !errors.As(err, &blocked) {
			t.Errorf("expected ErrBlockedDestination for %q, got %T: %v", u, err, err)
		}
	}
}

func TestValidateTrustURL_AllowsPublicHTTPS(t *testing.T) {
	httpsURLs := []string{
		"https://example.com/metadata",
		"https://metadata.idp.example.org/saml",
		"https://1.1.1.1/x",
	}
	for _, u := range httpsURLs {
		if err := ValidateTrustURL(u); err != nil {
			t.Errorf("expected trust validation to allow %q, got %v", u, err)
		}
	}
}

func TestValidateTrustURL_StillBlocksNonPublicAndBadScheme(t *testing.T) {
	// Tightening the scheme must not weaken the existing SSRF checks: a
	// non-public https host and non-http(s) schemes stay blocked.
	cases := []string{
		"https://127.0.0.1/x",     // loopback over https
		"https://169.254.169.254", // instance metadata over https
		"https://10.0.0.5/x",      // private over https
		"https://[::1]/x",         // IPv6 loopback over https
		"file:///etc/passwd",      // bad scheme
		"gopher://evil/x",         // bad scheme
		"https://",                // missing host
	}
	for _, u := range cases {
		err := ValidateTrustURL(u)
		if err == nil {
			t.Errorf("expected trust validation to block %q, got nil", u)
			continue
		}
		var blocked *ErrBlockedDestination
		if !errors.As(err, &blocked) {
			t.Errorf("expected ErrBlockedDestination for %q, got %T: %v", u, err, err)
		}
	}
}

func TestValidateURL_DefaultStillAllowsPlainHTTP(t *testing.T) {
	// The default (non-trust) path is unchanged: plain http to a public host
	// remains permitted.
	if err := ValidateURL("http://example.com/metadata"); err != nil {
		t.Errorf("expected default validation to allow plain http, got %v", err)
	}
}
