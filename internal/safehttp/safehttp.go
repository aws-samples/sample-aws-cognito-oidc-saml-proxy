// Package safehttp provides an HTTP client hardened against server-side
// request forgery (SSRF). Outbound requests are restricted to http/https and
// the destination IP is validated at connect time, so a hostname that resolves
// to a private, loopback, link-local (including the 169.254.169.254 instance
// metadata endpoint), or otherwise non-public address is refused. Validating
// the resolved IP in the dialer — rather than only parsing the URL — also
// defeats DNS-rebinding, where a name passes a pre-flight check and then
// resolves to an internal address at connect time.
//
// For integrity-critical fetches — SAML SP/IdP metadata carries signing
// certificates and endpoint URLs that are trusted downstream — use the
// trust-material variants (ValidateTrustURL, TrustClient). These require https
// so an on-path attacker cannot MITM a plaintext http:// URL and swap the
// signing material. Plain http remains permitted only on the default client
// (Client, ValidateURL), for fetches that carry no integrity-critical data.
package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// ErrBlockedDestination is returned when a request targets a scheme or address
// that is not permitted for outbound calls.
type ErrBlockedDestination struct {
	Reason string
}

func (e *ErrBlockedDestination) Error() string {
	return "blocked outbound request: " + e.Reason
}

// cgnatBlock is the RFC 6598 carrier-grade NAT range (100.64.0.0/10), which
// net.IP.IsPrivate does not cover but which is not a valid public target.
var cgnatBlock = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// isDisallowedIP reports whether an IP must not be dialed for outbound requests.
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && cgnatBlock.Contains(v4) {
		return true
	}
	return false
}

// ValidateURL checks that a raw URL is safe to submit as an outbound request
// based on the literal it contains: the scheme must be http or https and the
// host must be present. If the host is an IP literal it is validated here;
// hostnames are validated at dial time (see the dialer control below), which
// is the authoritative check. Callers should treat this as a fast pre-flight,
// not the sole defense.
func ValidateURL(rawURL string) error {
	return validateURL(rawURL, false)
}

// ValidateTrustURL is like ValidateURL but requires the https scheme. It is
// meant for fetches of integrity-critical data (e.g. SAML metadata) where a
// plaintext http:// URL would let an on-path attacker tamper with the payload.
func ValidateTrustURL(rawURL string) error {
	return validateURL(rawURL, true)
}

// validateURL performs the shared scheme/host/IP checks. When requireHTTPS is
// set, plain http is rejected so only TLS-protected fetches are permitted.
func validateURL(rawURL string, requireHTTPS bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return &ErrBlockedDestination{Reason: fmt.Sprintf("unparseable URL: %v", err)}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if requireHTTPS {
			return &ErrBlockedDestination{Reason: fmt.Sprintf("scheme %q not allowed for trust material; https is required", u.Scheme)}
		}
	default:
		return &ErrBlockedDestination{Reason: fmt.Sprintf("scheme %q not allowed", u.Scheme)}
	}
	host := u.Hostname()
	if host == "" {
		return &ErrBlockedDestination{Reason: "missing host"}
	}
	if ip := net.ParseIP(host); ip != nil && isDisallowedIP(ip) {
		return &ErrBlockedDestination{Reason: fmt.Sprintf("destination %s is not a public address", ip)}
	}
	return nil
}

// controlConn validates the resolved address the dialer is about to connect to.
// This runs after DNS resolution with the concrete IP, so it rejects both
// direct private-IP targets and hostnames that resolve to internal addresses.
func controlConn(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return &ErrBlockedDestination{Reason: fmt.Sprintf("cannot parse dial address %q: %v", address, err)}
	}
	ip := net.ParseIP(host)
	if isDisallowedIP(ip) {
		return &ErrBlockedDestination{Reason: fmt.Sprintf("destination %s is not a public address", host)}
	}
	return nil
}

// Client returns an *http.Client that refuses non-public destinations. The
// timeout bounds the whole request. Redirects are followed only to http/https
// URLs and each hop's destination IP is re-validated by the same dialer.
func Client(timeout time.Duration) *http.Client {
	return newClient(timeout, false)
}

// TrustClient is like Client but restricted to https, for fetching
// integrity-critical data such as SAML metadata. Every hop, including
// redirects, must be https; a redirect from https to plain http is refused so
// the fetch cannot be downgraded onto an attacker-controllable channel.
func TrustClient(timeout time.Duration) *http.Client {
	return newClient(timeout, true)
}

// newClient builds the SSRF-hardened client. When requireHTTPS is set, both the
// initial URL check and the per-hop redirect check reject plain http.
func newClient(timeout time.Duration, requireHTTPS bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   controlConn,
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return validateURL(req.URL.String(), requireHTTPS)
		},
	}
}
