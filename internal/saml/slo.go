package saml

import (
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"   //nolint:gosec // registers SHA-1 for crypto.Hash.New; used only when a tenant explicitly opts into legacy SHA-1 SP interop (default off).
	_ "crypto/sha256" // registers SHA-256/384 for crypto.Hash.New (crewjam IdP default is RSA-SHA256).
	_ "crypto/sha512" // registers SHA-512 for crypto.Hash.New.
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

// maxSAMLDecodedBytes bounds how many bytes a single inbound SAML message may
// inflate to. SAML redirect-binding LogoutRequests are a few KB; 512 KB
// is generous headroom. DEFLATE achieves extreme ratios, so an uncapped
// io.ReadAll on a small malicious payload can inflate to gigabytes and OOM the
// Lambda. Anything that hits this ceiling is rejected rather than buffered.
const maxSAMLDecodedBytes = 512 * 1024

// errSAMLTooLarge is returned when an inbound SAML message inflates past
// maxSAMLDecodedBytes.
var errSAMLTooLarge = fmt.Errorf("decompressed SAML message exceeds %d bytes", maxSAMLDecodedBytes)

// sloClockSkew is the tolerance applied to LogoutRequest freshness checks to
// absorb clock drift between the SP and this IdP. A LogoutRequest whose
// IssueInstant is more than this far in the future, or whose IssueInstant is
// older than sloMaxRequestAge (or whose NotOnOrAfter has passed), is stale.
const sloClockSkew = 3 * time.Minute

// sloMaxRequestAge bounds how long after its IssueInstant a LogoutRequest that
// carries no NotOnOrAfter remains acceptable. It matches the AuthnRequest replay
// window (session_provider.go), so a captured signed SLO URL cannot be replayed
// indefinitely.
const sloMaxRequestAge = 5 * time.Minute

// sloReplayTTL is how long a consumed LogoutRequest ID is remembered for
// replay rejection. It covers the full acceptance window (IssueInstant +
// sloMaxRequestAge + skew) so a request cannot be replayed while it is still
// otherwise fresh.
const sloReplayTTL = sloMaxRequestAge + sloClockSkew

// SAML redirect-binding signature algorithm URIs (SAML 2.0 bindings §3.4.4.1).
// The gateway's own IdP signs with RSA-SHA256. The SHA-256/384/512 variants are
// always accepted; the two SHA-1 variants are cryptographically broken for
// signatures and are rejected unless the SP's tenant explicitly opts into legacy
// SHA-1 interop (SAMLConfig.AllowInsecureSHA1, default off) — see hashForSigAlg.
const (
	sigAlgRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	sigAlgRSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	sigAlgRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	sigAlgECDSASHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	sigAlgECDSA256  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	sigAlgECDSA384  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	sigAlgECDSA512  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// HandleSLO returns an HTTP handler for SAML Single Logout (front-channel
// HTTP-Redirect binding). It decodes the SAMLRequest, validates the issuer
// against the AppStore, verifies the redirect-binding signature against the
// SP's registered signing certificate, terminates the gateway session
// by clearing the session cookie, and returns a LogoutResponse via
// HTTP-Redirect to the SP's SLO URL. The response status is Success only when
// every session participant is terminated; any other SP that shared the session
// but cannot be reached over this single front-channel exchange yields
// PartialLogout instead.
//
// baseURL is the gateway's server-side origin (e.g. https://idp.example.com);
// it is used to build the LogoutResponse issuer, so response URLs are never
// derived from the untrusted r.Host / X-Forwarded-Proto. It is also the trusted
// origin the inbound LogoutRequest's Destination is validated against.
//
// replay is the one-time-use guard for LogoutRequest IDs, mirroring the
// AuthnRequest replay protection in session_provider.go. It may be nil (the
// replay check is then skipped) for handler-only test wiring, but production
// callers MUST supply it.
func HandleSLO(baseURL string, sessions domain.SessionRepository, apps domain.AppReader, audit domain.AuditRepository, replay domain.ReplayRepository) http.HandlerFunc {
	// sloEndpointPath is the request path this IdP serves SLO on, used to
	// validate the LogoutRequest Destination. It is derived from the trusted
	// baseURL so it never reflects the untrusted request host.
	trustedBase := strings.TrimRight(baseURL, "/")

	return func(w http.ResponseWriter, r *http.Request) {
		tenantSlug := chi.URLParam(r, "tenant")
		if tenantSlug == "" {
			http.Error(w, "missing tenant", http.StatusBadRequest)
			return
		}

		encoded := r.URL.Query().Get("SAMLRequest")
		if encoded == "" {
			slog.Warn("SLO request missing SAMLRequest parameter",
				"tenant", tenantSlug,
				"method", r.Method,
			)
			http.Error(w, "missing SAMLRequest parameter", http.StatusBadRequest)
			return
		}
		relayState := r.URL.Query().Get("RelayState")

		// Decode: base64 -> deflate (bounded) -> XML. On failure return a
		// generic message to this unauthenticated caller; the underlying error
		// (which can echo attacker-controlled input) is logged server-side only.
		logoutReq, err := decodeSAMLRequest(encoded)
		if err != nil {
			slog.Warn("SLO failed to decode SAMLRequest",
				"tenant", tenantSlug,
				"error", err,
			)
			http.Error(w, "invalid SAMLRequest", http.StatusBadRequest)
			return
		}

		slog.Info("SLO request received",
			"tenant", tenantSlug,
			"issuer", issuerValue(logoutReq.Issuer),
			"nameId", nameIDValue(logoutReq.NameID),
			"requestId", logoutReq.ID,
			"sessionIndex", sessionIndexValue(logoutReq.SessionIndex),
		)

		// Validate: issuer must match a registered SP
		issuer := issuerValue(logoutReq.Issuer)
		if issuer == "" {
			http.Error(w, "LogoutRequest missing Issuer", http.StatusBadRequest)
			return
		}

		_, samlCfg, err := apps.GetByTenantEntityID(r.Context(), tenantSlug, issuer)
		if err != nil {
			slog.Warn("SLO issuer not found",
				"tenant", tenantSlug,
				"issuer", issuer,
				"error", err,
			)
			http.Error(w, "unknown SP issuer", http.StatusBadRequest)
			return
		}

		// Reject a stale or misdirected LogoutRequest before authenticating it.
		// A detached redirect-binding signature covers a fixed query string, so a
		// signed SLO URL captured from logs/history/Referer is otherwise replayable
		// forever; a freshness window plus a Destination check plus the one-time-use
		// guard below bound that. These are cheap and leak nothing, so they run
		// before signature verification.
		if err := checkLogoutRequestFreshness(logoutReq, time.Now()); err != nil {
			slog.Warn("SLO rejected stale LogoutRequest",
				"tenant", tenantSlug,
				"issuer", issuer,
				"requestId", logoutReq.ID,
				"error", err,
			)
			auditSLORejected(r, audit, tenantSlug, logoutReq.ID, issuer, "stale_request")
			http.Error(w, "LogoutRequest is stale or expired", http.StatusForbidden)
			return
		}
		// If a Destination is present it must address this IdP's SLO endpoint for
		// this tenant. SAML permits an absent Destination on the redirect binding,
		// so an empty value is not rejected — but a mismatched one is.
		if logoutReq.Destination != "" && !destinationMatches(logoutReq.Destination, trustedBase, tenantSlug) {
			slog.Warn("SLO rejected LogoutRequest with mismatched Destination",
				"tenant", tenantSlug,
				"issuer", issuer,
				"destination", logoutReq.Destination,
			)
			auditSLORejected(r, audit, tenantSlug, logoutReq.ID, issuer, "destination_mismatch")
			http.Error(w, "LogoutRequest Destination does not address this endpoint", http.StatusForbidden)
			return
		}

		// Authenticate the LogoutRequest before acting on it. SLO is a
		// security-relevant SAML message — an unsigned or forged LogoutRequest
		// can force-terminate another user's session — so it must carry a valid
		// redirect-binding signature over its registered signing certificate.
		// Fail closed: if the SP has no registered cert we cannot authenticate
		// the request, so we reject rather than honor an unverifiable logout.
		// SHA-1 SigAlgs are accepted only when this SP's tenant explicitly opts in.
		if err := verifyRedirectSignature(r.URL.RawQuery, samlCfg.SigningCertPem, samlCfg.AllowInsecureSHA1); err != nil {
			slog.Warn("SLO signature verification failed",
				"tenant", tenantSlug,
				"issuer", issuer,
				"error", err,
			)
			auditSLORejected(r, audit, tenantSlug, logoutReq.ID, issuer, "signature_verification_failed")
			http.Error(w, "LogoutRequest signature verification failed", http.StatusForbidden)
			return
		}
		if samlCfg.AllowInsecureSHA1 {
			// Surface every use of the legacy opt-in so operators can track and
			// retire it. (verifyRedirectSignature already enforced the algorithm.)
			slog.Warn("SLO accepted a request under the legacy SHA-1 opt-in",
				"tenant", tenantSlug,
				"issuer", issuer,
			)
		}

		// One-time-use guard: atomically claim this LogoutRequest ID, mirroring the
		// AuthnRequest replay protection in session_provider.go. MarkSeen is a single
		// conditional write, so it both detects replays and records the ID with no
		// check-then-act gap. Fail CLOSED: a replayed ID or an unavailable replay
		// store both reject rather than honor a possibly-replayed logout. Runs after
		// signature verification so an unauthenticated caller cannot burn IDs.
		if replay != nil && logoutReq.ID != "" {
			if err := replay.MarkSeen(r.Context(), logoutReq.ID, sloReplayTTL); err != nil {
				if errors.Is(err, store.ErrConditionFailed) {
					slog.Warn("SLO rejected replayed LogoutRequest",
						"tenant", tenantSlug,
						"issuer", issuer,
						"requestId", logoutReq.ID,
					)
					auditSLORejected(r, audit, tenantSlug, logoutReq.ID, issuer, "replayed_request")
					http.Error(w, "replayed LogoutRequest", http.StatusForbidden)
					return
				}
				slog.Error("SLO replay store unavailable; rejecting request",
					"tenant", tenantSlug,
					"requestId", logoutReq.ID,
					"error", err,
				)
				http.Error(w, "replay protection unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		// Actually terminate the session before emitting the response.
		// The gateway session is held in the signed saml_session cookie, so
		// clearing that cookie (MaxAge<0) is what ends this browser's session;
		// a Success response must not leave the cookie intact.
		clearSessionCookie(w)

		// Clearing the cookie only affects the browser that presented it. A
		// copy of the session cookie replayed at the (separate) SSO Lambda would
		// otherwise stay valid for the remainder of its 8h lifetime. Record a
		// durable server-side revocation marker keyed by SessionIndex so
		// GetSession rejects any copy of this session after logout. The logout
		// response is not failed if the marker write errors — the cookie is still
		// cleared for this browser — but the failure is logged so it is visible.
		sessionIndex := sessionIndexValue(logoutReq.SessionIndex)
		if sessionIndex != "" {
			if rerr := sessions.RevokeSession(r.Context(), sessionIndex); rerr != nil {
				slog.Error("SLO failed to record session revocation marker",
					"tenant", tenantSlug,
					"sessionIndex", sessionIndex,
					"error", rerr,
				)
			}
		}

		// Decide the logout status. This front-channel HTTP-Redirect exchange can
		// only terminate the session at the gateway and at the requesting SP.
		// If the session was shared with other SPs that we cannot reach over this
		// single response, logout is only partial: report PartialLogout so
		// the requester knows the session may still be live elsewhere.
		logoutStatus := saml.StatusSuccess
		if sessionIndex != "" {
			participants, err := sessions.GetParticipants(r.Context(), sessionIndex)
			if err != nil {
				// We cannot confirm every participant was terminated, so we must
				// not claim full success. Fail toward PartialLogout.
				slog.Warn("SLO failed to look up session participants",
					"sessionIndex", sessionIndex,
					"error", err,
				)
				logoutStatus = saml.StatusPartialLogout
			} else if otherParticipants(participants, issuer) > 0 {
				slog.Info("SLO cannot terminate all session participants over front-channel; reporting partial logout",
					"sessionIndex", sessionIndex,
					"participants", len(participants),
				)
				logoutStatus = saml.StatusPartialLogout
			}
		}

		// Determine the SP's SLO return URL
		sloDestination := samlCfg.SloURL
		if sloDestination == "" {
			// Fall back to ACS URL if no dedicated SLO URL is configured
			sloDestination = samlCfg.AcsURL
		}

		// Build LogoutResponse. The issuer URL is built from the server-side
		// baseURL, never from r.Host / X-Forwarded-Proto.
		resp := buildLogoutResponse(logoutReq, baseURL, tenantSlug, sloDestination, logoutStatus)

		// Redirect to SP with the LogoutResponse. The destination is the SP's
		// configured SloURL/AcsURL, resolved only after the LogoutRequest issuer
		// is validated against a registered SP — it is not user-controlled.
		redirectURL := resp.Redirect(relayState)

		slog.Info("SLO sending LogoutResponse",
			"tenant", tenantSlug,
			"destination", sloDestination,
			"responseId", resp.ID,
			"inResponseTo", resp.InResponseTo,
			"status", logoutStatus,
		)

		// Log SLO processed
		if audit != nil {
			auditStatus := "success"
			if logoutStatus == saml.StatusPartialLogout {
				auditStatus = "partial_logout"
			}
			if err := audit.LogStep(r.Context(), tenantSlug, resp.ID, "slo_processed", issuer, "", map[string]string{"status": auditStatus}); err != nil {
				slog.Error("audit store log failed", "error", err)
			}
		}

		// nosemgrep: open-redirect
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	}
}

// decodeSAMLRequest decodes a base64-encoded, deflate-compressed SAML LogoutRequest
// from the HTTP-Redirect binding. Inflation is bounded to maxSAMLDecodedBytes to
// prevent DEFLATE zip-bomb DoS.
func decodeSAMLRequest(encoded string) (*saml.LogoutRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	reader := flate.NewReader(strings.NewReader(string(raw)))
	defer func() { _ = reader.Close() }()

	// Read one byte past the cap so a message that exactly fills the buffer but
	// has more bytes waiting is still detected as over-limit.
	limited := io.LimitReader(reader, maxSAMLDecodedBytes+1)
	xmlBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("deflate decompress: %w", err)
	}
	if len(xmlBytes) > maxSAMLDecodedBytes {
		return nil, errSAMLTooLarge
	}

	var req saml.LogoutRequest
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		return nil, fmt.Errorf("XML unmarshal: %w", err)
	}

	return &req, nil
}

// checkLogoutRequestFreshness bounds how old a LogoutRequest may be so a signed
// SLO URL cannot be replayed indefinitely. It rejects a request whose
// IssueInstant lies further in the future than sloClockSkew (clock-drift
// tolerance), whose IssueInstant is older than sloMaxRequestAge, or whose
// explicit NotOnOrAfter has already passed (skew-adjusted). A missing
// IssueInstant is itself a rejection: without it the age cannot be bounded.
func checkLogoutRequestFreshness(req *saml.LogoutRequest, now time.Time) error {
	if req.IssueInstant.IsZero() {
		return errors.New("LogoutRequest missing IssueInstant")
	}
	if req.IssueInstant.After(now.Add(sloClockSkew)) {
		return fmt.Errorf("LogoutRequest IssueInstant %s is in the future", req.IssueInstant.UTC())
	}
	if now.Sub(req.IssueInstant) > sloMaxRequestAge+sloClockSkew {
		return fmt.Errorf("LogoutRequest IssueInstant %s is older than %s", req.IssueInstant.UTC(), sloMaxRequestAge)
	}
	if req.NotOnOrAfter != nil && !now.Before(req.NotOnOrAfter.Add(sloClockSkew)) {
		return fmt.Errorf("LogoutRequest NotOnOrAfter %s has passed", req.NotOnOrAfter.UTC())
	}
	return nil
}

// destinationMatches reports whether an inbound LogoutRequest Destination
// addresses this IdP's SLO endpoint for the given tenant. The expected endpoint
// is built from the trusted server-side baseURL (never r.Host), so a request
// signed for a different IdP/tenant cannot be replayed here.
func destinationMatches(destination, trustedBase, tenantSlug string) bool {
	expected := fmt.Sprintf("%s/t/%s/saml/slo", trustedBase, tenantSlug)
	return destination == expected
}

// auditSLORejected records a rejected SLO attempt to the audit log with a fixed
// reason code. The audit write failing is logged but never blocks the rejection.
func auditSLORejected(r *http.Request, audit domain.AuditRepository, tenantSlug, requestID, issuer, reason string) {
	if audit == nil {
		return
	}
	if aErr := audit.LogStep(r.Context(), tenantSlug, requestID, "slo_rejected", issuer, "", map[string]string{"status": "error", "reason": reason}); aErr != nil {
		slog.Error("audit store log failed", "error", aErr)
	}
}

// verifyRedirectSignature validates the HTTP-Redirect binding signature of an
// inbound SAML message against the SP's registered signing certificate.
//
// Per SAML 2.0 bindings §3.4.4.1 the signature covers the octet string
// "SAMLRequest=<v>&RelayState=<v>&SigAlg=<v>" using the raw, still-percent-encoded
// query values in that exact order (RelayState omitted when absent). We therefore
// reconstruct the signed input from r.URL.RawQuery rather than from parsed values,
// so the bytes match what the SP signed. It fails closed: a missing certificate,
// a missing SigAlg/Signature, an unsupported algorithm, or an invalid signature
// all return an error. allowSHA1 gates the legacy SHA-1 SigAlgs (default off,
// per-tenant opt-in) — see hashForSigAlg.
func verifyRedirectSignature(rawQuery, certPEM string, allowSHA1 bool) error {
	if strings.TrimSpace(certPEM) == "" {
		return errors.New("SP has no registered signing certificate; SLO requires a signed LogoutRequest")
	}

	sigAlgRaw, ok := rawQueryParam(rawQuery, "SigAlg")
	if !ok {
		return errors.New("missing SigAlg (unsigned request rejected)")
	}
	signatureRaw, ok := rawQueryParam(rawQuery, "Signature")
	if !ok {
		return errors.New("missing Signature (unsigned request rejected)")
	}
	samlReqRaw, ok := rawQueryParam(rawQuery, "SAMLRequest")
	if !ok {
		return errors.New("missing SAMLRequest")
	}

	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return fmt.Errorf("decode SigAlg: %w", err)
	}
	sigB64, err := url.QueryUnescape(signatureRaw)
	if err != nil {
		return fmt.Errorf("decode Signature: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("base64-decode Signature: %w", err)
	}

	// Reconstruct the signed octet string from raw (encoded) query values.
	signed := "SAMLRequest=" + samlReqRaw
	if relayRaw, ok := rawQueryParam(rawQuery, "RelayState"); ok {
		signed += "&RelayState=" + relayRaw
	}
	signed += "&SigAlg=" + sigAlgRaw

	hashFn, isECDSA, err := hashForSigAlg(sigAlg, allowSHA1)
	if err != nil {
		return err
	}
	h := hashFn.New()
	h.Write([]byte(signed))
	digest := h.Sum(nil)

	cert, err := parseSigningCert(certPEM)
	if err != nil {
		return fmt.Errorf("parse SP signing certificate: %w", err)
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if isECDSA {
			return errors.New("SigAlg is ECDSA but SP certificate is RSA")
		}
		if err := rsa.VerifyPKCS1v15(pub, hashFn, digest, sig); err != nil {
			return fmt.Errorf("RSA signature invalid: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if !isECDSA {
			return errors.New("SigAlg is RSA but SP certificate is ECDSA")
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return errors.New("ECDSA signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported SP public key type %T", cert.PublicKey)
	}
}

// hashForSigAlg maps a SAML SigAlg URI to its hash function and reports whether
// it is an ECDSA algorithm. Unknown algorithms are rejected. The two SHA-1
// variants are rejected unless allowSHA1 is true (a per-tenant legacy-interop
// opt-in): SHA-1 is collision-feasible and must not be accepted on a
// security-relevant control message by default.
func hashForSigAlg(sigAlg string, allowSHA1 bool) (crypto.Hash, bool, error) {
	switch sigAlg {
	case sigAlgRSASHA1:
		if !allowSHA1 {
			return 0, false, errSHA1Disabled
		}
		return crypto.SHA1, false, nil
	case sigAlgRSASHA256:
		return crypto.SHA256, false, nil
	case sigAlgRSASHA384:
		return crypto.SHA384, false, nil
	case sigAlgRSASHA512:
		return crypto.SHA512, false, nil
	case sigAlgECDSASHA1:
		if !allowSHA1 {
			return 0, true, errSHA1Disabled
		}
		return crypto.SHA1, true, nil
	case sigAlgECDSA256:
		return crypto.SHA256, true, nil
	case sigAlgECDSA384:
		return crypto.SHA384, true, nil
	case sigAlgECDSA512:
		return crypto.SHA512, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported SigAlg %q", sigAlg)
	}
}

// errSHA1Disabled is returned by hashForSigAlg when a SHA-1 SigAlg is presented
// but the SP's tenant has not opted into legacy SHA-1 interop.
var errSHA1Disabled = errors.New("SHA-1 signature algorithms are disabled; enable AllowInsecureSHA1 for this tenant to permit legacy SP interop")

// parseSigningCert PEM-decodes and parses an X.509 certificate.
func parseSigningCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// rawQueryParam returns the raw (still-percent-encoded) value of key from a raw
// query string, preserving the exact bytes the SP signed. It does not URL-decode.
func rawQueryParam(rawQuery, key string) (string, bool) {
	for pair := range strings.SplitSeq(rawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if k == key {
			return v, true
		}
	}
	return "", false
}

// buildLogoutResponse creates a SAML LogoutResponse carrying the given status
// (Success or PartialLogout). The issuer URL is derived from the server-side
// baseURL, never from the untrusted request host/scheme.
func buildLogoutResponse(req *saml.LogoutRequest, baseURL, tenantSlug, destination, status string) *saml.LogoutResponse {
	issuerURL := fmt.Sprintf("%s/t/%s/saml/metadata", strings.TrimRight(baseURL, "/"), tenantSlug)

	return &saml.LogoutResponse{
		ID:           fmt.Sprintf("_lr_%s", randomID()),
		InResponseTo: req.ID,
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  destination,
		Issuer: &saml.Issuer{
			Value: issuerURL,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: status,
			},
		},
	}
}

// clearSessionCookie writes a Set-Cookie that expires the gateway session
// cookie (MaxAge<0), terminating the session at the gateway. The name,
// Path, and security attributes match the cookie minted in session_provider.go
// so the browser drops the exact cookie that carried the session.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// otherParticipants counts session participants whose SP entityID differs from
// the SP that issued this LogoutRequest. A non-zero count means the session was
// shared with SPs this single front-channel response cannot reach, so logout is
// only partial.
func otherParticipants(participants []domain.SessionParticipant, requestingIssuer string) int {
	n := 0
	for _, p := range participants {
		if p.SPEntityID != requestingIssuer {
			n++
		}
	}
	return n
}

// Helper functions to safely extract values from optional SAML fields.

func issuerValue(issuer *saml.Issuer) string {
	if issuer == nil {
		return ""
	}
	return issuer.Value
}

func nameIDValue(nameID *saml.NameID) string {
	if nameID == nil {
		return ""
	}
	return nameID.Value
}

func sessionIndexValue(si *saml.SessionIndex) string {
	if si == nil {
		return ""
	}
	return si.Value
}

// randomID generates a random hex string for use as a SAML response ID.
func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
