package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// edgeOKHandler is the downstream handler; a 200 means the request passed the
// edge gate, a 403 means it was rejected before reaching here.
func edgeOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

const testEdgeSecret = "s3cr3t-origin-verify-value-1234567890"

// TestRequireEdgeSecret_MissingHeaderRejected asserts that with a secret
// configured (the deployed-environment case), a request that lacks the
// X-Origin-Verify header — i.e. one that reached the origin without transiting
// CloudFront — is rejected 403 and never reaches the handler.
func TestRequireEdgeSecret_MissingHeaderRejected(t *testing.T) {
	h := RequireEdgeSecret(testEdgeSecret)(edgeOKHandler())

	req := httptest.NewRequest(http.MethodGet, "/t/acme/saml/metadata", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "request without the origin-verify header must be rejected")
}

// TestRequireEdgeSecret_WrongHeaderRejected asserts a forged/incorrect header
// value does not satisfy the gate.
func TestRequireEdgeSecret_WrongHeaderRejected(t *testing.T) {
	h := RequireEdgeSecret(testEdgeSecret)(edgeOKHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set(EdgeVerifyHeader, "not-the-secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "request with a wrong origin-verify header must be rejected")
}

// TestRequireEdgeSecret_CorrectHeaderAllowed asserts the CloudFront-transited
// path: a request carrying the exact secret in X-Origin-Verify passes through.
func TestRequireEdgeSecret_CorrectHeaderAllowed(t *testing.T) {
	h := RequireEdgeSecret(testEdgeSecret)(edgeOKHandler())

	req := httptest.NewRequest(http.MethodGet, "/t/acme/oidc/authorize", nil)
	req.Header.Set(EdgeVerifyHeader, testEdgeSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "request with the correct origin-verify header must pass")
	assert.Equal(t, "ok", rec.Body.String())
}

// TestRequireEdgeSecret_EmptySecretIsNoop asserts the local-dev behavior: with
// no secret configured the middleware is a passthrough (there is no CloudFront
// edge locally). config.Load makes an empty secret impossible in any deployed
// environment, so this branch is reachable only in local dev / tests.
func TestRequireEdgeSecret_EmptySecretIsNoop(t *testing.T) {
	h := RequireEdgeSecret("")(edgeOKHandler())

	// No header set — would be a 403 if the gate were enforcing.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "with no secret configured the gate must be a no-op passthrough")
}

// TestRequireEdgeSecret_EmptySecretPassthroughIgnoresHeader guards the no-op
// path: when no secret is configured (local dev), ANY header value must be
// ignored and the request must pass. This ensures the local-dev no-op is
// unconditional and cannot accidentally reject or honour a header.
func TestRequireEdgeSecret_EmptySecretPassthroughIgnoresHeader(t *testing.T) {
	h := RequireEdgeSecret("")(edgeOKHandler())

	// A request that carries a non-empty header value — must still pass because
	// the gate is entirely disabled when secret is empty.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set(EdgeVerifyHeader, "some-arbitrary-value")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "no-op gate must pass regardless of header value")
}

// TestRequireEdgeSecret_EmptySecretDoesNotAcceptEmptyHeader guards against a
// bypass where an attacker sends an empty X-Origin-Verify header hoping it
// matches an empty configured secret. When enforcing (non-empty secret), an
// empty header value must still be rejected.
func TestRequireEdgeSecret_EmptySecretDoesNotAcceptEmptyHeader(t *testing.T) {
	h := RequireEdgeSecret(testEdgeSecret)(edgeOKHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set(EdgeVerifyHeader, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "an empty header must not satisfy a configured secret")
}
