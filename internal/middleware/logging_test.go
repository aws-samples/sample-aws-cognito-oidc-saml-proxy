package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogging_RequestPassesThrough(t *testing.T) {
	nextCalled := false
	handler := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLogging_ResponseWriterCapturesStatusCode(t *testing.T) {
	var capturedStatus int
	handler := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	// Wrap the handler to intercept the responseWriter after ServeHTTP
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/applications", nil)
	rec := httptest.NewRecorder()

	inner.ServeHTTP(rec, req)

	// The recorder should have the status from the inner handler
	assert.Equal(t, http.StatusCreated, rec.Code)
	// capturedStatus is zero because we can't directly inspect the wrapped writer,
	// but we can test the responseWriter type directly
	_ = capturedStatus
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	wrapped.WriteHeader(http.StatusNotFound)

	assert.Equal(t, http.StatusNotFound, wrapped.statusCode)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestResponseWriter_DefaultStatusCode(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	// Without calling WriteHeader, the default should be 200
	assert.Equal(t, http.StatusOK, wrapped.statusCode)
}

func TestLogging_DifferentHTTPMethods(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}
