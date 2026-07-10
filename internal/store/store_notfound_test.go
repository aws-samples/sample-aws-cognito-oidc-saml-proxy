package store

import (
	"errors"
	"fmt"
	"testing"

	"github.com/guregu/dynamo/v2"
	"github.com/stretchr/testify/assert"
)

// TestTranslateGetErr_MapsDynamoNotFound ensures a real DynamoDB miss
// (guregu's dynamo.ErrNotFound) is translated to the store's own ErrNotFound
// sentinel, so handlers branching on errors.Is(err, store.ErrNotFound) return
// 404 instead of 500.
func TestTranslateGetErr_MapsDynamoNotFound(t *testing.T) {
	got := translateGetErr(dynamo.ErrNotFound)
	assert.ErrorIs(t, got, ErrNotFound, "dynamo.ErrNotFound must map to store.ErrNotFound")
}

// TestTranslateGetErr_WrappedDynamoNotFound ensures the translation also fires
// when the not-found sentinel is wrapped, since guregu may return it wrapped.
func TestTranslateGetErr_WrappedDynamoNotFound(t *testing.T) {
	wrapped := fmt.Errorf("get failed: %w", dynamo.ErrNotFound)
	got := translateGetErr(wrapped)
	assert.ErrorIs(t, got, ErrNotFound, "wrapped dynamo.ErrNotFound must map to store.ErrNotFound")
}

// TestTranslateGetErr_PassesThroughOtherErrors ensures unrelated errors are
// returned verbatim and are NOT misreported as not-found.
func TestTranslateGetErr_PassesThroughOtherErrors(t *testing.T) {
	other := errors.New("throttled: provisioned throughput exceeded")
	got := translateGetErr(other)
	assert.Same(t, other, got, "non-not-found errors must be returned unchanged")
	assert.NotErrorIs(t, got, ErrNotFound, "other errors must not be reported as not found")
}

// TestTranslateGetErr_NilPassesThrough ensures a successful Get (nil error) is
// not turned into a spurious error.
func TestTranslateGetErr_NilPassesThrough(t *testing.T) {
	assert.NoError(t, translateGetErr(nil))
}
