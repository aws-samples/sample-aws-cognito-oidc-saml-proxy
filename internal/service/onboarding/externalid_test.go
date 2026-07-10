package onboarding

import (
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateExternalID_FormatMatchesAWSRules(t *testing.T) {
	got, err := GenerateExternalID()
	require.NoError(t, err)

	re := regexp.MustCompile(`^[A-Z2-7]+=*$`)
	assert.True(t, re.MatchString(got), "ExternalID must match base32 format, got %q", got)
	assert.GreaterOrEqual(t, len(got), 2, "AWS minimum length")
	assert.LessOrEqual(t, len(got), 1224, "AWS maximum length")
}

func TestGenerateExternalID_UniqueAcrossCalls(t *testing.T) {
	const n = 1000
	ids := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := GenerateExternalID()
			if err == nil {
				ids <- id
			}
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[string]struct{}, n)
	for id := range ids {
		_, dup := seen[id]
		require.False(t, dup, "duplicate ExternalID generated: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, n, "all %d IDs must be unique", n)
}

func TestGenerateExternalID_LengthIsStable(t *testing.T) {
	id, err := GenerateExternalID()
	require.NoError(t, err)
	assert.Equal(t, 52, len(id), "fixed 52-char output so trust policies don't need dynamic sizing")
}
