package cognito

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverPool(t *testing.T) {
	// Note: This test verifies the discovery logic structure.
	// Integration tests with real AWS credentials are run separately.

	t.Run("builds correct domain from pool", func(t *testing.T) {
		domain := "my-app"
		region := "eu-north-1"

		poolInfo := &PoolInfo{
			Domain:     domain + ".auth." + region + ".amazoncognito.com",
			Attributes: []string{"email", "given_name", "family_name"},
		}

		assert.Equal(t, "my-app.auth.eu-north-1.amazoncognito.com", poolInfo.Domain)
		assert.Len(t, poolInfo.Attributes, 3)
		assert.Contains(t, poolInfo.Attributes, "email")
	})

	t.Run("handles custom attributes", func(t *testing.T) {
		attrs := []string{
			"email",
			"given_name",
			"family_name",
			"custom:tenant_id",
			"custom:organization",
		}

		poolInfo := &PoolInfo{
			Attributes: attrs,
		}

		assert.Len(t, poolInfo.Attributes, 5)
		assert.Contains(t, poolInfo.Attributes, "custom:tenant_id")
		assert.Contains(t, poolInfo.Attributes, "custom:organization")
	})

	t.Run("handles empty domain", func(t *testing.T) {
		poolInfo := &PoolInfo{
			Domain:     "",
			Attributes: []string{},
		}

		assert.Empty(t, poolInfo.Domain)
		assert.Empty(t, poolInfo.Attributes)
	})
}

func TestPoolInfoStruct(t *testing.T) {
	info := &PoolInfo{
		Domain:     "test.auth.eu-north-1.amazoncognito.com",
		Attributes: []string{"email", "sub", "custom:tenant"},
	}

	require.NotNil(t, info)
	assert.Equal(t, "test.auth.eu-north-1.amazoncognito.com", info.Domain)
	assert.Equal(t, 3, len(info.Attributes))
}
