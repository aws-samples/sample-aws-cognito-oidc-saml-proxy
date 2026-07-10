package cognito

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// PoolInfo contains discovered information about a Cognito User Pool.
type PoolInfo struct {
	Domain     string   `json:"domain"`     // e.g., "my-app.auth.eu-north-1.amazoncognito.com"
	Attributes []string `json:"attributes"` // Schema attribute names (email, given_name, custom:tenant_id, etc.)
}

// DiscoverPool calls DescribeUserPool and returns pool configuration.
// Returns nil, nil if AWS credentials are not available (e.g., local dev without AWS_PROFILE).
func DiscoverPool(ctx context.Context, cfg aws.Config, poolID, region string) (*PoolInfo, error) {
	client := cip.NewFromConfig(cfg, func(o *cip.Options) {
		o.Region = region
	})

	result, err := client.DescribeUserPool(ctx, &cip.DescribeUserPoolInput{
		UserPoolId: &poolID,
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeUserPool failed: %w", err)
	}

	pool := result.UserPool
	info := &PoolInfo{}

	// Domain
	if pool.Domain != nil && *pool.Domain != "" {
		info.Domain = fmt.Sprintf("%s.auth.%s.amazoncognito.com", *pool.Domain, region)
	}

	// Schema attributes
	for _, attr := range pool.SchemaAttributes {
		if attr.Name != nil {
			info.Attributes = append(info.Attributes, *attr.Name)
		}
	}

	return info, nil
}
