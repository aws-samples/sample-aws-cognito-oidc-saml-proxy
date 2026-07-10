// Package secrets wraps AWS Secrets Manager GetSecretValue with caller-provided
// credentials (typically cross-account assumed-role credentials). The client is
// intentionally thin: no caching, no rotation handling. Callers cache the result
// of GetSecret at their level (e.g., per-Lambda-instance, 5-minute TTL).
//
// It is wired into a SecretFetcher closure for
// cognito.NewAuthClientForSource so a tenant's Cognito app-client secret can be
// read from the tenant's own AWS account via the cross-account role.
package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// GetSecretValueAPI is the minimal interface from secretsmanager.Client that Client uses.
// Defined here so tests can stub without importing the real client.
type GetSecretValueAPI interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Client fetches SecretString values from AWS Secrets Manager.
type Client struct {
	api GetSecretValueAPI
}

// NewClient returns a Client backed by the given API implementation.
// In production, pass secretsmanager.NewFromConfig(tenantCfg) where tenantCfg
// has cross-account assumed-role credentials.
func NewClient(api GetSecretValueAPI) *Client {
	return &Client{api: api}
}

// GetSecret returns the SecretString for the given ARN. Binary secrets are
// rejected — the onboarding wizard only writes SecretString values for Cognito
// client secrets.
func (c *Client) GetSecret(ctx context.Context, arn string) (string, error) {
	if arn == "" {
		return "", fmt.Errorf("secrets: secret ARN is required")
	}
	out, err := c.api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(arn),
	})
	if err != nil {
		return "", fmt.Errorf("secrets: GetSecretValue %q: %w", arn, err)
	}
	if out.SecretString == nil || *out.SecretString == "" {
		return "", fmt.Errorf("secrets: SecretString is empty for %q (binary secrets are not supported)", arn)
	}
	return *out.SecretString, nil
}
