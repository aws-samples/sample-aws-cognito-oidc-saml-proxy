// Package crypto — edge-secret provisioning.
//
// The CloudFront origin-verify shared secret was previously delivered as the
// PROXY_EDGE_AUTH_SECRET environment variable, exposing the raw token in the
// Lambda console and in CloudTrail GetFunctionConfiguration events. It is now
// stored in AWS Secrets Manager and fetched once at cold-start via
// FetchEdgeSecret; only the SM ARN (PROXY_EDGE_AUTH_SECRET_ARN) is stored in
// the Lambda environment, never the token itself.
package crypto

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// EdgeSecretClient is the Secrets Manager subset needed to fetch the secret.
// *secretsmanager.Client satisfies this interface; tests can inject a stub.
type EdgeSecretClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// FetchEdgeSecret fetches the CloudFront origin-verify shared secret from
// Secrets Manager. The secret is stored as a SecretString (the 48-character
// alphanumeric token that CloudFront injects as the X-Origin-Verify header).
// The returned string is passed directly to middleware.RequireEdgeSecret.
//
// secretARN may be a full ARN or a secret name; Secrets Manager resolves both.
// An error is returned — and the Lambda aborts at boot — if the fetch fails or
// the secret string is empty; fail closed rather than start without a gate.
//
// Local dev: when secretARN is empty (PROXY_EDGE_AUTH_SECRET_ARN is not set in
// local dev) FetchEdgeSecret returns an empty string without contacting SM. The
// empty string causes middleware.RequireEdgeSecret to be a no-op passthrough,
// matching the previous local-dev behaviour.
func FetchEdgeSecret(ctx context.Context, client EdgeSecretClient, secretARN string) (string, error) {
	if secretARN == "" {
		// Local dev: no ARN → no SM call → empty secret → edge middleware is a no-op.
		return "", nil
	}

	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	})
	if err != nil {
		return "", fmt.Errorf("failed to fetch edge secret from Secrets Manager: %w", err)
	}

	if out.SecretString == nil {
		return "", fmt.Errorf("edge secret %q has no string value — expected SecretString", secretARN)
	}

	val := strings.TrimSpace(*out.SecretString)
	if val == "" {
		return "", fmt.Errorf("edge secret %q resolved to an empty string — refusing to start without an edge gate", secretARN)
	}

	return val, nil
}
