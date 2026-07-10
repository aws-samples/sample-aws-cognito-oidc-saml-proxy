// Package crypto — OIDC CryptoKey provisioning.
//
// zitadel/oidc encrypts every opaque bearer token as
// AES-GCM(tokenID + ":" + subject) using op.Config.CryptoKey. When the OIDC
// provider is split across Lambdas (oidc-token, oidc-discovery, oidc-authorize)
// each process MUST share the same 32-byte key, otherwise a token minted by
// oidc-token cannot be decrypted by oidc-discovery (functional break) and
// revocation silently no-ops under concurrency (security break, MF-5).
//
// FetchOIDCCryptoKey retrieves the shared key from AWS Secrets Manager. The
// secret is a 32-byte binary value (SecretBinary). In deployed environments the
// IaC layer creates the secret and grants each Lambda IAM access to it
// (secretsmanager:GetSecretValue); the key material never touches disk or env.
package crypto

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// OIDCCryptoKeyClient is the Secrets Manager subset needed to fetch the key.
// *secretsmanager.Client satisfies this interface; tests can inject a stub.
type OIDCCryptoKeyClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// FetchOIDCCryptoKey fetches the shared OIDC CryptoKey from Secrets Manager.
// The secret must contain exactly 32 bytes as SecretBinary. If the secret is
// absent, too short, or too long, an error is returned and the Lambda aborts
// at boot — fail closed rather than operating with an unpredictable key.
//
// secretARN may be a full ARN or a secret name; Secrets Manager resolves both.
func FetchOIDCCryptoKey(ctx context.Context, client OIDCCryptoKeyClient, secretARN string) ([32]byte, error) {
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to fetch OIDC crypto key from Secrets Manager: %w", err)
	}

	if out.SecretBinary == nil {
		return [32]byte{}, fmt.Errorf("OIDC crypto key secret %q has no binary value — expected 32-byte SecretBinary", secretARN)
	}
	if len(out.SecretBinary) != 32 {
		return [32]byte{}, fmt.Errorf("OIDC crypto key secret %q has wrong length: got %d bytes, need exactly 32", secretARN, len(out.SecretBinary))
	}

	var key [32]byte
	copy(key[:], out.SecretBinary)
	return key, nil
}
