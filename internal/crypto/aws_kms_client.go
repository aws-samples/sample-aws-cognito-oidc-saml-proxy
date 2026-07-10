package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSClientAPI abstracts the AWS KMS SDK operations used by AWSKMSClient.
// This allows for dependency injection and testing with mocks.
type KMSClientAPI interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// AWSKMSClient implements KMSSignerClient using the real AWS KMS service.
type AWSKMSClient struct {
	client KMSClientAPI
	keyID  string
}

// NewAWSKMSClient creates a new AWSKMSClient that uses the given KMS client
// and key ID for cryptographic operations.
func NewAWSKMSClient(cfg aws.Config, keyID string) *AWSKMSClient {
	return &AWSKMSClient{
		client: kms.NewFromConfig(cfg),
		keyID:  keyID,
	}
}

// NewAWSKMSClientFromAPI creates a new AWSKMSClient from a KMSClientAPI interface.
// This is useful for testing or when you already have a KMS client instance.
func NewAWSKMSClientFromAPI(client KMSClientAPI, keyID string) *AWSKMSClient {
	return &AWSKMSClient{
		client: client,
		keyID:  keyID,
	}
}

// Sign signs the given digest using the KMS key with RSASSA_PKCS1_V1_5_SHA_256.
// The digest must be a pre-computed SHA-256 hash (32 bytes).
func (c *AWSKMSClient) Sign(digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	result, err := c.client.Sign(context.Background(), &kms.SignInput{
		KeyId:            &c.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Sign failed: %w", err)
	}

	return result.Signature, nil
}

// PublicKey retrieves the RSA public key from the KMS key.
func (c *AWSKMSClient) PublicKey() (*rsa.PublicKey, error) {
	result, err := c.client.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{
		KeyId: &c.keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS GetPublicKey failed: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(result.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key is not an RSA key")
	}

	return rsaPub, nil
}

// Verify compile-time interface compliance.
var _ KMSSignerClient = (*AWSKMSClient)(nil)
