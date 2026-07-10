package secrets

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubSMClient struct {
	mu           sync.Mutex
	callCount    atomic.Int32
	lastSecretID string
	returnValue  string
	returnErr    error
}

func (s *stubSMClient) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	s.callCount.Add(1)
	s.mu.Lock()
	s.lastSecretID = aws.ToString(in.SecretId)
	s.mu.Unlock()
	if s.returnErr != nil {
		return nil, s.returnErr
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(s.returnValue)}, nil
}

func (s *stubSMClient) getLastSecretID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSecretID
}

func TestClient_GetSecret_ReturnsSecretString(t *testing.T) {
	stub := &stubSMClient{returnValue: "the-client-secret"}
	c := NewClient(stub)

	got, err := c.GetSecret(context.Background(), "arn:aws:secretsmanager:eu-north-1:123456789012:secret:cognito-client-secret-xyz-AB12CD")
	require.NoError(t, err)
	assert.Equal(t, "the-client-secret", got)
	assert.Equal(t, int32(1), stub.callCount.Load())
	assert.Equal(t, "arn:aws:secretsmanager:eu-north-1:123456789012:secret:cognito-client-secret-xyz-AB12CD", stub.getLastSecretID())
}

func TestClient_GetSecret_RejectsEmptyARN(t *testing.T) {
	stub := &stubSMClient{}
	c := NewClient(stub)

	_, err := c.GetSecret(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ARN is required")
	assert.Equal(t, int32(0), stub.callCount.Load(), "must not call SecretsManager with empty ARN")
}

func TestClient_GetSecret_PropagatesError(t *testing.T) {
	stub := &stubSMClient{returnErr: errors.New("AccessDeniedException: kms:Decrypt denied")}
	c := NewClient(stub)

	_, err := c.GetSecret(context.Background(), "arn:aws:secretsmanager:eu-north-1:123456789012:secret:whatever-ABC")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDeniedException")
}

func TestClient_GetSecret_ErrorsOnBinarySecret(t *testing.T) {
	// Binary secrets (SecretBinary set, SecretString empty) are not used for
	// Cognito client secrets. The wizard only writes SecretString entries.
	// Treat binary as a configuration error.
	stub := &stubBinarySMClient{}
	c := NewClient(stub)

	_, err := c.GetSecret(context.Background(), "arn:aws:secretsmanager:eu-north-1:123456789012:secret:binary-ABC")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SecretString is empty")
}

type stubBinarySMClient struct{}

func (s *stubBinarySMClient) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return &secretsmanager.GetSecretValueOutput{SecretBinary: []byte("binary-data")}, nil
}
