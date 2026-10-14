package crypto

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSecretsClient returns a canned GetSecretValue response (or error) and
// records the SecretId it was asked for.
type stubSecretsClient struct {
	out      *secretsmanager.GetSecretValueOutput
	err      error
	secretID string
}

func (s *stubSecretsClient) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	s.secretID = aws.ToString(in.SecretId)
	return s.out, s.err
}

func TestFetchCookieKey_32Bytes_OK(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	client := &stubSecretsClient{out: &secretsmanager.GetSecretValueOutput{SecretBinary: want}}

	key, err := FetchCookieKey(context.Background(), client, "arn:aws:secretsmanager:us-east-1:111122223333:secret:cookie-key")
	require.NoError(t, err)
	assert.Equal(t, want, key)
	assert.Equal(t, "arn:aws:secretsmanager:us-east-1:111122223333:secret:cookie-key", client.secretID)

	// The returned slice must be a copy, not an alias of the SDK response.
	want[0] ^= 0xff
	assert.NotEqual(t, want[0], key[0])
}

func TestFetchCookieKey_WrongLength_Errors(t *testing.T) {
	for _, l := range []int{0, 16, 31, 33, 64} {
		client := &stubSecretsClient{out: &secretsmanager.GetSecretValueOutput{SecretBinary: make([]byte, l)}}
		_, err := FetchCookieKey(context.Background(), client, "cookie-key")
		require.Error(t, err, "length %d must be rejected", l)
		if l == 0 {
			// make([]byte, 0) is non-nil, so this is the wrong-length branch too.
			assert.Contains(t, err.Error(), "wrong length")
		}
	}
}

func TestFetchCookieKey_NilBinary_Errors(t *testing.T) {
	client := &stubSecretsClient{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("not-binary")}}
	_, err := FetchCookieKey(context.Background(), client, "cookie-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no binary value")
}

func TestFetchCookieKey_ClientError_Wrapped(t *testing.T) {
	sentinel := errors.New("access denied")
	client := &stubSecretsClient{err: sentinel}
	_, err := FetchCookieKey(context.Background(), client, "cookie-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Contains(t, err.Error(), "cookie key")
}

// FetchOIDCCryptoKey shares fetchSecretKey32; make sure the refactor kept its
// contract (32-byte array, same validation).
func TestFetchOIDCCryptoKey_SharesValidation(t *testing.T) {
	want := make([]byte, 32)
	want[31] = 0x42
	client := &stubSecretsClient{out: &secretsmanager.GetSecretValueOutput{SecretBinary: want}}
	key, err := FetchOIDCCryptoKey(context.Background(), client, "oidc-key")
	require.NoError(t, err)
	assert.Equal(t, byte(0x42), key[31])

	client = &stubSecretsClient{out: &secretsmanager.GetSecretValueOutput{SecretBinary: make([]byte, 31)}}
	_, err = FetchOIDCCryptoKey(context.Background(), client, "oidc-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC crypto key")
}
