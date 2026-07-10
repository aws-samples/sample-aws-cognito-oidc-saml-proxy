package publisher

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubS3Client struct {
	calls     atomic.Int32
	lastInput *s3.PutObjectInput
	returnErr error
}

func (s *stubS3Client) PutObject(ctx context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.calls.Add(1)
	s.lastInput = in
	if s.returnErr != nil {
		return nil, s.returnErr
	}
	return &s3.PutObjectOutput{}, nil
}

func TestPublisher_Publish_UploadsAndReturnsURL(t *testing.T) {
	stub := &stubS3Client{}
	p := NewS3(stub, "my-iac-bucket", "https://my-iac-bucket.s3.eu-north-1.amazonaws.com")

	url, err := p.Publish(context.Background(), "acme", "cfn", []byte("dummy-body"))
	require.NoError(t, err)

	require.NotNil(t, stub.lastInput)
	assert.Equal(t, "my-iac-bucket", aws.ToString(stub.lastInput.Bucket))
	assert.True(t, strings.HasPrefix(aws.ToString(stub.lastInput.Key), "templates/acme/"),
		"key must be under templates/<slug>/, got %q", aws.ToString(stub.lastInput.Key))
	assert.True(t, strings.HasSuffix(aws.ToString(stub.lastInput.Key), ".yaml"),
		"cfn format must produce .yaml extension")
	assert.Equal(t, "application/x-yaml", aws.ToString(stub.lastInput.ContentType))

	assert.True(t, strings.HasPrefix(url, "https://my-iac-bucket.s3.eu-north-1.amazonaws.com/templates/acme/"),
		"returned URL must be public-addressable (virtual-hosted style), got %q", url)
}

func TestPublisher_Publish_FormatExtensions(t *testing.T) {
	stub := &stubS3Client{}
	p := NewS3(stub, "bucket", "https://s3.us-east-1.amazonaws.com")

	cases := map[string]string{
		"cfn": ".yaml",
		"tf":  ".tf",
		"cli": ".sh",
	}
	for fmt, ext := range cases {
		_, err := p.Publish(context.Background(), "acme", fmt, []byte("x"))
		require.NoError(t, err, "format %s", fmt)
		assert.True(t, strings.HasSuffix(aws.ToString(stub.lastInput.Key), ext), "format %s → %s", fmt, ext)
	}
}

func TestPublisher_Publish_RejectsUnknownFormat(t *testing.T) {
	stub := &stubS3Client{}
	p := NewS3(stub, "bucket", "https://s3.example.com")

	_, err := p.Publish(context.Background(), "acme", "toml", []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
	assert.Equal(t, int32(0), stub.calls.Load(), "must not call S3 on format error")
}

func TestPublisher_Publish_PropagatesS3Error(t *testing.T) {
	stub := &stubS3Client{returnErr: errors.New("AccessDenied")}
	p := NewS3(stub, "bucket", "https://s3.example.com")

	_, err := p.Publish(context.Background(), "acme", "cfn", []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestPublisher_Publish_UniqueKeyPerCall(t *testing.T) {
	stub := &stubS3Client{}
	p := NewS3(stub, "bucket", "https://s3.example.com")

	_, err := p.Publish(context.Background(), "acme", "cfn", []byte("x"))
	require.NoError(t, err)
	key1 := aws.ToString(stub.lastInput.Key)

	_, err = p.Publish(context.Background(), "acme", "cfn", []byte("x"))
	require.NoError(t, err)
	key2 := aws.ToString(stub.lastInput.Key)

	assert.NotEqual(t, key1, key2, "consecutive publishes must produce different object keys")
}
