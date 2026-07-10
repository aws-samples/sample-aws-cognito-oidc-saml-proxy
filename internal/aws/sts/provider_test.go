package sts

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSTSClient implements stscreds.AssumeRoleAPIClient for unit tests.
type stubSTSClient struct {
	mu         sync.Mutex
	callCount  atomic.Int32
	lastInput  *sts.AssumeRoleInput
	returnErr  error
	expiration time.Time
}

func (s *stubSTSClient) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	s.callCount.Add(1)
	s.mu.Lock()
	s.lastInput = in
	s.mu.Unlock()
	if s.returnErr != nil {
		return nil, s.returnErr
	}
	exp := s.expiration
	if exp.IsZero() {
		exp = time.Now().Add(1 * time.Hour)
	}
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIA-TEST"),
			SecretAccessKey: aws.String("SECRET-TEST"),
			SessionToken:    aws.String("SESSION-TEST"),
			Expiration:      &exp,
		},
	}, nil
}

func tenantSource(slug, roleArn, externalID string) *tenant.IdentitySource {
	return &tenant.IdentitySource{
		TenantSlug: slug,
		RoleArn:    roleArn,
		ExternalID: externalID,
	}
}

func TestProvider_AssumeForTenant_CallsSTSWithExternalID(t *testing.T) {
	stub := &stubSTSClient{}
	p := NewProvider(stub)

	src := tenantSource("acme", "arn:aws:iam::123456789012:role/identity-gateway-acme", "EXT-123")
	creds, err := p.AssumeForTenant(context.Background(), src)
	require.NoError(t, err)

	// Retrieve at least once to force the AssumeRole call.
	_, err = creds.Retrieve(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(1), stub.callCount.Load())
	require.NotNil(t, stub.lastInput)
	assert.Equal(t, "arn:aws:iam::123456789012:role/identity-gateway-acme", aws.ToString(stub.lastInput.RoleArn))
	require.NotNil(t, stub.lastInput.ExternalId)
	assert.Equal(t, "EXT-123", aws.ToString(stub.lastInput.ExternalId))
	assert.Contains(t, aws.ToString(stub.lastInput.RoleSessionName), "acme")
}

func TestProvider_AssumeForTenant_CachesPerTenant(t *testing.T) {
	stub := &stubSTSClient{}
	p := NewProvider(stub)

	src := tenantSource("acme", "arn:aws:iam::123456789012:role/identity-gateway-acme", "EXT-123")

	// Two AssumeForTenant calls for the same tenant must return the SAME provider instance
	// (so credentials caching across calls is shared).
	creds1, err := p.AssumeForTenant(context.Background(), src)
	require.NoError(t, err)
	creds2, err := p.AssumeForTenant(context.Background(), src)
	require.NoError(t, err)
	assert.Same(t, creds1, creds2, "must return the cached instance (same pointer)")

	// Retrieve from both — the CredentialsCache should serve the second from cache.
	_, err = creds1.Retrieve(context.Background())
	require.NoError(t, err)
	_, err = creds2.Retrieve(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(1), stub.callCount.Load(), "second call must reuse cached creds")
}

func TestProvider_AssumeForTenant_DifferentTenantsIsolated(t *testing.T) {
	stub := &stubSTSClient{}
	p := NewProvider(stub)

	srcA := tenantSource("acme", "arn:aws:iam::111111111111:role/identity-gateway-acme", "EXT-A")
	srcB := tenantSource("beta", "arn:aws:iam::222222222222:role/identity-gateway-beta", "EXT-B")

	credsA, err := p.AssumeForTenant(context.Background(), srcA)
	require.NoError(t, err)
	credsB, err := p.AssumeForTenant(context.Background(), srcB)
	require.NoError(t, err)

	_, err = credsA.Retrieve(context.Background())
	require.NoError(t, err)
	_, err = credsB.Retrieve(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(2), stub.callCount.Load(), "different tenants must each get one AssumeRole call")
}

func TestProvider_AssumeForTenant_PropagatesError(t *testing.T) {
	stub := &stubSTSClient{returnErr: errors.New("AccessDenied: trust policy rejected caller")}
	p := NewProvider(stub)

	src := tenantSource("acme", "arn:aws:iam::123456789012:role/identity-gateway-acme", "EXT-123")
	creds, err := p.AssumeForTenant(context.Background(), src)
	require.NoError(t, err, "AssumeForTenant returns a lazy provider; error surfaces on Retrieve")

	_, err = creds.Retrieve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestProvider_AssumeForTenant_RejectsMissingRoleArn(t *testing.T) {
	stub := &stubSTSClient{}
	p := NewProvider(stub)

	src := tenantSource("acme", "", "EXT-123")
	_, err := p.AssumeForTenant(context.Background(), src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RoleArn is required")
}

func TestProvider_AssumeForTenant_RejectsMissingExternalID(t *testing.T) {
	stub := &stubSTSClient{}
	p := NewProvider(stub)

	src := tenantSource("acme", "arn:aws:iam::123456789012:role/identity-gateway-acme", "")
	_, err := p.AssumeForTenant(context.Background(), src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ExternalID is required")
}

func TestProvider_AssumeForTenant_RejectsNilSource(t *testing.T) {
	stub := &stubSTSClient{}
	p := NewProvider(stub)

	_, err := p.AssumeForTenant(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source must not be nil")
}

func TestProvider_AssumeForTenant_TruncatesLongSlugForSessionName(t *testing.T) {
	stub := &stubSTSClient{}
	p := NewProvider(stub)

	// Slug of 60 chars → with 17-char prefix would be 77 chars without truncation.
	// After fix, session name must be ≤ 64 chars.
	longSlug := "acme-corporation-with-a-very-long-identifier-for-testing-tru"
	require.Equal(t, 60, len(longSlug))

	src := tenantSource(longSlug, "arn:aws:iam::123456789012:role/identity-gateway-acme", "EXT-123")
	creds, err := p.AssumeForTenant(context.Background(), src)
	require.NoError(t, err)
	_, err = creds.Retrieve(context.Background())
	require.NoError(t, err)

	require.NotNil(t, stub.lastInput)
	sessionName := aws.ToString(stub.lastInput.RoleSessionName)
	assert.LessOrEqual(t, len(sessionName), 64, "RoleSessionName must be ≤ 64 chars per AWS STS limits")
	assert.True(t, strings.HasPrefix(sessionName, "identity-gateway-"), "prefix must be preserved")
}
