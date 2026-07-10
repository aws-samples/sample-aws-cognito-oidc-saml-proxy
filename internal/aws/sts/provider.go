// Package sts provides a cross-account AssumeRole credential provider for SaaS
// multi-tenant scenarios. Each tenant's IdentitySource carries a RoleArn +
// ExternalID; the provider assumes that role and caches the resulting
// credentials (auto-refreshed by aws.NewCredentialsCache) keyed by tenant slug.
package sts

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// Provider returns cached cross-account credential providers keyed by tenant slug.
type Provider struct {
	client stscreds.AssumeRoleAPIClient
	cache  sync.Map // "<tenantSlug>\x00<roleArn>" -> aws.CredentialsProvider
}

// cacheSeparator is a null byte — it cannot appear in a DNS-safe tenant slug
// or an AWS ARN, so using it as the cache-key separator eliminates any
// theoretical collision from slug characters that resemble the separator.
const cacheSeparator = "\x00"

// NewProvider returns a Provider backed by the given STS client.
// Pass sts.NewFromConfig(baseCfg) where baseCfg has the Lambda's execution-role credentials.
func NewProvider(client stscreds.AssumeRoleAPIClient) *Provider {
	return &Provider{client: client}
}

// AssumeForTenant returns a credentials provider that assumes the tenant's
// cross-account role. The returned provider is safe to use with service-client
// constructors (cognitoidentityprovider.NewFromConfig etc.) via aws.Config.Credentials.
//
// Credentials are retrieved lazily on first use and cached until within 5
// minutes of expiry by aws.NewCredentialsCache (SDK default).
func (p *Provider) AssumeForTenant(ctx context.Context, src *tenant.IdentitySource) (aws.CredentialsProvider, error) {
	if src == nil {
		return nil, fmt.Errorf("sts: source must not be nil")
	}
	if src.RoleArn == "" {
		return nil, fmt.Errorf("sts: RoleArn is required on identity source %q", src.ID)
	}
	if src.ExternalID == "" {
		return nil, fmt.Errorf("sts: ExternalID is required on identity source %q", src.ID)
	}

	key := src.TenantSlug + cacheSeparator + src.RoleArn
	if cached, ok := p.cache.Load(key); ok {
		return cached.(aws.CredentialsProvider), nil
	}

	// AWS STS limits RoleSessionName to 64 characters. Prefix is 17 chars;
	// truncate the slug to 47 so the combined length fits.
	slug := src.TenantSlug
	if len(slug) > 47 {
		slug = slug[:47]
	}
	sessionName := fmt.Sprintf("identity-gateway-%s", slug)
	assumeProvider := stscreds.NewAssumeRoleProvider(p.client, src.RoleArn, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(src.ExternalID)
		o.RoleSessionName = sessionName
	})
	cached := aws.NewCredentialsCache(assumeProvider)

	// LoadOrStore handles the race where two goroutines build the same key simultaneously:
	// only one entry wins; both return the same cached value.
	actual, _ := p.cache.LoadOrStore(key, aws.CredentialsProvider(cached))
	return actual.(aws.CredentialsProvider), nil
}
