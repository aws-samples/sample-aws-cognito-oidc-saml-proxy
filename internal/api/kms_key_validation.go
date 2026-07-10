package api

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// KMSKeyPolicy constrains the per-tenant KMS signing key a tenant admin may
// register on a tenant.
//
// A tenant admin is authenticated only for their own tenant, but the gateway
// signs SAML assertions and OIDC tokens with its OWN IAM identity. An
// unvalidated, client-supplied key reference is therefore a classic
// confused-deputy vector: a caller could register a fully-qualified ARN that
// points at a KMS key in another AWS account for which the gateway's execution
// role happens to hold a kms:Sign grant, or feed a malformed value straight
// into the signing path. This policy exists so that client-supplied key
// references are validated rather than stored and used verbatim.
//
// The safe rules this policy enforces:
//   - A bare key ID (UUID or multi-region mrk-...) or a bare alias name
//     ("alias/...") is always resolved by KMS within the gateway's OWN account
//     and region, so it cannot reference a foreign key — only its syntax is
//     validated.
//   - A fully-qualified ARN can point anywhere, so it must be pinned to the
//     gateway's own AccountID and Region. In a deployed environment (Strict),
//     if the gateway does not know its own account (AccountID unset), a
//     fully-qualified ARN is refused outright rather than accepted unpinned —
//     failing closed, consistent with the rest of the policy.
type KMSKeyPolicy struct {
	// AccountID is the gateway's own AWS account number (config.SaaSAccountID).
	// When set, any supplied key/alias ARN must belong to this account.
	AccountID string
	// Region is the gateway's operating region (config.AWSRegion). When set, any
	// supplied key/alias ARN must be in this region.
	Region string
	// Strict is true in every deployed environment and false only in local dev.
	// When true, a fully-qualified ARN that cannot be pinned to a known gateway
	// account is rejected rather than accepted.
	Strict bool
}

var (
	// kmsBareKeyIDPattern matches a bare KMS key identifier: a standard key UUID
	// or a multi-region key id (mrk- followed by 32 hex chars). KMS resolves such
	// unqualified ids within the caller's own account+region.
	kmsBareKeyIDPattern = regexp.MustCompile(`^(mrk-[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
	// kmsAliasNamePattern matches a bare alias name. Alias names allow
	// alphanumerics plus /_- and are also resolved account-locally by KMS. The
	// reserved "alias/aws/" AWS-managed prefix is rejected separately.
	kmsAliasNamePattern = regexp.MustCompile(`^alias/[a-zA-Z0-9/_-]{1,250}$`)
)

// validateTenantKMSKeyRefs validates the optional client-supplied KMS key
// references on a tenant create/update before they are persisted. Empty
// values are allowed — the tenant then uses the gateway's default signing key.
func validateTenantKMSKeyRefs(keyID, keyArn string, policy KMSKeyPolicy) error {
	if keyID != "" {
		if err := policy.validateKeyRef(keyID); err != nil {
			return fmt.Errorf("invalid kmsKeyId: %w", err)
		}
	}
	if keyArn != "" {
		// The KMSKeyArn field is, by name and contract, a fully-qualified ARN.
		if !arn.IsARN(keyArn) {
			return fmt.Errorf("invalid kmsKeyArn: must be a fully-qualified KMS key ARN")
		}
		if err := policy.validateARN(keyArn); err != nil {
			return fmt.Errorf("invalid kmsKeyArn: %w", err)
		}
	}
	return nil
}

// validateKeyRef validates a KMSKeyID, which may be a bare key id, a bare alias
// name, or a fully-qualified ARN.
func (p KMSKeyPolicy) validateKeyRef(ref string) error {
	if arn.IsARN(ref) {
		return p.validateARN(ref)
	}
	if kmsBareKeyIDPattern.MatchString(ref) {
		return nil
	}
	if kmsAliasNamePattern.MatchString(ref) {
		if strings.HasPrefix(ref, "alias/aws/") {
			return fmt.Errorf("AWS-managed alias %q may not be used as a tenant signing key", ref)
		}
		return nil
	}
	return fmt.Errorf("%q is neither a valid KMS key id, alias name, nor key ARN", ref)
}

// validateARN validates a fully-qualified KMS key or alias ARN and pins it to
// the gateway's own account and region.
func (p KMSKeyPolicy) validateARN(raw string) error {
	parsed, err := arn.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid ARN: %w", err)
	}
	if parsed.Service != "kms" {
		return fmt.Errorf("ARN service must be \"kms\", got %q", parsed.Service)
	}
	isKey := strings.HasPrefix(parsed.Resource, "key/")
	isAlias := strings.HasPrefix(parsed.Resource, "alias/")
	if !isKey && !isAlias {
		return fmt.Errorf("KMS ARN resource must be a key/... or alias/... resource, got %q", parsed.Resource)
	}
	// Require a non-empty resource identifier after the "key/" or "alias/" prefix.
	if _, id, _ := strings.Cut(parsed.Resource, "/"); id == "" {
		return fmt.Errorf("KMS ARN is missing a key or alias identifier")
	}
	if isAlias && strings.HasPrefix(parsed.Resource, "alias/aws/") {
		return fmt.Errorf("AWS-managed alias may not be used as a tenant signing key")
	}
	if p.AccountID == "" {
		if p.Strict {
			return fmt.Errorf("this gateway is not configured with its own account id (PROXY_SAAS_ACCOUNT_ID); refusing a fully-qualified KMS ARN that cannot be pinned to the gateway account")
		}
		// Non-strict (local dev only): allow without account pinning.
	} else if parsed.AccountID != p.AccountID {
		return fmt.Errorf("KMS key must belong to the gateway's own account %s, got %s (cross-account keys are refused as a confused-deputy defense)", p.AccountID, parsed.AccountID)
	}
	if p.Region != "" && parsed.Region != "" && parsed.Region != p.Region {
		return fmt.Errorf("KMS key must be in the gateway's region %s, got %s", p.Region, parsed.Region)
	}
	return nil
}
