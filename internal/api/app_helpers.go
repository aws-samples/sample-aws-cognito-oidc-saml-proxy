package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// MetadataFetcher is an interface for fetching SP metadata, allowing test injection.
type MetadataFetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// HTTPMetadataFetcher fetches metadata over HTTP.
type HTTPMetadataFetcher struct{}

// Fetch retrieves metadata from the given URL.
func (f *HTTPMetadataFetcher) Fetch(_ context.Context, metadataURL string) ([]byte, error) {
	resp, err := http.Get(metadataURL) //nolint:gosec // URL is user-provided and validated
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata URL returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata body: %w", err)
	}
	return body, nil
}

// tenantSlugFromContext extracts the tenant slug from context.
// Returns the slug and true if found, or empty string and false otherwise.
func tenantSlugFromContext(ctx context.Context) (string, bool) {
	t, ok := tenant.FromContext(ctx)
	if !ok || t == nil {
		return "", false
	}
	return t.Slug, true
}

// setBoolDefault returns the value if not nil, otherwise returns the default.
func setBoolDefault(val *bool, defaultVal bool) bool {
	if val != nil {
		return *val
	}
	return defaultVal
}

// setStringDefault returns the value if not empty, otherwise returns the default.
func setStringDefault(val string, defaultVal string) string {
	if val != "" {
		return val
	}
	return defaultVal
}

// setIntDefault returns the value if not zero, otherwise returns the default.
func setIntDefault(val int, defaultVal int) int {
	if val != 0 {
		return val
	}
	return defaultVal
}

// isNotFound checks whether an error wraps store.ErrNotFound.
func isNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound)
}

// toPEM wraps base64-encoded certificate data in PEM headers.
func toPEM(base64Data string) string {
	// Clean whitespace from the base64 data.
	cleaned := strings.Join(strings.Fields(base64Data), "")
	return "-----BEGIN CERTIFICATE-----\n" + cleaned + "\n-----END CERTIFICATE-----"
}

// toClaimMappings converts the wizard's simplified {source,target} claim
// mappings into domain ClaimMapping records. The target attribute name is used
// as the mapping Name (its DynamoDB key), so mappings must have distinct
// targets. Entries with an empty target are skipped.
func toClaimMappings(in []ClaimMappingInput) []tenant.ClaimMapping {
	out := make([]tenant.ClaimMapping, 0, len(in))
	for _, m := range in {
		if m.Target == "" {
			continue
		}
		out = append(out, tenant.ClaimMapping{
			Name:            m.Target,
			SourceType:      "attribute",
			SourceAttribute: m.Source,
			TargetAttribute: m.Target,
		})
	}
	return out
}

// toRoleMappings converts the wizard's simplified {group,value} role mappings
// into domain RoleMapping records. Entries with an empty group are skipped.
func toRoleMappings(in []RoleMappingInput) []tenant.RoleMapping {
	out := make([]tenant.RoleMapping, 0, len(in))
	for _, m := range in {
		if m.Group == "" {
			continue
		}
		out = append(out, tenant.RoleMapping{
			CognitoGroup: m.Group,
			MappedValue:  m.Value,
		})
	}
	return out
}

// nameIDFormatURNs maps short NameID-format codes to their canonical SAML URNs.
var nameIDFormatURNs = map[string]string{
	"email":        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	"emailaddress": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	"persistent":   "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
	"transient":    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
	"unspecified":  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
}

// normalizeNameIDFormat converts a NameID format into the canonical SAML URN
// that the SAML layer writes into IdP metadata. It accepts both short codes
// (email/persistent/transient/unspecified) and full URNs (in any case),
// returning the canonical URN. Unrecognized values are passed through
// unchanged so custom formats still work.
func normalizeNameIDFormat(v string) string {
	key := strings.ToLower(strings.TrimSpace(v))
	if key == "" {
		return nameIDFormatURNs["unspecified"]
	}
	if urn, ok := nameIDFormatURNs[key]; ok {
		return urn
	}
	// Already a URN (possibly differing only in case) — map known lowercased
	// URNs back to canonical casing; otherwise pass through.
	switch key {
	case "urn:oasis:names:tc:saml:1.1:nameid-format:emailaddress":
		return nameIDFormatURNs["email"]
	case "urn:oasis:names:tc:saml:2.0:nameid-format:persistent":
		return nameIDFormatURNs["persistent"]
	case "urn:oasis:names:tc:saml:2.0:nameid-format:transient":
		return nameIDFormatURNs["transient"]
	case "urn:oasis:names:tc:saml:1.1:nameid-format:unspecified":
		return nameIDFormatURNs["unspecified"]
	}
	return v
}
