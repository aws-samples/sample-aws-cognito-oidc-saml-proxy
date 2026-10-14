package tenant

import "strings"

// Canonical SAML NameID-Format URNs. These are the only values the SAML layer
// writes into IdP metadata and assertions; CanonicalNameIDFormat maps the short
// codes and case-variant URNs accepted by the management API onto them.
const (
	NameIDFormatEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

// nameIDFormatByKey maps lower-cased short codes and URNs to the canonical URN.
var nameIDFormatByKey = map[string]string{
	"email":        NameIDFormatEmail,
	"emailaddress": NameIDFormatEmail,
	"persistent":   NameIDFormatPersistent,
	"transient":    NameIDFormatTransient,
	"unspecified":  NameIDFormatUnspecified,

	strings.ToLower(NameIDFormatEmail):       NameIDFormatEmail,
	strings.ToLower(NameIDFormatPersistent):  NameIDFormatPersistent,
	strings.ToLower(NameIDFormatTransient):   NameIDFormatTransient,
	strings.ToLower(NameIDFormatUnspecified): NameIDFormatUnspecified,
}

// CanonicalNameIDFormat converts a NameID format into the canonical SAML URN.
// It accepts the short codes email/emailaddress/persistent/transient/unspecified
// and the full URNs in any case. An empty value is the unspecified format.
// Unrecognised values are passed through unchanged so custom formats still
// work (the SAML layer treats them like unspecified when choosing a NameID).
func CanonicalNameIDFormat(v string) string {
	key := strings.ToLower(strings.TrimSpace(v))
	if key == "" {
		return NameIDFormatUnspecified
	}
	if urn, ok := nameIDFormatByKey[key]; ok {
		return urn
	}
	return v
}
