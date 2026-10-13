package tenant

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanonicalNameIDFormat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty is unspecified", "", NameIDFormatUnspecified},
		{"whitespace is unspecified", "   ", NameIDFormatUnspecified},
		{"short email", "email", NameIDFormatEmail},
		{"short emailaddress", "emailAddress", NameIDFormatEmail},
		{"short persistent", "persistent", NameIDFormatPersistent},
		{"short transient", "Transient", NameIDFormatTransient},
		{"short unspecified", "unspecified", NameIDFormatUnspecified},
		{"short code with spaces", "  persistent ", NameIDFormatPersistent},
		{"email urn canonical", NameIDFormatEmail, NameIDFormatEmail},
		{"email urn lowercase", "urn:oasis:names:tc:saml:1.1:nameid-format:emailaddress", NameIDFormatEmail},
		{"persistent urn uppercase", "URN:OASIS:NAMES:TC:SAML:2.0:NAMEID-FORMAT:PERSISTENT", NameIDFormatPersistent},
		{"transient urn canonical", NameIDFormatTransient, NameIDFormatTransient},
		{"unspecified urn mixed case", "urn:oasis:names:tc:SAML:1.1:nameid-format:Unspecified", NameIDFormatUnspecified},
		{"unknown urn passthrough", "urn:example:custom-format", "urn:example:custom-format"},
		{"unknown word passthrough", "kerberos", "kerberos"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CanonicalNameIDFormat(tt.in))
		})
	}
}
