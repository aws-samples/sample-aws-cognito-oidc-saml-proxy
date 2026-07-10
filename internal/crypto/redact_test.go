package crypto

import (
	"log/slog"
	"testing"
)

func TestRedactedString_LogValue(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"long token": {"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature", "eyJh...ture"},
		"short":      {"abc", "***"},
		"empty":      {"", "***"},
		"exactly 12": {"123456789012", "1234...9012"},
		"11 chars":   {"12345678901", "***"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rs := RedactedString(tc.input)
			got := rs.LogValue().String()
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedactedString_Raw(t *testing.T) {
	secret := RedactedString("my-super-secret-token")
	if secret.Raw() != "my-super-secret-token" {
		t.Error("Raw() should return original value")
	}
}

func TestRedactedString_ImplementsLogValuer(t *testing.T) {
	var _ slog.LogValuer = RedactedString("")
}
