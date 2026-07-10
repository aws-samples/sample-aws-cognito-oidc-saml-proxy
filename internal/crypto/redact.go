package crypto

import "log/slog"

// RedactedString is a string type that redacts itself in logs.
// It shows the first 4 and last 4 characters with "..." in between.
// If shorter than 12 chars, it shows "***".
type RedactedString string

// LogValue implements slog.LogValuer for automatic redaction in structured logs.
func (s RedactedString) LogValue() slog.Value {
	str := string(s)
	if len(str) < 12 {
		return slog.StringValue("***")
	}
	return slog.StringValue(str[:4] + "..." + str[len(str)-4:])
}

// String returns the redacted form (safe for fmt.Println, etc.)
func (s RedactedString) String() string {
	return s.LogValue().String()
}

// Raw returns the original unredacted value.
func (s RedactedString) Raw() string {
	return string(s)
}
