package formatters

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

// escapeMarkdownChars lists every character escapeMarkdownReplacer rewrites.
// It must stay in sync with the replacer's keys below. The two-character
// "\r\n" key needs no separate entry because both of its bytes appear here.
const escapeMarkdownChars = "\\*_`[]<>|\r\n"

// stringEscape applies the markdown escape rules to a single string. Every
// exported escaper here shares it so the strategy stays in one place.
//
// The ContainsAny guard avoids a known allocation rather than a measured one:
// the mixed-length "\r\n" key forces strings.NewReplacer onto its generic
// implementation, whose Replace allocates a buffer unconditionally, even when
// nothing matches. This now runs once per config-derived field, and most values
// contain none of these characters.
func stringEscape(s string) string {
	if !strings.ContainsAny(s, escapeMarkdownChars) {
		return strings.TrimSpace(s)
	}

	return strings.TrimSpace(escapeMarkdownReplacer.Replace(s))
}

// EscapeMarkdownValue escapes markdown metacharacters in a config-derived value
// so it renders as literal text wherever the report interpolates it.
//
// The angle brackets are the security-relevant part: goldmark's inline parser
// treats `<img src=x onerror=...>` as a raw-HTML node, not a text node, so text
// escaping never applies to it. Escaping `<` keeps it a text node. The rest are
// formatting: an unescaped `*`, `_`, `[` or backtick reformats the report, and a
// bare `|` splits a table row.
func EscapeMarkdownValue(value string) string {
	return stringEscape(value)
}

// Pre-compiled regex for SanitizeID to avoid repeated compilation.
// This pattern matches any sequence of non-alphanumeric characters.
var sanitizeIDRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// escapeMarkdownReplacer performs all markdown escapes in a single pass.
//
//nolint:gochecknoglobals // Immutable replacer, avoids per-call allocation
var escapeMarkdownReplacer = strings.NewReplacer(
	"\\", "\\\\",
	"*", "\\*",
	"_", "\\_",
	"`", "\\`",
	"[", "\\[",
	"]", "\\]",
	"<", "\\<",
	">", "\\>",
	"|", "\\|",
	"\r\n", " ",
	"\n", " ",
	"\r", " ",
)

// EscapeTableContent escapes content for safe display in markdown tables.
// It applies the same escape set as [EscapeMarkdownValue] and exists as a
// separate name because most call sites are table cells, where the name
// documents the intent at the call site, and because it accepts any value
// rather than only a string.
//
// Two fast paths skip fmt.Sprintf("%v", ...) reflection boxing for
// string-kind inputs — the unnamed string path covers the common
// per-row formatter callers, and the reflect.Kind == String path
// covers named string types like FirewallRuleType, IPProtocol, and
// VIPMode that the markdown table builders also pass through. fmt
// machinery is pure overhead for both shapes; reflection is cheaper
// than fmt.Sprintf for the named-string case.
func EscapeTableContent(content any) string {
	if content == nil {
		return ""
	}

	if s, ok := content.(string); ok {
		return stringEscape(s)
	}

	if v := reflect.ValueOf(content); v.Kind() == reflect.String {
		return stringEscape(v.String())
	}

	return stringEscape(fmt.Sprintf("%v", content))
}

// TruncateDescription truncates a description to the specified maximum length,
// ensuring word boundaries are respected when possible.
func TruncateDescription(description string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}

	if len(description) <= maxLength {
		return description
	}

	truncated := description[:maxLength]
	lastSpace := strings.LastIndex(truncated, " ")

	if lastSpace > 0 && lastSpace > maxLength-20 {
		truncated = truncated[:lastSpace]
	}

	return truncated + "..."
}

// IsLastInSlice checks if the given index is the last element in a slice or array.
func IsLastInSlice(index int, slice any) bool {
	if slice == nil {
		return false
	}

	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return false
	}

	return index == rv.Len()-1
}

// DefaultValue returns the default value if the primary value is empty, otherwise returns the primary value.
func DefaultValue(value, defaultVal any) any {
	if IsEmpty(value) {
		return defaultVal
	}
	return value
}

// IsEmpty checks if a value is considered empty according to Go conventions.
func IsEmpty(value any) bool {
	if value == nil {
		return true
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.String:
		return rv.String() == ""
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() == 0
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.Pointer, reflect.Interface:
		return rv.IsNil()
	case reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}

// ToUpper converts a string to uppercase.
func ToUpper(s string) string {
	return strings.ToUpper(s)
}

// ToLower converts a string to lowercase.
func ToLower(s string) string {
	return strings.ToLower(s)
}

// TrimSpace removes leading and trailing whitespace from a string.
func TrimSpace(s string) string {
	return strings.TrimSpace(s)
}

// BoolToString converts a boolean value to a standardized string representation with emojis.
func BoolToString(val bool) string {
	if val {
		return "✅ Enabled"
	}
	return "❌ Disabled"
}

// FormatBytes formats a byte count as a human-readable string using binary prefixes (1024-based).
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// SanitizeID converts a string to a valid HTML/markdown anchor ID by removing
// or replacing invalid characters and converting to lowercase.
func SanitizeID(s string) string {
	sanitized := sanitizeIDRegex.ReplaceAllString(s, "-")
	sanitized = strings.ToLower(sanitized)

	sanitized = strings.Trim(sanitized, "-")

	if sanitized == "" {
		return "unnamed"
	}

	return sanitized
}
