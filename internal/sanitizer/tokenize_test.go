package sanitizer

import (
	"bytes"
	"strings"
	"testing"
)

// Unicode separators that unicode.IsSpace recognizes but RE2's \s does not.
const (
	noBreakSpace     = "\u00A0"
	figureSpace      = "\u2007"
	ideographicSpace = "\u3000"
	nextLine         = "\u0085"
)

// TestReplaceTokens_PreservesWhitespace pins the property the comment and
// CharData paths depend on: separators are copied verbatim, only tokens are
// handed to the callback.
func TestReplaceTokens_PreservesWhitespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"single token", "abc", "<abc>"},
		{"ascii spaces", "a b", "<a> <b>"},
		{"leading and trailing", "  a  ", "  <a>  "},
		{"newlines kept", "a\n\nb", "<a>\n\n<b>"},
		{"tabs kept", "a\tb", "<a>\t<b>"},
		{"no-break space", "a" + noBreakSpace + "b", "<a>" + noBreakSpace + "<b>"},
		{"ideographic space", "a" + ideographicSpace + "b", "<a>" + ideographicSpace + "<b>"},
		{"only whitespace", " \n ", " \n "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := replaceTokens(tt.in, func(tok string) string { return "<" + tok + ">" })
			if got != tt.want {
				t.Errorf("replaceTokens(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestSanitize_RedactsAcrossUnicodeSeparators guards a redaction bypass. The
// tokenizer was a regexp `\S+`, and RE2 defines \s as ASCII-only
// ([\t\n\f\r ]), so a secret separated from its neighbour by a no-break space
// reached the detectors as one glued token, failed every whole-token check and
// was emitted verbatim. unicode.IsSpace is what strings.Fields uses and what
// the separators below require.
func TestSanitize_RedactsAcrossUnicodeSeparators(t *testing.T) {
	t.Parallel()

	const secretIP = "10.0.0.5"

	separators := map[string]string{
		"ascii space":       " ",
		"no-break space":    noBreakSpace,
		"figure space":      figureSpace,
		"ideographic space": ideographicSpace,
		"next line":         nextLine,
	}

	for name, sep := range separators {
		t.Run("comment/"+name, func(t *testing.T) {
			t.Parallel()
			assertRedacted(t, "<o><!-- admin"+sep+secretIP+" --><a>x</a></o>", secretIP)
		})

		t.Run("chardata/"+name, func(t *testing.T) {
			t.Parallel()
			assertRedacted(t, "<o><descr>admin"+sep+secretIP+"</descr></o>", secretIP)
		})
	}
}

func assertRedacted(t *testing.T, doc, secret string) {
	t.Helper()

	s := NewSanitizer(ModeAggressive)

	var out bytes.Buffer
	if err := s.SanitizeXML(strings.NewReader(doc), &out); err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	if strings.Contains(out.String(), secret) {
		t.Errorf("secret %q survived sanitization: %s", secret, out.String())
	}
}
