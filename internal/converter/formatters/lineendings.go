package formatters

import "strings"

// NormalizeToLF converts CRLF and bare CR to LF.
//
// github.com/nao1215/markdown emits the host platform's line ending: its
// internal.LineFeed returns "\r\n" on Windows and "\n" everywhere else. Every
// place that takes a string out of a markdown.Markdown or its backing buffer
// has to pass it through here, or the same configuration yields byte-different
// reports per platform. That contradicts the guarantee stated in
// internal/export ("exports use LF line endings for deterministic
// cross-platform builds") and fails every LF golden fixture on a Windows
// checkout.
//
// Normalizing at the point of construction rather than in internal/export is
// deliberate: export only covers file writes, while reports also reach stdout,
// the terminal display path, and the goldmark HTML renderer. All of them need
// the same bytes.
//
// Operators who want CRLF on disk keep the existing opt-in,
// OPNDOSSIER_PLATFORM_LINE_ENDINGS=1, which internal/export applies at write
// time and which now has an LF input to convert rather than being a no-op on
// Windows.
func NormalizeToLF(s string) string {
	if !strings.ContainsRune(s, '\r') {
		return s
	}

	return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s)
}
