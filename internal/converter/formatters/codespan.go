package formatters

import "strings"

// codeSpanChars are the characters that make wrapping non-trivial: a backtick
// changes the fence width and a line break has to be collapsed. A pipe is not
// listed because [CodeSpanCell] escapes pipes after the fence is built, on the
// wrapped result rather than on the raw value.
const codeSpanChars = "`\r\n"

// newlineCollapser flattens a value onto one line. A raw newline would end the
// table row or list item holding the span.
//
//nolint:gochecknoglobals // Immutable replacer, avoids per-call allocation
var newlineCollapser = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

// CodeSpan wraps value in a markdown code span sized to its contents, and is the
// only safe way to render a configuration value inside backticks.
//
// Code span contents are literal and goldmark HTML-escapes them on render, which
// is what makes this safe for untrusted input. Backslash escaping is wrong here:
// CommonMark does not process backslash escapes inside a code span, so
// [EscapeTableContent] applied to a value that is then wrapped in backticks both
// fails to contain the value and leaves the backslashes visible in the output.
//
// The one way out of a code span is a backtick run matching the fence, which
// CommonMark resolves by allowing a longer fence, so the fence is sized to one
// more than the longest run in the value. A value starting or ending with a
// backtick also needs the padding spaces CommonMark strips back off when reading
// the span. Newlines are collapsed because a code span cannot span lines and a
// raw newline would break the enclosing table row or list item.
func CodeSpan(value string) string {
	// A fence with nothing between its halves is an unclosed opening delimiter,
	// not an empty span: it renders as two literal backtick characters. An empty
	// value therefore yields nothing at all.
	if value == "" {
		return ""
	}

	// Same reasoning as stringEscape's guard: this runs once per config-derived
	// field, the replacer allocates whether or not it matches, and nearly every
	// real value is a name or an address containing none of these. Wrapping is
	// exactly equivalent to the general path when none are present.
	if !strings.ContainsAny(value, codeSpanChars) {
		return "`" + value + "`"
	}

	value = newlineCollapser.Replace(value)

	longest, current := 0, 0

	for _, r := range value {
		if r != '`' {
			current = 0

			continue
		}

		current++
		if current > longest {
			longest = current
		}
	}

	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") {
		return fence + " " + value + " " + fence
	}

	return fence + value + fence
}

// CodeSpanCell is [CodeSpan] for a value going into a GFM table cell.
//
// A code span alone is not enough inside a table. GFM splits a row on unescaped
// pipes before it does any inline parsing, so a pipe in the value ends the cell
// no matter what inline construct encloses it. The escape GFM does honor at that
// stage is a backslashed pipe, which it consumes during the split and hands to
// the inline parser as a literal.
//
// Pipes are escaped after the fence is measured, since escaping cannot change
// the backtick runs the fence is sized against.
func CodeSpanCell(value string) string {
	return strings.ReplaceAll(CodeSpan(value), "|", "\\|")
}
