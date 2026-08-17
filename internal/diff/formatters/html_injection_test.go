package formatters

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
)

// diffInjectionMarker brackets each payload so a failure points at the field
// that leaked rather than at "some HTML appeared somewhere".
const diffInjectionMarker = "OPNDOSSIERPROBE"

// diffForbiddenInHTML are substrings that must never appear in a generated HTML
// diff report, because each one means a value was parsed as markup instead of
// text. Each entry carries its opening angle bracket or attribute quoting so it
// matches only real markup: once escaping works the report contains
// "&lt;img src=x onerror=alert(1)&gt;" as visible text, and an event-handler
// substring on its own would match that harmless case too.
var diffForbiddenInHTML = []string{
	"<img src=x",
	"<script>",
	"<div onmouseover",
	`href="javascript:`,
}

// newInjectionResult builds a diff result whose value-carrying fields all hold
// payload.
//
// These are not arbitrary fields. Change.Description carries configuration text
// in practice: the network analyzer interpolates iface.Description into
// "Added interface: %s (%s)", and the firewall analyzer interpolates the rule
// description. OldValue and NewValue carry serialized configuration directly.
func newInjectionResult(payload string) *diff.Result {
	return &diff.Result{
		Summary: diff.Summary{Added: 1, Total: 1},
		Metadata: diff.Metadata{
			OldFile:     payload,
			NewFile:     payload,
			ToolVersion: "test",
		},
		Changes: []diff.Change{{
			Type:           diff.ChangeAdded,
			Section:        diff.SectionInterfaces,
			Path:           payload,
			Description:    "Added interface: opt1 (" + payload + ")",
			OldValue:       payload,
			NewValue:       payload,
			SecurityImpact: "medium",
		}},
	}
}

// TestDiffHTMLDoesNotExecuteConfigValues is the regression test for injection
// through the diff report.
//
// Both configurations passed to `diff` are untrusted input, and the HTML
// formatter renders its markdown with raw HTML passthrough enabled because it
// needs its own <details>/<summary> wrappers to survive. That makes escaping in
// the markdown formatter the only thing standing between a payload in an
// interface description and live markup in the report.
func TestDiffHTMLDoesNotExecuteConfigValues(t *testing.T) {
	payloads := []string{
		diffInjectionMarker + `<img src=x onerror=alert(1)>`,
		diffInjectionMarker + `<script>alert(2)</script>`,
		diffInjectionMarker + `<div onmouseover="alert(3)">hover</div>`,
		diffInjectionMarker + `[click](javascript:alert(4))`,
		diffInjectionMarker + "`backtick`break<img src=x onerror=alert(5)>",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			var buf bytes.Buffer

			if err := NewHTMLFormatter(&buf).Format(newInjectionResult(payload)); err != nil {
				t.Fatalf("format failed: %v", err)
			}

			out := buf.String()

			for _, forbidden := range diffForbiddenInHTML {
				if strings.Contains(out, forbidden) {
					t.Errorf("value rendered as live markup: report contains %q", forbidden)
				}
			}

			if !strings.Contains(out, diffInjectionMarker) {
				t.Error("value disappeared from the report instead of being escaped")
			}
		})
	}
}

// TestCodeSpanContainsBackticks covers the one way out of a code span. A value
// holding a backtick run as long as the fence would otherwise close the span
// early and let the rest parse as markdown.
func TestCodeSpanContainsBackticks(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain", input: "a/b", want: "`a/b`"},
		{name: "single backtick", input: "a`b", want: "``a`b``"},
		{name: "double backtick run", input: "a``b", want: "```a``b```"},
		{name: "leading backtick", input: "`a", want: "`` `a ``"},
		{name: "trailing backtick", input: "a`", want: "`` a` ``"},
		{name: "newline collapses", input: "a\nb", want: "`a b`"},
		{name: "crlf collapses", input: "a\r\nb", want: "`a b`"},
		{name: "empty", input: "", want: "``"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := codeSpan(tt.input); got != tt.want {
				t.Errorf("codeSpan(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
