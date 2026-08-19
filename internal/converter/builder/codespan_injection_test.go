package builder_test

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// tableBreakPayload closes a single-backtick code span and follows with pipes.
// Once the span is closed early the pipes are table syntax again and the cell
// ends there. A value like this is what an operator would find in a
// config.xml handed to them by someone else.
const tableBreakPayload = "lan`|evil|col"

// markupPayload closes the span and follows with an HTML element.
const markupPayload = "lan`<img src=x onerror=alert(1)>`"

// TestTableValuesSurviveCodeSpanBreakout covers the code span escape in the
// table and list builders.
//
// Those builders used to wrap config-derived values in a single-backtick code
// span, some of them backslash-escaping the contents first. CommonMark does not
// process backslash escapes inside a code span, so a value containing a backtick
// closed the span early: the remainder became live table syntax, and the
// backslashes rendered literally. formatters.CodeSpan sizes the fence past the
// longest backtick run instead, which contains the value.
func TestTableValuesSurviveCodeSpanBreakout(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		System:     common.System{Hostname: "fw", Domain: "example.com"},
		Interfaces: []common.Interface{{
			Name:        tableBreakPayload,
			Description: markupPayload,
			IPAddress:   tableBreakPayload,
			Enabled:     true,
		}},
		IDS: &common.IDSConfig{
			Enabled:      true,
			Interfaces:   []string{tableBreakPayload},
			HomeNetworks: []string{markupPayload},
			MPMAlgo:      tableBreakPayload,
			Verbosity:    markupPayload,
		},
	}

	b := builder.NewMarkdownBuilder()

	network := b.BuildNetworkSection(device)
	if network == "" {
		t.Fatal("network section produced no output")
	}

	// goldmark splits a table row on pipes before inline parsing, so a pipe
	// inside a code span still ends the cell. With a fixed column count the
	// surplus cells are dropped rather than widening the row, which means the
	// failure is silent truncation: everything after the pipe disappears from
	// the report. Assert the value survives, not the cell count.
	networkHTML, err := converter.RenderMarkdownToHTML(network)
	if err != nil {
		t.Fatalf("RenderMarkdownToHTML(network): %v", err)
	}

	// Scope to the table. BuildNetworkSection also emits a per-interface details
	// block outside it, where the value survives regardless, so an unscoped
	// check would pass even with a truncating table cell.
	_, afterTable, found := strings.Cut(networkHTML, "<table>")
	if !found {
		t.Fatal("no table rendered in the network section")
	}

	table, _, _ := strings.Cut(afterTable, "</table>")

	if !strings.Contains(table, "evil|col") {
		t.Errorf("interface name was truncated at the pipe inside the table cell:\n  %s", table)
	}

	for name, md := range map[string]string{"network": network, "security": b.BuildSecuritySection(device)} {
		if md == "" {
			t.Fatalf("%s section produced no output", name)
		}

		html, err := converter.RenderMarkdownToHTML(md)
		if err != nil {
			t.Fatalf("%s: RenderMarkdownToHTML: %v", name, err)
		}

		// Defense in depth. Passthrough is off in htmlOutputRenderer, so this
		// also fails if someone re-enables it.
		if strings.Contains(html, "<img src=x") {
			t.Errorf("%s: payload became live markup in the HTML report", name)
		}

		// Backslashes leaking into output was the visible symptom of escaping a
		// value that then went inside a code span.
		if strings.Contains(html, "\\<") || strings.Contains(html, "\\|") {
			t.Errorf("%s: backslash escapes rendered literally inside a code span", name)
		}
	}
}
