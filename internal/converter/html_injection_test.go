package converter

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// injectionMarker brackets each payload so a test failure points at the exact
// field that leaked, rather than at "some HTML appeared somewhere".
const injectionMarker = "OPNDOSSIERPROBE"

// injectionPayloads are the markup shapes a config value could carry into a
// report. Each is a real vector rather than a generic "bad string": an image
// with an error handler, an inline script, an event handler that needs no
// external fetch, and a markdown link with a javascript URL, which goldmark
// turns into a live anchor without any raw HTML being involved at all.
var injectionPayloads = []string{
	injectionMarker + `<img src=x onerror=alert(1)>`,
	injectionMarker + `<script>alert(2)</script>`,
	injectionMarker + `<div onmouseover="alert(3)">hover</div>`,
	injectionMarker + `[click](javascript:alert(4))`,
}

// forbiddenInHTML are substrings that must never appear in a generated HTML
// report, because each one means a config value was parsed as markup instead of
// text.
//
// Each entry includes the opening angle bracket or the attribute quoting, so it
// matches only real markup. Once escaping works the report contains
// "&lt;img src=x onerror=alert(1)&gt;" as visible text, and an event-handler
// substring on its own would match that harmless case too.
var forbiddenInHTML = []string{
	"<img src=x",
	"<script>",
	"<div onmouseover",
	`href="javascript:`,
}

// newInjectionTestDevice returns a device whose config-derived string fields all
// carry payload. The fields chosen are the ones that reach the report through
// the non-table paths (bullet lists and PlainTextf lines) plus a representative
// set of table cells, which is where the escaping gap lived.
func newInjectionTestDevice(payload string) *common.CommonDevice {
	return &common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		System: common.System{
			Hostname:     payload,
			Domain:       payload,
			Optimization: payload,
			Timezone:     payload,
			Language:     payload,
			TimeServers:  []string{payload},
			DNSServers:   []string{payload},
			WebGUI:       common.WebGUI{Protocol: payload},
			Firmware:     common.Firmware{Version: payload},
			SSH:          common.SSH{Group: payload},
			Bogons:       common.Bogons{Interval: payload},
		},
		Interfaces: []common.Interface{{
			Name:        "lan",
			PhysicalIf:  payload,
			Description: payload,
			Enabled:     true,
			IPAddress:   payload,
			Subnet:      payload,
			IPv6Address: payload,
			SubnetV6:    payload,
			Gateway:     payload,
			MTU:         payload,
		}},
		FirewallRules: []common.FirewallRule{{
			Type:        common.RuleTypePass,
			Description: payload,
			Interfaces:  []string{"lan"},
			Protocol:    payload,
			Target:      payload,
			Source:      common.RuleEndpoint{Address: payload, Port: payload},
			Destination: common.RuleEndpoint{Address: payload, Port: payload},
		}},
		SNMP: common.SNMPConfig{
			SysLocation: payload,
			SysContact:  payload,
			ROCommunity: payload,
		},
		NTP: common.NTPConfig{PreferredServer: payload},
	}
}

// TestReportHTMLDoesNotExecuteConfigValues is the regression test for the
// report injection bug.
//
// A config.xml is untrusted input. It arrives from a customer firewall, an
// incident-response capture, or a backup of unknown provenance, and the whole
// point of the tool is to turn it into a report someone then opens. Before the
// fix, values such as the hostname were concatenated into markdown unescaped
// and the HTML renderer was configured to pass raw HTML through, so a payload
// in config.xml became live markup in report.html.
//
// The test asserts the outcome rather than the mechanism, so it keeps working
// if the escaping moves: no dangerous construct survives into the HTML, and the
// value is still visible in escaped form so the fix cannot be mistaken for
// silently dropping data.
func TestReportHTMLDoesNotExecuteConfigValues(t *testing.T) {
	t.Parallel()

	for _, payload := range injectionPayloads {
		t.Run(payload, func(t *testing.T) {
			t.Parallel()

			for _, comprehensive := range []bool{false, true} {
				device := newInjectionTestDevice(payload)
				opts := DefaultOptions().WithFormat(FormatHTML)
				opts.Comprehensive = comprehensive

				gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
				require.NoError(t, err)

				out, err := gen.Generate(context.Background(), device, opts)
				require.NoError(t, err)

				for _, forbidden := range forbiddenInHTML {
					assert.NotContains(t, out, forbidden,
						"comprehensive=%v: config value rendered as live markup", comprehensive)
				}

				assert.Contains(t, out, injectionMarker,
					"comprehensive=%v: config value disappeared instead of being escaped", comprehensive)
			}
		})
	}
}

// TestReportMarkdownEscapesConfigValues covers the markdown deliverable. HTML is
// where the security consequence lands, but an unescaped value also silently
// reformats the markdown report: a stray asterisk turns the rest of a line into
// emphasis, and a bare pipe splits a table row into extra columns.
func TestReportMarkdownEscapesConfigValues(t *testing.T) {
	t.Parallel()

	const payload = injectionMarker + `<b>*emph*|pipe|[link](x)`

	device := newInjectionTestDevice(payload)

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	out, err := gen.Generate(context.Background(), device, DefaultOptions().WithFormat(FormatMarkdown))
	require.NoError(t, err)

	require.Contains(t, out, injectionMarker, "payload should be present in the report")

	// Assert on the rendered result rather than on the markdown spelling. There
	// are two valid ways to contain a value: backslash-escape the
	// metacharacters, or put it in a correctly fenced code span, where the
	// characters are literal and must appear verbatim. Checking the markdown
	// text for "<b>" would fail the code span form even though it is inert, and
	// would say nothing about whether the escaping actually worked.
	rendered, err := RenderMarkdownToHTML(out)
	require.NoError(t, err)

	assert.NotContains(t, rendered, "<b>", "angle brackets became live markup")
	assert.NotContains(t, rendered, "<em>emph</em>", "asterisks were parsed as emphasis")
	assert.NotContains(t, rendered, `<a href="x"`, "brackets were parsed as a link")

	// Containment is only half of it. A value can also be silently truncated,
	// which is what an unescaped pipe does to a table cell, so require the whole
	// payload to survive somewhere in the output.
	assert.Contains(t, rendered, "pipe", "payload was truncated rather than escaped")
}
