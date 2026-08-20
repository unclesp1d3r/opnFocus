package processor

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestReportMarkdownIsLF covers the processor's own markdown exits, which build
// on github.com/nao1215/markdown independently of internal/converter/builder
// and so carried the same CRLF-on-Windows defect. ToMarkdown reaches users
// through Report.ToFormat and CoreProcessor.toMarkdown.
func TestReportMarkdownIsLF(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		System:     common.System{Hostname: "fw", Domain: "example.com"},
		Interfaces: []common.Interface{{Name: "lan", Enabled: true, IPAddress: "192.168.1.1", Subnet: "24"}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Description: "allow", Interfaces: []string{"lan"}},
		},
	}

	report := NewReport(device, Config{})

	formatted, err := report.ToFormat(OutputFormatMarkdown)
	if err != nil {
		t.Fatalf("ToFormat(markdown): %v", err)
	}

	outputs := map[string]string{
		"Report.ToMarkdown":         report.ToMarkdown(),
		"Report.Summary":            report.Summary(),
		"Report.ToFormat(markdown)": formatted,
	}

	for name, out := range outputs {
		if out == "" {
			t.Errorf("%s produced no output; the assertion below would be vacuous", name)

			continue
		}

		if strings.Contains(out, "\r") {
			t.Errorf("%s output contains CR; reports must be LF on every platform", name)
		}
	}
}
