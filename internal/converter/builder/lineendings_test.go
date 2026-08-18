package builder

import (
	"bytes"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestReportOutputIsLF is the regression test for platform-dependent line
// endings in generated reports.
//
// github.com/nao1215/markdown emits the host's line ending, so on Windows every
// report contained CRLF. That made the same configuration produce byte-different
// output per platform, contradicted the LF guarantee documented in
// internal/export, and failed every golden fixture on a Windows checkout.
//
// The assertion is on the builder's public output surface rather than on one
// function, so a report method added later that forgets renderMarkdown fails
// here. It can only fail on Windows, which is why the Windows CI job runs the
// full suite rather than a smoke subset.
func TestReportOutputIsLF(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		System:     common.System{Hostname: "fw", Domain: "example.com"},
		Interfaces: []common.Interface{{Name: "lan", Enabled: true, IPAddress: "192.168.1.1", Subnet: "24"}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Description: "allow", Interfaces: []string{"lan"}},
		},
		// BuildAuditSection returns "" without this, which would make its
		// entry below vacuous rather than a real assertion.
		ComplianceResults: &common.ComplianceResults{Mode: "blue"},
		// The tunables blocks in writer.go are guarded by len(filteredSysctl) > 0,
		// so without a tunable the streaming paths skip them entirely and a raw
		// md.String() there would go unnoticed. FilterSystemTunables drops
		// anything outside securitySysctlPrefixes when includeTunables is false,
		// so this has to be a security-prefixed name to survive.
		Sysctl: []common.SysctlItem{
			{Tunable: "net.inet.tcp.blackhole", Value: "2", Description: "TCP stealth drop"},
		},
		// Same reason: writeIDSSection returns early unless IDS is enabled, so
		// BuildIDSSection yields "" and its exit goes unexercised without this.
		IDS: &common.IDSConfig{Enabled: true, IPSMode: true, Interfaces: []string{"lan"}},
	}

	b := NewMarkdownBuilder()

	standard, err := b.BuildStandardReport(device)
	if err != nil {
		t.Fatalf("BuildStandardReport: %v", err)
	}

	comprehensive, err := b.BuildComprehensiveReport(device)
	if err != nil {
		t.Fatalf("BuildComprehensiveReport: %v", err)
	}

	var streamedStandard bytes.Buffer
	if err := b.WriteStandardReport(&streamedStandard, device); err != nil {
		t.Fatalf("WriteStandardReport: %v", err)
	}

	var streamedComprehensive bytes.Buffer
	if err := b.WriteComprehensiveReport(&streamedComprehensive, device); err != nil {
		t.Fatalf("WriteComprehensiveReport: %v", err)
	}

	outputs := map[string]string{
		"BuildStandardReport":      standard,
		"BuildComprehensiveReport": comprehensive,
		"WriteStandardReport":      streamedStandard.String(),
		"WriteComprehensiveReport": streamedComprehensive.String(),
		"BuildSystemSection":       b.BuildSystemSection(device),
		"BuildNetworkSection":      b.BuildNetworkSection(device),
		"BuildSecuritySection":     b.BuildSecuritySection(device),
		"BuildServicesSection":     b.BuildServicesSection(device),
		"BuildAuditSection":        b.BuildAuditSection(device),
		"BuildIDSSection":          b.BuildIDSSection(device),
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
