package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestIsAnyAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want bool
	}{
		// The converters normalize <any/>, <any>1</any> and
		// <network>any</network> to this literal.
		{"any literal", "any", true},
		// Vendor XML is not case-normalized.
		{"uppercase", "ANY", true},
		{"mixed case", "Any", true},
		// An omitted or empty <source>/<destination> element matches every
		// host: a rule with no source matches every source.
		{"empty", "", true},
		{"whitespace only", "   ", true},
		// Wildcard CIDRs are what automation and hand-edited configs write.
		{"ipv4 wildcard", "0.0.0.0/0", true},
		{"ipv6 wildcard", "::/0", true},
		// Specific addresses must not be swept up.
		{"host", "192.168.1.1", false},
		{"subnet", "192.168.1.0/24", false},
		{"large but bounded subnet", "10.0.0.0/8", false},
		{"single host cidr", "0.0.0.0/32", false},
		{"hostname", "fw.example.com", false},
		{"alias name", "MgmtHosts", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.IsAnyAddress(tt.addr))
		})
	}
}

func TestIsAnyPort(t *testing.T) {
	t.Parallel()

	assert.True(t, analysis.IsAnyPort(""))
	assert.True(t, analysis.IsAnyPort("any"))
	assert.True(t, analysis.IsAnyPort("ANY"))
	assert.False(t, analysis.IsAnyPort("443"))
	assert.False(t, analysis.IsAnyPort("8000-9000"))
	assert.False(t, analysis.IsAnyPort("MgmtPorts"))
}

func TestIsAnyProtocol(t *testing.T) {
	t.Parallel()

	assert.True(t, analysis.IsAnyProtocol(""))
	assert.True(t, analysis.IsAnyProtocol("   "))
	assert.True(t, analysis.IsAnyProtocol("any"))
	assert.True(t, analysis.IsAnyProtocol("ANY"))
	assert.False(t, analysis.IsAnyProtocol("tcp"))
	assert.False(t, analysis.IsAnyProtocol("udp"))
	assert.False(t, analysis.IsAnyProtocol("icmp"))
}

// TestIsWideOpenPassRule_AllAnySpellings guards the false negatives that
// motivated IsAnyAddress: a pass rule matching all traffic must be recognized
// however the config spells "any", not only as the literal the converters
// normalize <any/> to.
func TestIsWideOpenPassRule_AllAnySpellings(t *testing.T) {
	t.Parallel()

	spellings := []string{"any", "ANY", "", "   ", "0.0.0.0/0", "::/0"}
	for _, s := range spellings {
		t.Run("addr="+s, func(t *testing.T) {
			t.Parallel()

			rule := common.FirewallRule{
				Type:        common.RuleTypePass,
				Source:      common.RuleEndpoint{Address: s},
				Destination: common.RuleEndpoint{Address: s},
			}
			assert.True(t, analysis.IsWideOpenPassRule(rule),
				"a pass rule with source and destination %q matches all traffic", s)
		})
	}
}

func TestIsWideOpenPassRule_NotWideOpen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule common.FirewallRule
	}{
		{"disabled", common.FirewallRule{
			Type: common.RuleTypePass, Disabled: true,
			Source: common.RuleEndpoint{Address: "any"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
		{"block rule", common.FirewallRule{
			Type:   common.RuleTypeBlock,
			Source: common.RuleEndpoint{Address: "any"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
		{"scoped source", common.FirewallRule{
			Type:   common.RuleTypePass,
			Source: common.RuleEndpoint{Address: "198.51.100.0/24"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
		{"scoped destination port", common.FirewallRule{
			Type:        common.RuleTypePass,
			Source:      common.RuleEndpoint{Address: "any"},
			Destination: common.RuleEndpoint{Address: "any", Port: "443"},
		}},
		{"specific protocol", common.FirewallRule{
			Type:     common.RuleTypePass,
			Protocol: "tcp",
			Source:   common.RuleEndpoint{Address: "any"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.False(t, analysis.IsWideOpenPassRule(tt.rule))
		})
	}
}
