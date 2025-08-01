package converter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/parser"
)

func TestMarkdownConverter_ToMarkdown(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	tests := []struct {
		name     string
		input    *model.OpnSenseDocument
		expected string
		wantErr  bool
	}{
		{
			name: "basic conversion",
			input: &model.OpnSenseDocument{
				Version: "1.2.3",
				System: model.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			expected: `OPNsense Configuration

  ## System

  Hostname: test-host Domain: test.local`,
			wantErr: false,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: "",
			wantErr:  true,
		},
		{
			name:     "empty struct",
			input:    &model.OpnSenseDocument{},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
		{
			name: "missing system fields",
			input: &model.OpnSenseDocument{
				System: model.System{},
			},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewMarkdownConverter()
			md, err := c.ToMarkdown(context.Background(), tt.input)

			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, md)
			} else {
				require.NoError(t, err)

				// With TERM=dumb, we get clean output without ANSI codes
				assert.Contains(t, md, "OPNsense Configuration")
				assert.Contains(t, md, "## System")

				if tt.input != nil && tt.input.System.Hostname != "" && tt.input.System.Domain != "" {
					// Check for hostname and domain separately to be more flexible
					assert.Contains(t, md, "**Hostname**: "+tt.input.System.Hostname)
					assert.Contains(t, md, "**Domain**: "+tt.input.System.Domain)
				}
			}
		})
	}
}

// TestMarkdownConverter_ConvertFromTestdataFile tests conversion of the complete testdata file.
func TestMarkdownConverter_ConvertFromTestdataFile(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")
	// Read the sample XML file
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.3.xml")
	xmlData, err := os.ReadFile(xmlPath)
	require.NoError(t, err, "Failed to read testdata XML file")

	// Parse the XML file using the parser
	p := parser.NewXMLParser()
	opnsense, err := p.Parse(context.Background(), strings.NewReader(string(xmlData)))
	require.NoError(t, err, "XML parsing should succeed")

	// Convert to markdown
	c := NewMarkdownConverter()
	markdown, err := c.ToMarkdown(context.Background(), opnsense)
	require.NoError(t, err, "Markdown conversion should succeed")

	// Verify the markdown is not empty
	assert.NotEmpty(t, markdown, "Markdown output should not be empty")

	// With TERM=dumb, we get clean output without ANSI codes
	// Verify main sections are present
	assert.Contains(t, markdown, "OPNsense Configuration")
	assert.Contains(t, markdown, "## System Configuration")
	assert.Contains(t, markdown, "## Network Configuration")
	assert.Contains(t, markdown, "## Security Configuration")
	assert.Contains(t, markdown, "## Service Configuration")

	// Verify system information
	assert.Contains(t, markdown, "**Hostname**: OPNsense")
	assert.Contains(t, markdown, "**Domain**: localdomain")
	assert.Contains(t, markdown, "**Optimization**:")
	assert.Contains(t, markdown, "normal")
	assert.Contains(t, markdown, "**Protocol**: https")

	// Verify network interfaces
	assert.Contains(t, markdown, "## WAN Interface")
	assert.Contains(t, markdown, "## LAN Interface")
	assert.Contains(t, markdown, "**Physical Interface**: mismatch1")
	assert.Contains(t, markdown, "**Physical Interface**: mismatch0")
	assert.Contains(t, markdown, "**IPv4 Address**: dhcp")
	assert.Contains(t, markdown, "192.168.1.1")

	// Verify security configuration
	assert.Contains(t, markdown, "NAT Configuration")
	assert.Contains(t, markdown, "**Outbound NAT Mode**: automatic")
	assert.Contains(t, markdown, "Firewall Rules")

	// Verify service configuration
	assert.Contains(t, markdown, "DHCP Server")
	assert.Contains(t, markdown, "DNS Resolver (Unbound)")
	assert.Contains(t, markdown, "SNMP")
	assert.Contains(t, markdown, "**Read-Only Community**: public")

	// Verify tables are rendered
	assert.Contains(t, markdown, "TUNABLE")
	assert.Contains(t, markdown, "VALUE")
	assert.Contains(t, markdown, "DESCRIPTION")

	// Verify users and groups tables
	assert.Contains(t, markdown, "Users")
	assert.Contains(t, markdown, "Groups")
	assert.Contains(t, markdown, "root")
	assert.Contains(t, markdown, "admins")

	// Verify firewall rules table
	assert.Contains(t, markdown, "TYPE")
	assert.Contains(t, markdown, "INT")
	assert.Contains(t, markdown, "PROTO")
	assert.Contains(t, markdown, "SOUR")
	assert.Contains(t, markdown, "DEST")

	// Verify load balancer monitors
	assert.Contains(t, markdown, "Load Balancer Monitors")
	assert.Contains(t, markdown, "ICMP")
	assert.Contains(t, markdown, "HTTP")
}

// TestMarkdownConverter_EdgeCases tests edge cases and error conditions.
func TestMarkdownConverter_EdgeCases(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	c := NewMarkdownConverter()

	t.Run("nil opnsense struct", func(t *testing.T) {
		md, err := c.ToMarkdown(context.Background(), nil)
		require.Error(t, err)
		assert.Equal(t, ErrNilOpnSenseDocument, err)
		assert.Empty(t, md)
	})

	t.Run("empty opnsense struct", func(t *testing.T) {
		md, err := c.ToMarkdown(context.Background(), &model.OpnSenseDocument{})
		require.NoError(t, err)
		assert.NotEmpty(t, md)
		assert.Contains(t, md, "OPNsense Configuration")
	})

	t.Run("opnsense with only system configuration", func(t *testing.T) {
		opnsense := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "test-host",
				Domain:   "test.local",
				WebGUI:   model.WebGUIConfig{Protocol: "http"},
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
				}{Interval: "monthly"},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "**Hostname**: test-host")
		assert.Contains(t, md, "**Domain**: test.local")
		assert.Contains(t, md, "**Protocol**: http")
	})

	t.Run("opnsense with complex sysctl configuration", func(t *testing.T) {
		opnsense := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "sysctl-test",
				Domain:   "test.local",
			},
			Sysctl: []model.SysctlItem{
				{
					Tunable: "net.inet.ip.forwarding",
					Value:   "1",
					Descr:   "Enable IP forwarding",
				},
				{
					Tunable: "kern.ipc.somaxconn",
					Value:   "1024",
					Descr:   "Maximum socket connections",
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "System Tuning")
		assert.Contains(t, md, "net.inet.ip.forwarding")
		assert.Contains(t, md, "kern.ipc.somaxconn")
		assert.Contains(t, md, "Enable IP forwarding")
		assert.Contains(t, md, "Maximum socket connections")
	})

	t.Run("opnsense with users and groups", func(t *testing.T) {
		opnsense := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "user-test",
				Domain:   "test.local",
				User: []model.User{
					{
						Name:      "admin",
						Descr:     "Administrator",
						Groupname: "wheel",
						Scope:     "system",
					},
				},
				Group: []model.Group{
					{
						Name:        "wheel",
						Description: "Wheel Group",
						Scope:       "system",
					},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "Users")
		assert.Contains(t, md, "Groups")
		assert.Contains(t, md, "admin")
		assert.Contains(t, md, "wheel")
		assert.Contains(t, md, "Administrator")
		assert.Contains(t, md, "Wheel Group")
	})

	t.Run("opnsense with multiple firewall rules", func(t *testing.T) {
		opnsense := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "firewall-test",
				Domain:   "test.local",
			},
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						Interface:  "lan",
						IPProtocol: "inet",
						Descr:      "Allow LAN",
						Source:     model.Source{Network: "lan"},
					},
					{
						Type:       "block",
						Interface:  "wan",
						IPProtocol: "inet",
						Descr:      "Block external",
						Source:     model.Source{Network: "any"},
					},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "Firewall Rules")
		assert.Contains(t, md, "Allow LAN")
		assert.Contains(t, md, "Block external")
		assert.Contains(t, md, "pass")
		assert.Contains(t, md, "block")
	})

	t.Run("opnsense with load balancer monitors", func(t *testing.T) {
		opnsense := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "lb-test",
				Domain:   "test.local",
			},
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{
					{
						Name:  "TCP-80",
						Type:  "tcp",
						Descr: "TCP port 80 check",
					},
					{
						Name:  "HTTPS-443",
						Type:  "https",
						Descr: "HTTPS health check",
					},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "Load Balancer Monitors")
		assert.Contains(t, md, "TCP-80")
		assert.Contains(t, md, "HTTPS-443")
		assert.Contains(t, md, "TCP port 80 check")
		assert.Contains(t, md, "HTTPS health check")
	})
}

// TestMarkdownConverter_ThemeSelection tests theme selection logic.
func TestMarkdownConverter_ThemeSelection(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	c := NewMarkdownConverter()

	t.Run("default theme selection", func(t *testing.T) {
		// Test the getTheme method indirectly through ToMarkdown
		opnsense := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "theme-test",
				Domain:   "test.local",
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		require.NoError(t, err)
		assert.NotEmpty(t, md)
		// The markdown should be rendered without error regardless of theme
		assert.Contains(t, md, "OPNsense Configuration")
	})
}

// TestNewMarkdownConverter tests the constructor.
func TestNewMarkdownConverter(t *testing.T) {
	c := NewMarkdownConverter()
	assert.NotNil(t, c)
	assert.IsType(t, &MarkdownConverter{}, c)
}
