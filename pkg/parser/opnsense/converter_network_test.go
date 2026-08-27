package opnsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_Bridges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		bridges []schema.Bridge
		wantLen int
	}{
		{
			name:    "empty bridges returns nil",
			bridges: nil,
			wantLen: 0,
		},
		{
			name: "single bridge with STP",
			bridges: []schema.Bridge{
				{
					Bridgeif: "bridge0",
					Members:  "opt1,opt2",
					Descr:    "LAN Bridge",
					STP:      true,
					Created:  "2024-01-01",
					Updated:  "2024-06-15",
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple bridges",
			bridges: []schema.Bridge{
				{Bridgeif: "bridge0", Members: "opt1,opt2", Descr: "Internal"},
				{Bridgeif: "bridge1", Members: "opt3", Descr: "DMZ"},
			},
			wantLen: 2,
		},
		{
			name:    "empty bridged placeholder is skipped",
			bridges: []schema.Bridge{{}},
			wantLen: 0,
		},
		{
			name: "placeholder alongside a real bridge keeps only the real one",
			bridges: []schema.Bridge{
				{},
				{Bridgeif: "bridge0", Members: "opt1,opt2", Descr: "Internal"},
			},
			wantLen: 1,
		},
		{
			name:    "bridge carrying only a description is retained",
			bridges: []schema.Bridge{{Descr: "staged bridge"}},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.Bridges.Bridge = tt.bridges

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.Bridges)
				return
			}
			require.Len(t, device.Bridges, tt.wantLen)
		})
	}
}

func TestConverter_Bridges_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Bridges.Bridge = []schema.Bridge{
		{
			Bridgeif: "bridge0",
			Members:  "opt1,opt2,opt3",
			Descr:    "LAN Bridge",
			STP:      true,
			Created:  "2024-01-01",
			Updated:  "2024-06-15",
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.Bridges, 1)

	b := device.Bridges[0]
	assert.Equal(t, "bridge0", b.BridgeIf)
	assert.Equal(t, []string{"opt1", "opt2", "opt3"}, b.Members)
	assert.Equal(t, "LAN Bridge", b.Description)
	assert.True(t, b.STP)
	assert.Equal(t, "2024-01-01", b.Created)
	assert.Equal(t, "2024-06-15", b.Updated)
}

func TestConverter_Bridges_EmptyMembers(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Bridges.Bridge = []schema.Bridge{
		{Bridgeif: "bridge0", Members: ""},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.Bridges, 1)
	assert.Nil(t, device.Bridges[0].Members)
}

func TestConverter_PPPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ppps    []schema.PPP
		wantLen int
	}{
		{
			name:    "empty PPPs returns nil",
			ppps:    nil,
			wantLen: 0,
		},
		{
			name: "single PPPoE",
			ppps: []schema.PPP{
				{If: "pppoe0", Type: "pppoe", Descr: "WAN PPPoE"},
			},
			wantLen: 1,
		},
		{
			name: "mixed PPP types",
			ppps: []schema.PPP{
				{If: "pppoe0", Type: "pppoe", Descr: "WAN"},
				{If: "pptp0", Type: "pptp", Descr: "VPN"},
				{If: "l2tp0", Type: "l2tp", Descr: "Remote"},
			},
			wantLen: 3,
		},
		{
			// OPNsense writes this placeholder when no PPP link is configured.
			name:    "empty ppp placeholder is skipped",
			ppps:    []schema.PPP{{}},
			wantLen: 0,
		},
		{
			name:    "description-only ppp is retained",
			ppps:    []schema.PPP{{Descr: "backup link"}},
			wantLen: 1,
		},
		{
			name:    "placeholder alongside a real ppp yields only the real one",
			ppps:    []schema.PPP{{}, {If: "pppoe0", Type: "pppoe", Descr: "WAN"}},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.PPPInterfaces.Ppp = tt.ppps

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.PPPs)
				return
			}
			require.Len(t, device.PPPs, tt.wantLen)
		})
	}
}

func TestConverter_PPPs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.PPPInterfaces.Ppp = []schema.PPP{
		{If: "pppoe0", Type: "pppoe", Descr: "ISP Connection"},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.PPPs, 1)

	p := device.PPPs[0]
	assert.Equal(t, "pppoe0", p.Interface)
	assert.Equal(t, "pppoe", p.Type)
	assert.Equal(t, "ISP Connection", p.Description)
}

func TestConverter_GIFs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		gifs    []schema.GIF
		wantLen int
	}{
		{
			name:    "empty GIFs returns nil",
			gifs:    nil,
			wantLen: 0,
		},
		{
			name: "single GIF tunnel",
			gifs: []schema.GIF{
				{
					Gifif:   "gif0",
					If:      "wan",
					Remote:  "209.51.181.2",
					Descr:   "HE IPv6 Tunnel",
					Created: "2024-03-01",
					Updated: "2024-03-15",
				},
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.GIFInterfaces.Gif = tt.gifs

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.GIFs)
				return
			}
			require.Len(t, device.GIFs, tt.wantLen)
		})
	}
}

//nolint:dupl // tunnel field-mapping tests (GIF/GRE) are structurally similar by design
func TestConverter_GIFs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.GIFInterfaces.Gif = []schema.GIF{
		{
			Gifif:   "gif0",
			If:      "wan",
			Remote:  "209.51.181.2",
			Descr:   "HE IPv6 Tunnel",
			Created: "2024-03-01",
			Updated: "2024-03-15",
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.GIFs, 1)

	g := device.GIFs[0]
	assert.Equal(t, "gif0", g.Interface)
	assert.Equal(t, "wan", g.Local)
	assert.Equal(t, "209.51.181.2", g.Remote)
	assert.Equal(t, "HE IPv6 Tunnel", g.Description)
	assert.Equal(t, "2024-03-01", g.Created)
	assert.Equal(t, "2024-03-15", g.Updated)
}

func TestConverter_GREs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		gres    []schema.GRE
		wantLen int
	}{
		{
			name:    "empty GREs returns nil",
			gres:    nil,
			wantLen: 0,
		},
		{
			name: "single GRE tunnel",
			gres: []schema.GRE{
				{
					Greif:   "gre0",
					If:      "wan",
					Remote:  "198.51.100.1",
					Descr:   "Datacenter GRE",
					Created: "2024-02-01",
					Updated: "2024-02-10",
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple GRE tunnels",
			gres: []schema.GRE{
				{Greif: "gre0", If: "wan", Remote: "198.51.100.1", Descr: "DC1"},
				{Greif: "gre1", If: "opt1", Remote: "198.51.100.2", Descr: "DC2"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.GREInterfaces.Gre = tt.gres

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.GREs)
				return
			}
			require.Len(t, device.GREs, tt.wantLen)
		})
	}
}

//nolint:dupl // tunnel field-mapping tests (GIF/GRE) are structurally similar by design
func TestConverter_GREs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.GREInterfaces.Gre = []schema.GRE{
		{
			Greif:   "gre0",
			If:      "wan",
			Remote:  "198.51.100.1",
			Descr:   "Datacenter GRE",
			Created: "2024-02-01",
			Updated: "2024-02-10",
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.GREs, 1)

	g := device.GREs[0]
	assert.Equal(t, "gre0", g.Interface)
	assert.Equal(t, "wan", g.Local)
	assert.Equal(t, "198.51.100.1", g.Remote)
	assert.Equal(t, "Datacenter GRE", g.Description)
	assert.Equal(t, "2024-02-01", g.Created)
	assert.Equal(t, "2024-02-10", g.Updated)
}

func TestConverter_LAGGs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		laggs   []schema.LAGG
		wantLen int
	}{
		{
			name:    "empty LAGGs returns nil",
			laggs:   nil,
			wantLen: 0,
		},
		{
			name: "single LACP bond",
			laggs: []schema.LAGG{
				{
					Laggif:  "lagg0",
					Members: "ix0,ix1",
					Proto:   "lacp",
					Descr:   "LAN LACP Bond",
					Created: "2024-01-15",
					Updated: "2024-01-20",
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple LAGG protocols",
			laggs: []schema.LAGG{
				{Laggif: "lagg0", Members: "ix0,ix1", Proto: "lacp", Descr: "LACP"},
				{Laggif: "lagg1", Members: "ix2,ix3", Proto: "failover", Descr: "Failover"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.LAGGInterfaces.Lagg = tt.laggs

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.LAGGs)
				return
			}
			require.Len(t, device.LAGGs, tt.wantLen)
		})
	}
}

func TestConverter_LAGGs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.LAGGInterfaces.Lagg = []schema.LAGG{
		{
			Laggif:  "lagg0",
			Members: "ix0,ix1,ix2",
			Proto:   "lacp",
			Descr:   "Server Bond",
			Created: "2024-01-15",
			Updated: "2024-01-20",
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.LAGGs, 1)

	l := device.LAGGs[0]
	assert.Equal(t, "lagg0", l.Interface)
	assert.Equal(t, []string{"ix0", "ix1", "ix2"}, l.Members)
	assert.Equal(t, common.LAGGProtocolLACP, l.Protocol)
	assert.Equal(t, "Server Bond", l.Description)
	assert.Equal(t, "2024-01-15", l.Created)
	assert.Equal(t, "2024-01-20", l.Updated)
}

func TestConverter_VirtualIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		vips    []schema.VIP
		wantLen int
	}{
		{
			name:    "empty VIPs returns nil",
			vips:    nil,
			wantLen: 0,
		},
		{
			name: "mixed VIP modes",
			vips: []schema.VIP{
				{Mode: "carp", Interface: "wan", Subnet: "203.0.113.100", Descr: "WAN CARP"},
				{Mode: "ipalias", Interface: "lan", Subnet: "192.168.1.200", Descr: "LAN Alias"},
				{Mode: "proxyarp", Interface: "wan", Subnet: "203.0.113.64", Descr: "Proxy ARP"},
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.VirtualIP.Vip = tt.vips

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.VirtualIPs)
				return
			}
			require.Len(t, device.VirtualIPs, tt.wantLen)
		})
	}
}

func TestConverter_VirtualIPs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.VirtualIP.Vip = []schema.VIP{
		{Mode: "carp", Interface: "wan", Subnet: "203.0.113.100", Descr: "WAN CARP VIP"},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.VirtualIPs, 1)

	v := device.VirtualIPs[0]
	assert.Equal(t, common.VIPModeCarp, v.Mode)
	assert.Equal(t, "wan", v.Interface)
	assert.Equal(t, "203.0.113.100", v.Subnet)
	assert.Equal(t, "WAN CARP VIP", v.Description)
}

func TestConverter_InterfaceGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		groups  []schema.IfGroupEntry
		wantLen int
	}{
		{
			name:    "empty groups returns nil",
			groups:  nil,
			wantLen: 0,
		},
		{
			name: "single group with multiple members",
			groups: []schema.IfGroupEntry{
				{IfName: "INTERNAL", Members: "lan opt1 opt2"},
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.InterfaceGroups.IfGroupEntry = tt.groups

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.InterfaceGroups)
				return
			}
			require.Len(t, device.InterfaceGroups, tt.wantLen)
		})
	}
}

func TestConverter_InterfaceGroups_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.InterfaceGroups.IfGroupEntry = []schema.IfGroupEntry{
		{IfName: "INTERNAL", Members: "lan opt1 opt2"},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.InterfaceGroups, 1)

	ig := device.InterfaceGroups[0]
	assert.Equal(t, "INTERNAL", ig.Name)
	assert.Equal(t, []string{"lan", "opt1", "opt2"}, ig.Members)
}

func TestConverter_InterfaceGroups_SpaceSeparated(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.InterfaceGroups.IfGroupEntry = []schema.IfGroupEntry{
		{IfName: "GROUP1", Members: "  lan   opt1  "},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.InterfaceGroups, 1)

	// splitNonEmpty trims whitespace from each part
	assert.Equal(t, []string{"lan", "opt1"}, device.InterfaceGroups[0].Members)
}

// TestConverter_Bridges_EndToEnd_PlaceholderNotCounted drives real config.xml content
// through the full parse -> convert -> statistics path. The <bridged> tag fix in
// pkg/schema/opnsense made this path reachable for the first time, so the
// end-to-end bridge count is asserted here rather than only at the schema layer.
func TestConverter_Bridges_EndToEnd_PlaceholderNotCounted(t *testing.T) {
	t.Parallel()

	const configTemplate = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <bridges>%s</bridges>
</opnsense>`

	tests := []struct {
		name         string
		bridgesInner string
		wantBridges  int
		wantBridgeIf string
	}{
		{
			// OPNsense writes this placeholder when no bridge is configured.
			name:         "empty bridged placeholder reports zero bridges",
			bridgesInner: `<bridged/>`,
			wantBridges:  0,
		},
		{
			name:         "populated bridged element is counted",
			bridgesInner: `<bridged><bridgeif>bridge0</bridgeif><members>opt1,opt2</members></bridged>`,
			wantBridges:  1,
			wantBridgeIf: "bridge0",
		},
	}

	factory := parser.NewFactory(cfgparser.NewXMLParser())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlBody := strings.Replace(configTemplate, "%s", tt.bridgesInner, 1)
			device, _, err := factory.CreateDevice(
				context.Background(),
				strings.NewReader(xmlBody),
				common.DeviceTypeUnknown,
				false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Len(t, device.Bridges, tt.wantBridges)

			stats := analysis.ComputeStatistics(device)
			assert.Equal(t, tt.wantBridges, stats.TotalBridges,
				"TotalBridges must not count empty <bridged/> placeholders")

			if tt.wantBridgeIf != "" {
				require.Len(t, device.Bridges, 1)
				assert.Equal(t, tt.wantBridgeIf, device.Bridges[0].BridgeIf)
			}
		})
	}
}

// TestConverter_PPPs_EndToEnd_PlaceholderNotCounted drives real config.xml
// content through the full parse -> convert path. The existing table tests build
// schema.PPP values directly in Go and so never exercise the XML path, which is
// how the empty-<ppp/> placeholder reached CommonDevice unnoticed.
func TestConverter_PPPs_EndToEnd_PlaceholderNotCounted(t *testing.T) {
	t.Parallel()

	const configTemplate = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <ppps>%s</ppps>
</opnsense>`

	tests := []struct {
		name          string
		pppsInner     string
		wantPPPs      int
		wantInterface string
	}{
		{
			// OPNsense writes this placeholder when no PPP link is configured.
			name:      "empty ppp placeholder reports zero PPPs",
			pppsInner: `<ppp/>`,
			wantPPPs:  0,
		},
		{
			name:          "populated ppp element is counted",
			pppsInner:     `<ppp><if>pppoe0</if><type>pppoe</type><descr>WAN</descr></ppp>`,
			wantPPPs:      1,
			wantInterface: "pppoe0",
		},
		{
			// A per-item filter must drop only the placeholder, never a sibling.
			name:          "placeholder alongside a real ppp yields only the real one",
			pppsInner:     `<ppp/><ppp><if>pppoe0</if><type>pppoe</type><descr>WAN</descr></ppp>`,
			wantPPPs:      1,
			wantInterface: "pppoe0",
		},
	}

	factory := parser.NewFactory(cfgparser.NewXMLParser())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlBody := strings.Replace(configTemplate, "%s", tt.pppsInner, 1)
			device, _, err := factory.CreateDevice(
				context.Background(),
				strings.NewReader(xmlBody),
				common.DeviceTypeUnknown,
				false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Len(t, device.PPPs, tt.wantPPPs,
				"PPPs must not include empty <ppp/> placeholders")

			if tt.wantInterface != "" {
				require.Len(t, device.PPPs, 1)
				assert.Equal(t, tt.wantInterface, device.PPPs[0].Interface)
			}
		})
	}
}

// TestConverter_StaticRoutes_EndToEnd_PlaceholderNotCounted drives real
// config.xml content through the full parse -> convert path and asserts the
// consumer that makes this bug user-visible: HasRoutes reports whether the
// device has routing configuration, and a phantom route flips an empty routing
// section to populated. The fixture carries no <gateways> because HasRoutes ORs
// static routes with gateways and gateway groups.
func TestConverter_StaticRoutes_EndToEnd_PlaceholderNotCounted(t *testing.T) {
	t.Parallel()

	const configTemplate = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <staticroutes>%s</staticroutes>
</opnsense>`

	tests := []struct {
		name          string
		routesInner   string
		wantRoutes    int
		wantHasRoutes bool
		wantNetwork   string
	}{
		{
			// OPNsense writes this placeholder when no route is configured.
			name:          "empty route placeholder reports zero routes",
			routesInner:   `<route/>`,
			wantRoutes:    0,
			wantHasRoutes: false,
		},
		{
			name:          "populated route element is counted",
			routesInner:   `<route><network>10.0.0.0/8</network><gateway>WAN_GW</gateway><descr>branch</descr></route>`,
			wantRoutes:    1,
			wantHasRoutes: true,
			wantNetwork:   "10.0.0.0/8",
		},
		{
			// A per-item filter must drop only the placeholder, never a sibling.
			name:          "placeholder alongside a real route yields only the real one",
			routesInner:   `<route/><route><network>10.0.0.0/8</network><gateway>WAN_GW</gateway></route>`,
			wantRoutes:    1,
			wantHasRoutes: true,
			wantNetwork:   "10.0.0.0/8",
		},
		{
			// Disabled is the one guarded field with non-trivial unmarshal
			// semantics (BoolFlag: a self-closing tag decodes to true), so it is
			// driven through real XML rather than built as a struct.
			name:          "route carrying only a self-closing disabled marker is retained",
			routesInner:   `<route><disabled/></route>`,
			wantRoutes:    1,
			wantHasRoutes: true,
		},
	}

	factory := parser.NewFactory(cfgparser.NewXMLParser())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlBody := strings.Replace(configTemplate, "%s", tt.routesInner, 1)
			device, _, err := factory.CreateDevice(
				context.Background(),
				strings.NewReader(xmlBody),
				common.DeviceTypeUnknown,
				false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Len(t, device.Routing.StaticRoutes, tt.wantRoutes,
				"StaticRoutes must not include empty <route/> placeholders")
			assert.Equal(t, tt.wantHasRoutes, device.HasRoutes(),
				"HasRoutes must not be flipped true by an empty <route/> placeholder")

			if tt.wantNetwork != "" {
				require.Len(t, device.Routing.StaticRoutes, 1)
				assert.Equal(t, tt.wantNetwork, device.Routing.StaticRoutes[0].Network)
			}
		})
	}
}

// TestConverter_AllPlaceholderContainers_EndToEnd_ProduceNoEntries drives a
// config carrying the empty placeholder for every guarded container through the
// full parse -> convert path at once.
//
// testdata/opnsense-config.dtd declares each of these elements EMPTY, and
// testdata/sample.config.5.xml -- a real OPNsense export -- carries all eight in
// a single file. Guarding them one at a time is how five of them stayed broken
// after the first three were fixed, so they are asserted together here.
func TestConverter_AllPlaceholderContainers_EndToEnd_ProduceNoEntries(t *testing.T) {
	t.Parallel()

	const configXML = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <staticroutes><route/></staticroutes>
  <bridges><bridged/></bridges>
  <ppps><ppp/></ppps>
  <gifs><gif/></gifs>
  <gres><gre/></gres>
  <laggs><lagg/></laggs>
  <virtualip><vip/></virtualip>
  <vlans><vlan/></vlans>
</opnsense>`

	factory := parser.NewFactory(cfgparser.NewXMLParser())

	device, warnings, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(configXML),
		common.DeviceTypeUnknown,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Empty(t, device.Routing.StaticRoutes, "static routes")
	assert.Empty(t, device.Bridges, "bridges")
	assert.Empty(t, device.PPPs, "PPPs")
	assert.Empty(t, device.GIFs, "GIFs")
	assert.Empty(t, device.GREs, "GREs")
	assert.Empty(t, device.LAGGs, "LAGGs")
	assert.Empty(t, device.VirtualIPs, "virtual IPs")
	assert.Empty(t, device.VLANs, "VLANs")

	assert.False(t, device.HasRoutes(),
		"a config whose only routing content is a placeholder has no routing configuration")

	// A placeholder must not reach the enum-cast validation in convertLAGGs and
	// convertVirtualIPs, which would warn about its empty protocol/mode.
	assert.Empty(t, warnings, "placeholders must not produce conversion warnings")
}
