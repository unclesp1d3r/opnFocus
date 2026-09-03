package opnsense_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The OPNsense schema modelled several repeated vendor elements as scalars,
// so a config with many values converted to a device carrying one. These
// guard the full set surviving the trip to CommonDevice.

func TestConverter_GroupMembersAndPrivilegesAreJoined(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.Group = []schema.Group{{
		Name:   "admins",
		Gid:    "1999",
		Scope:  "system",
		Member: []string{"0", "2000", "2001"},
		Priv:   []string{"page-all", "user-shell-access"},
	}}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Groups, 1)
	assert.Equal(t, "0, 2000, 2001", device.Groups[0].Member)
	assert.Equal(t, "page-all, user-shell-access", device.Groups[0].Privileges)
}

func TestConverter_UserPrivilegesReachCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.User = []schema.User{{
		Name: "alice",
		UID:  "2000",
		Priv: []string{"page-all", "user-shell-access"},
	}}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Users, 1)
	assert.Equal(t, "page-all, user-shell-access", device.Users[0].Privileges)
}

func TestConverter_FirewallRuleTagsReachCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Filter.Rule = []schema.Rule{{
		Type:      "pass",
		Interface: schema.InterfaceList{"lan"},
		Tag:       "MULLVAD_NO_WAN_EGRESS",
		Tagged:    "MARKED",
	}}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 1)
	assert.Equal(t, "MULLVAD_NO_WAN_EGRESS", device.FirewallRules[0].Tag)
	assert.Equal(t, "MARKED", device.FirewallRules[0].Tagged)
}

func TestConverter_EverySysctlTunableReachesCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Sysctl = schema.SysctlItems{
		{Tunable: "net.inet.ip.redirect", Value: "0", Descr: "no redirects"},
		{Tunable: "net.inet.tcp.blackhole", Value: "2", Descr: "blackhole"},
	}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Sysctl, 2)
	assert.Equal(t, "net.inet.ip.redirect", device.Sysctl[0].Tunable)
	assert.Equal(t, "net.inet.tcp.blackhole", device.Sysctl[1].Tunable)
}

// The three tests below cover OPNsense write-sites whose pfSense twins were
// already guarded. Each was reverted individually and the suite stayed green
// before they existed, which is the copy-on-write asymmetry §3.3 warns about
// showing up in the tests rather than in the schema.

func TestConverter_OutboundNATDstPortReachesCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Nat.Outbound.Rule = []schema.NATRule{{
		Interface: schema.InterfaceList{"wan"},
		Protocol:  "udp",
		DstPort:   "500",
		Descr:     "Auto created rule for ISAKMP",
	}}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.NAT.OutboundRules, 1)
	assert.Equal(t, "500", device.NAT.OutboundRules[0].Destination.Port,
		"a port-scoped outbound NAT rule must not read as matching every port")
}

func TestConverter_OpenVPNCryptoReachesCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OpenVPN.Servers = []schema.OpenVPNServer{{
		VPN_ID:         "1",
		Crypto:         "AES-256-GCM",
		Digest:         "SHA384",
		NCPCiphers:     "AES-256-GCM",
		Custom_options: "remote-cert-tls client",
	}}
	doc.OpenVPN.Clients = []schema.OpenVPNClient{{
		VPN_ID:         "2",
		Crypto:         "AES-128-GCM",
		Digest:         "SHA256",
		NCPCiphers:     "AES-128-GCM",
		Custom_options: "remote-cert-tls server",
	}}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	// A server on a weak data-channel cipher is the instance an auditor most
	// wants, and it was the write-site with no coverage at all.
	require.Len(t, device.VPN.OpenVPN.Servers, 1)
	server := device.VPN.OpenVPN.Servers[0]
	assert.Equal(t, "AES-256-GCM", server.Crypto)
	assert.Equal(t, "SHA384", server.Digest)
	assert.Equal(t, "AES-256-GCM", server.NCPCiphers)
	assert.Equal(t, "remote-cert-tls client", server.CustomOptions)

	require.Len(t, device.VPN.OpenVPN.Clients, 1)
	client := device.VPN.OpenVPN.Clients[0]
	assert.Equal(t, "AES-128-GCM", client.Crypto)
	assert.Equal(t, "SHA256", client.Digest)
	assert.Equal(t, "AES-128-GCM", client.NCPCiphers)
	assert.Equal(t, "remote-cert-tls server", client.CustomOptions)
}

func TestConverter_DHCPFailoverAndDdnsReachCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Dhcpd.Items = map[string]schema.DhcpdInterface{
		"lan": {
			Enable:              "1",
			DdnsDomainAlgorithm: "hmac-sha256",
			FailoverPeerIP:      "10.1.1.12",
		},
	}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.DHCP, 1)
	require.NotNil(t, device.DHCP[0].AdvancedV4,
		"the advanced block must exist once any advanced field is set")
	assert.Equal(t, "hmac-sha256", device.DHCP[0].AdvancedV4.DdnsDomainAlgorithm)
	assert.Equal(t, "10.1.1.12", device.DHCP[0].AdvancedV4.FailoverPeerIP)
}
