package pfsense_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These guard values that the schema already parsed but the converter dropped
// on the floor, so the loss was invisible in every output format.

func TestConverter_UserPrivilegesReachCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()
	doc.System.User = []schema.User{{
		Name: "admin",
		UID:  "0",
		Priv: []string{"page-all", "user-shell-access"},
	}}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Users, 1)
	assert.Equal(t, "page-all, user-shell-access", device.Users[0].Privileges)
}

func TestConverter_FirewallRuleTagsReachCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()
	doc.Filter.Rule = []schema.FilterRule{{
		Type:      "pass",
		Interface: opnsense.InterfaceList{"lan"},
		Tag:       "MULLVAD_NO_WAN_EGRESS",
		Tagged:    "MARKED",
	}}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 1)
	assert.Equal(t, "MULLVAD_NO_WAN_EGRESS", device.FirewallRules[0].Tag)
	assert.Equal(t, "MARKED", device.FirewallRules[0].Tagged)
}

func TestConverter_OutboundNATDstPortReachesCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()
	doc.Nat.Outbound.Rule = []opnsense.NATRule{{
		Interface: opnsense.InterfaceList{"wan"},
		Protocol:  "udp",
		DstPort:   "500",
		Descr:     "Auto created rule for ISAKMP",
	}}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.NAT.OutboundRules, 1)
	assert.Equal(t, "500", device.NAT.OutboundRules[0].Destination.Port,
		"a port-scoped outbound NAT rule must not read as matching every port")
}

func TestConverter_OpenVPNCryptoReachesCommonDevice(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()
	doc.OpenVPN.Clients = []opnsense.OpenVPNClient{{
		VPN_ID:         "1",
		Crypto:         "AES-256-GCM",
		Digest:         "SHA384",
		NCPCiphers:     "AES-256-GCM",
		Custom_options: "remote-cert-tls server",
	}}
	// The server write-site was uncovered while the client one was guarded,
	// and a server on a weak data-channel cipher is the instance an auditor
	// most wants to see.
	doc.OpenVPN.Servers = []opnsense.OpenVPNServer{{
		VPN_ID:         "2",
		Crypto:         "AES-128-GCM",
		Digest:         "SHA256",
		NCPCiphers:     "AES-128-GCM",
		Custom_options: "remote-cert-tls client",
	}}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.VPN.OpenVPN.Clients, 1)
	client := device.VPN.OpenVPN.Clients[0]
	assert.Equal(t, "AES-256-GCM", client.Crypto)
	assert.Equal(t, "SHA384", client.Digest)
	assert.Equal(t, "AES-256-GCM", client.NCPCiphers)
	assert.Equal(t, "remote-cert-tls server", client.CustomOptions)

	require.Len(t, device.VPN.OpenVPN.Servers, 1)
	server := device.VPN.OpenVPN.Servers[0]
	assert.Equal(t, "AES-128-GCM", server.Crypto)
	assert.Equal(t, "SHA256", server.Digest)
	assert.Equal(t, "AES-128-GCM", server.NCPCiphers)
	assert.Equal(t, "remote-cert-tls client", server.CustomOptions)
}
