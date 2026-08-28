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
