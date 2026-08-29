package opnsense

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for vendor element shapes the schema used to decode into
// something smaller than what the file contained. Every case here failed
// silently before: the decode returned no error, just fewer values.

func TestSysctlItems_ContainerHoldsEveryTunable(t *testing.T) {
	const cfg = `<opnsense>
		<sysctl>
			<item><descr>read ahead</descr><tunable>vfs.read_max</tunable><value>128</value></item>
			<item><descr>port range</descr><tunable>net.inet.ip.portrange.first</tunable><value>1024</value></item>
			<item><descr>blackhole</descr><tunable>net.inet.tcp.blackhole</tunable><value>2</value></item>
		</sysctl>
	</opnsense>`

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(cfg), &doc))

	require.Len(t, doc.Sysctl, 3, "one <sysctl> container holding three <item> children must yield three tunables")
	assert.Equal(t, "vfs.read_max", doc.Sysctl[0].Tunable)
	assert.Equal(t, "128", doc.Sysctl[0].Value)
	assert.Equal(t, "read ahead", doc.Sysctl[0].Descr)
	assert.Equal(t, "net.inet.tcp.blackhole", doc.Sysctl[2].Tunable)
}

func TestSysctlItems_LegacyDirectShapeStillDecodes(t *testing.T) {
	const cfg = `<opnsense>
		<sysctl><descr>legacy</descr><tunable>net.inet.ip.test</tunable><value>1</value></sysctl>
	</opnsense>`

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(cfg), &doc))

	require.Len(t, doc.Sysctl, 1)
	assert.Equal(t, "net.inet.ip.test", doc.Sysctl[0].Tunable)
	assert.Equal(t, "1", doc.Sysctl[0].Value)
}

func TestSysctlItems_MultipleContainersAccumulate(t *testing.T) {
	const cfg = `<opnsense>
		<sysctl><item><tunable>first</tunable><value>1</value></item></sysctl>
		<sysctl><item><tunable>second</tunable><value>2</value></item></sysctl>
	</opnsense>`

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(cfg), &doc))

	require.Len(t, doc.Sysctl, 2, "a second <sysctl> container must append, not replace")
	assert.Equal(t, "first", doc.Sysctl[0].Tunable)
	assert.Equal(t, "second", doc.Sysctl[1].Tunable)
}

func TestSysctlItems_EmptyContainerYieldsNoTunables(t *testing.T) {
	const cfg = `<opnsense><sysctl></sysctl></opnsense>`

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(cfg), &doc))

	assert.Empty(t, doc.Sysctl, "an empty container must not synthesise a blank tunable")
}

func TestGroupAndUser_RepeatedPrivilegesAreKept(t *testing.T) {
	const cfg = `<opnsense>
		<system>
			<group>
				<name>admins</name><scope>system</scope><gid>1999</gid>
				<member>0</member><member>2000</member><member>2001</member>
				<priv>page-all</priv><priv>user-shell-access</priv>
			</group>
			<user>
				<name>alice</name><scope>local</scope><uid>2000</uid><groupname>admins</groupname>
				<priv>page-all</priv><priv>user-shell-access</priv>
			</user>
		</system>
	</opnsense>`

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(cfg), &doc))

	require.Len(t, doc.System.Group, 1)
	assert.Equal(t, []string{"0", "2000", "2001"}, doc.System.Group[0].Member)
	assert.Equal(t, []string{"page-all", "user-shell-access"}, doc.System.Group[0].Priv)

	require.Len(t, doc.System.User, 1)
	assert.Equal(t, []string{"page-all", "user-shell-access"}, doc.System.User[0].Priv)
}

func TestNATRule_DestinationPortPrefersNestedThenDstPort(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want string
	}{
		{
			name: "dstport sibling of destination",
			xml:  `<rule><destination><any/></destination><dstport>500</dstport></rule>`,
			want: "500",
		},
		{
			name: "nested destination port wins",
			xml:  `<rule><destination><port>443</port></destination><dstport>500</dstport></rule>`,
			want: "443",
		},
		{
			name: "neither present",
			xml:  `<rule><destination><any/></destination></rule>`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule NATRule
			require.NoError(t, xml.Unmarshal([]byte(tt.xml), &rule))
			assert.Equal(t, tt.want, rule.EffectiveDestinationPort())
		})
	}
}

func TestRule_TagAndTaggedAreParsed(t *testing.T) {
	const cfg = `<rule>
		<type>pass</type><interface>lan</interface>
		<tag>MULLVAD_NO_WAN_EGRESS</tag><tagged>MARKED</tagged>
	</rule>`

	var rule Rule
	require.NoError(t, xml.Unmarshal([]byte(cfg), &rule))

	assert.Equal(t, "MULLVAD_NO_WAN_EGRESS", rule.Tag)
	assert.Equal(t, "MARKED", rule.Tagged)
}

func TestDhcpdInterface_FailoverPeerAndDdnsAlgorithm(t *testing.T) {
	const cfg = `<lan>
		<enable>1</enable>
		<failover_peerip>10.1.1.12</failover_peerip>
		<ddnsdomainalgorithm>hmac-md5</ddnsdomainalgorithm>
	</lan>`

	var iface DhcpdInterface
	require.NoError(t, xml.Unmarshal([]byte(cfg), &iface))

	assert.Equal(t, "10.1.1.12", iface.FailoverPeerIP)
	assert.Equal(t, "hmac-md5", iface.DdnsDomainAlgorithm)
}

func TestOpenVPNClient_CryptoFieldsAreParsed(t *testing.T) {
	const cfg = `<openvpn-client>
		<vpnid>1</vpnid>
		<crypto>AES-256-GCM</crypto>
		<digest>SHA384</digest>
		<ncp-ciphers>AES-256-GCM</ncp-ciphers>
	</openvpn-client>`

	var client OpenVPNClient
	require.NoError(t, xml.Unmarshal([]byte(cfg), &client))

	assert.Equal(t, "AES-256-GCM", client.Crypto)
	assert.Equal(t, "SHA384", client.Digest)
	assert.Equal(t, "AES-256-GCM", client.NCPCiphers)
}

func TestSysctlItems_PlaceholderItemIsDropped(t *testing.T) {
	// The DTD makes every child of <item> optional, so a bare <item/> is valid
	// and would otherwise unmarshal into an entry reporting a tunable that is
	// not configured. Same phantom-entry class as GOTCHAS.md section 3.4.
	tests := []struct {
		name string
		xml  string
		want int
	}{
		{"bare placeholder", `<opnsense><sysctl><item/></sysctl></opnsense>`, 0},
		{"placeholder among real entries", `<opnsense><sysctl>` +
			`<item><tunable>net.inet.ip.redirect</tunable><value>0</value></item>` +
			`<item/>` +
			`<item><tunable>net.inet.tcp.blackhole</tunable><value>2</value></item>` +
			`</sysctl></opnsense>`, 2},
		{"description alone survives", `<opnsense><sysctl>` +
			`<item><descr>documented but unset</descr></item></sysctl></opnsense>`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc OpnSenseDocument
			require.NoError(t, xml.Unmarshal([]byte(tt.xml), &doc))
			assert.Len(t, doc.Sysctl, tt.want)
		})
	}
}

func TestSysctlItems_MarshalsBackToTheContainerShape(t *testing.T) {
	// Every other custom container in this package pairs its unmarshaler with a
	// marshaler. Without one the encoder emits a <sysctl> element per tunable in
	// the legacy flat shape, which still decodes but no longer matches what the
	// vendor writes.
	const in = `<opnsense><sysctl>` +
		`<item><descr>a</descr><tunable>t1</tunable><value>1</value></item>` +
		`<item><descr>b</descr><tunable>t2</tunable><value>2</value></item>` +
		`</sysctl></opnsense>`

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(in), &doc))
	require.Len(t, doc.Sysctl, 2)

	out, err := xml.Marshal(&doc)
	require.NoError(t, err)

	rendered := string(out)
	assert.Equal(t, 1, strings.Count(rendered, "<sysctl>"),
		"exactly one container, not one element per tunable")
	assert.Equal(t, 2, strings.Count(rendered, "<item>"),
		"one <item> child per tunable")

	var back OpnSenseDocument
	require.NoError(t, xml.Unmarshal(out, &back))
	assert.Equal(t, doc.Sysctl, back.Sysctl, "round trip must preserve every tunable")
}

func TestSysctlItems_MarshalsNothingWhenEmpty(t *testing.T) {
	var doc OpnSenseDocument
	out, err := xml.Marshal(&doc)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "<sysctl>",
		"an empty list must not emit an empty container")
}
