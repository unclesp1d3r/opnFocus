package model

// Interface represents a network interface with normalized fields.
type Interface struct {
	// Name is the logical interface name (e.g., "lan", "wan", "opt1").
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// PhysicalIf is the physical device identifier (e.g., "igb0", "em0").
	PhysicalIf string `json:"physicalIf,omitempty" yaml:"physicalIf,omitempty"`
	// Description is a human-readable label for the interface.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Enabled indicates whether the interface is administratively up.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// IPAddress is the IPv4 address assigned to the interface.
	IPAddress string `json:"ipAddress,omitempty" yaml:"ipAddress,omitempty"`
	// IPv6Address is the IPv6 address assigned to the interface.
	IPv6Address string `json:"ipv6Address,omitempty" yaml:"ipv6Address,omitempty"`
	// Subnet is the IPv4 subnet prefix length.
	Subnet string `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	// SubnetV6 is the IPv6 subnet prefix length.
	SubnetV6 string `json:"subnetV6,omitempty" yaml:"subnetV6,omitempty"`
	// Gateway is the IPv4 gateway for the interface.
	Gateway string `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	// GatewayV6 is the IPv6 gateway for the interface.
	GatewayV6 string `json:"gatewayV6,omitempty" yaml:"gatewayV6,omitempty"`
	// BlockPrivate enables blocking of RFC 1918 private network traffic.
	BlockPrivate bool `json:"blockPrivate,omitempty" yaml:"blockPrivate,omitempty"`
	// BlockBogons enables blocking of bogon (unassigned/reserved) network traffic.
	BlockBogons bool `json:"blockBogons,omitempty" yaml:"blockBogons,omitempty"`
	// Type is the interface type (e.g., "dhcp", "static", "none").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// MTU is the maximum transmission unit size.
	MTU string `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	// SpoofMAC is an overridden MAC address for the interface.
	SpoofMAC string `json:"spoofMac,omitempty" yaml:"spoofMac,omitempty"`
	// DHCPHostname is the hostname sent in DHCP requests.
	DHCPHostname string `json:"dhcpHostname,omitempty" yaml:"dhcpHostname,omitempty"`
	// Media is the interface media type (e.g., "autoselect").
	Media string `json:"media,omitempty" yaml:"media,omitempty"`
	// MediaOpt is the interface media option (e.g., "full-duplex").
	MediaOpt string `json:"mediaOpt,omitempty" yaml:"mediaOpt,omitempty"`
	// Virtual indicates this is a virtual rather than physical interface.
	Virtual bool `json:"virtual,omitempty" yaml:"virtual,omitempty"`
	// Lock prevents the interface from being accidentally deleted or modified.
	Lock bool `json:"lock,omitempty" yaml:"lock,omitempty"`

	// DHCPAdvancedV4 holds the advanced DHCPv4 *client* settings configured on this
	// interface (pfSense/OPNsense "DHCP client configuration" panel). These are the
	// <interfaces><wan>/<lan> elements, distinct from the DHCP *server* settings of
	// the same name that DHCPScope.AdvancedV4 carries from <dhcpd>. Nil when unset,
	// so the field is omitted during serialization.
	DHCPAdvancedV4 *InterfaceDHCPAdvancedV4 `json:"dhcpAdvancedV4,omitempty" yaml:"dhcpAdvancedV4,omitempty"`
	// DHCPAdvancedV6 holds the advanced DHCPv6 client settings configured on this
	// interface. See DHCPAdvancedV4 for the server/client distinction. Nil when unset.
	DHCPAdvancedV6 *InterfaceDHCPAdvancedV6 `json:"dhcpAdvancedV6,omitempty" yaml:"dhcpAdvancedV6,omitempty"`
}

// VLAN represents a VLAN configuration.
type VLAN struct {
	// VLANIf is the VLAN interface name (e.g., "igb0_vlan100").
	VLANIf string `json:"vlanIf,omitempty" yaml:"vlanIf,omitempty"`
	// PhysicalIf is the parent physical interface carrying the VLAN.
	PhysicalIf string `json:"physicalIf,omitempty" yaml:"physicalIf,omitempty"`
	// Tag is the 802.1Q VLAN tag identifier.
	Tag string `json:"tag,omitempty" yaml:"tag,omitempty"`
	// Description is a human-readable description of the VLAN.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the VLAN was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the VLAN was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// Bridge represents a network bridge configuration.
type Bridge struct {
	// Members contains the member interface names belonging to this bridge.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
	// Description is a human-readable description of the bridge.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// BridgeIf is the bridge interface name (e.g., "bridge0").
	BridgeIf string `json:"bridgeIf,omitempty" yaml:"bridgeIf,omitempty"`
	// STP indicates whether Spanning Tree Protocol is enabled.
	STP bool `json:"stp,omitempty" yaml:"stp,omitempty"`
	// Created is the timestamp when the bridge was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the bridge was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// PPP represents a PPP connection configuration.
type PPP struct {
	// Interface is the PPP interface name (e.g., "pppoe0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Type is the PPP connection type (e.g., "pppoe", "pptp", "l2tp").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Description is a human-readable description of the PPP connection.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Ports lists the physical interface(s) the PPP connection operates over.
	// May contain multiple entries for multi-link PPP (MLPPP).
	Ports string `json:"ports,omitempty" yaml:"ports,omitempty"`
	// Username is the authentication username for the PPP connection.
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	// AuthMethod is the PPP authentication method (e.g., "chap", "pap", "mschap").
	AuthMethod string `json:"authMethod,omitempty" yaml:"authMethod,omitempty"`
	// MTU is the maximum transmission unit for the PPP link.
	MTU string `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	// Provider is the ISP or service provider identifier.
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`
}

// GIF represents a GIF (generic tunnel interface) tunnel configuration.
type GIF struct {
	// Interface is the GIF tunnel interface name (e.g., "gif0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Local is the parent physical interface name (e.g., "wan").
	Local string `json:"local,omitempty" yaml:"local,omitempty"`
	// Remote is the remote outer endpoint address for the tunnel.
	Remote string `json:"remote,omitempty" yaml:"remote,omitempty"`
	// TunnelLocalAddress is the local inner tunnel address.
	TunnelLocalAddress string `json:"tunnelLocalAddress,omitempty" yaml:"tunnelLocalAddress,omitempty"`
	// TunnelRemoteAddress is the remote inner tunnel address.
	TunnelRemoteAddress string `json:"tunnelRemoteAddress,omitempty" yaml:"tunnelRemoteAddress,omitempty"`
	// TunnelSubnetBits is the tunnel subnet mask prefix length.
	TunnelSubnetBits string `json:"tunnelSubnetBits,omitempty" yaml:"tunnelSubnetBits,omitempty"`
	// Description is a human-readable description of the GIF tunnel.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the GIF tunnel was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the GIF tunnel was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// GRE represents a GRE (Generic Routing Encapsulation) tunnel configuration.
type GRE struct {
	// Interface is the GRE tunnel interface name (e.g., "gre0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Local is the parent physical interface name (e.g., "wan").
	Local string `json:"local,omitempty" yaml:"local,omitempty"`
	// Remote is the remote outer endpoint address for the tunnel.
	Remote string `json:"remote,omitempty" yaml:"remote,omitempty"`
	// TunnelLocalAddress is the local inner tunnel address.
	TunnelLocalAddress string `json:"tunnelLocalAddress,omitempty" yaml:"tunnelLocalAddress,omitempty"`
	// TunnelRemoteAddress is the remote inner tunnel address.
	TunnelRemoteAddress string `json:"tunnelRemoteAddress,omitempty" yaml:"tunnelRemoteAddress,omitempty"`
	// TunnelSubnetBits is the tunnel subnet mask prefix length.
	TunnelSubnetBits string `json:"tunnelSubnetBits,omitempty" yaml:"tunnelSubnetBits,omitempty"`
	// Description is a human-readable description of the GRE tunnel.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the GRE tunnel was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the GRE tunnel was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// LAGGProtocol represents the link aggregation protocol.
type LAGGProtocol string

const (
	// LAGGProtocolLACP uses IEEE 802.3ad Link Aggregation Control Protocol.
	LAGGProtocolLACP LAGGProtocol = "lacp"
	// LAGGProtocolFailover uses active/standby failover between members.
	LAGGProtocolFailover LAGGProtocol = "failover"
	// LAGGProtocolLoadBalance distributes traffic across members by hashing.
	LAGGProtocolLoadBalance LAGGProtocol = "loadbalance"
	// LAGGProtocolRoundRobin distributes traffic across members in round-robin order.
	LAGGProtocolRoundRobin LAGGProtocol = "roundrobin"
)

// IsValid reports whether p is a recognized LAGG protocol.
func (p LAGGProtocol) IsValid() bool {
	switch p {
	case LAGGProtocolLACP, LAGGProtocolFailover, LAGGProtocolLoadBalance, LAGGProtocolRoundRobin:
		return true
	default:
		return false
	}
}

// LAGG represents a link aggregation configuration.
type LAGG struct {
	// Interface is the LAGG interface name (e.g., "lagg0", "Port-channel1").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Members contains the member physical interface names.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
	// Protocol is the aggregation protocol (lacp, failover, loadbalance, or roundrobin).
	Protocol LAGGProtocol `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// Description is a human-readable description of the LAGG.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the LAGG was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the LAGG was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// VIPMode represents the virtual IP operating mode.
type VIPMode string

const (
	// VIPModeCarp uses CARP (Common Address Redundancy Protocol) for HA failover.
	VIPModeCarp VIPMode = "carp"
	// VIPModeIPAlias assigns an additional IP address to an interface.
	VIPModeIPAlias VIPMode = "ipalias"
	// VIPModeProxyARP enables ARP proxying for downstream hosts.
	VIPModeProxyARP VIPMode = "proxyarp"
)

// IsValid reports whether m is a recognized virtual IP mode.
func (m VIPMode) IsValid() bool {
	switch m {
	case VIPModeCarp, VIPModeIPAlias, VIPModeProxyARP:
		return true
	default:
		return false
	}
}

// VirtualIP represents a virtual IP address configuration.
type VirtualIP struct {
	// Mode is the virtual IP mode (carp, ipalias, or proxyarp).
	Mode VIPMode `json:"mode,omitempty" yaml:"mode,omitempty"`
	// Interface is the interface the virtual IP is bound to.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Subnet is the virtual IP address.
	Subnet string `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	// SubnetBits is the CIDR subnet mask length.
	SubnetBits string `json:"subnetBits,omitempty" yaml:"subnetBits,omitempty"`
	// Description is a human-readable description of the virtual IP.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// UniqueID is a platform-generated unique identifier for the VIP entry.
	UniqueID string `json:"uniqueId,omitempty" yaml:"uniqueId,omitempty"`
	// VHID is the Virtual Host ID for CARP (1-255, unique per interface).
	VHID string `json:"vhid,omitempty" yaml:"vhid,omitempty"`
	// AdvSkew is the CARP advertisement skew (0-254, lower = higher priority).
	AdvSkew string `json:"advSkew,omitempty" yaml:"advSkew,omitempty"`
	// AdvBase is the CARP advertisement base interval in seconds.
	AdvBase string `json:"advBase,omitempty" yaml:"advBase,omitempty"`
}

// InterfaceGroup represents a logical grouping of interfaces.
type InterfaceGroup struct {
	// Name is the interface group name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Members contains the interface names belonging to this group.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
	// Description is a human-readable description of the interface group.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// InterfaceDHCPAdvancedV4 holds the advanced DHCPv4 *client* settings an interface
// carries, populated from the <interfaces> section. It deliberately does not reuse
// DHCPAdvancedV4: that struct models the <dhcpd> server section, and the two element
// sets have diverged (ddnsdomainalgorithm, ddnsdomainkeyalgorithm and failover_peerip
// occur only under <dhcpd>). Keeping them separate means a field added for the server
// cannot silently appear, unpopulated, on every interface.
//
// Every field below was verified to occur under <interfaces> in the shipped fixtures.
type InterfaceDHCPAdvancedV4 struct {
	// Alias and rejection fields.

	// AliasAddress is an additional IP alias for the DHCP server interface.
	AliasAddress string `json:"aliasAddress,omitempty" yaml:"aliasAddress,omitempty"`
	// AliasSubnet is the subnet mask for the alias address.
	AliasSubnet string `json:"aliasSubnet,omitempty" yaml:"aliasSubnet,omitempty"`
	// DHCPRejectFrom is a comma-separated list of MAC addresses to reject.
	DHCPRejectFrom string `json:"dhcpRejectFrom,omitempty" yaml:"dhcpRejectFrom,omitempty"`

	// Advanced DHCPv4 protocol timing fields.

	// AdvDHCPPTTimeout is the protocol timeout for DHCP client requests.
	AdvDHCPPTTimeout string `json:"advDhcpPtTimeout,omitempty" yaml:"advDhcpPtTimeout,omitempty"`
	// AdvDHCPPTRetry is the retry interval for DHCP client requests.
	AdvDHCPPTRetry string `json:"advDhcpPtRetry,omitempty" yaml:"advDhcpPtRetry,omitempty"`
	// AdvDHCPPTSelectTimeout is the timeout for selecting a DHCP offer.
	AdvDHCPPTSelectTimeout string `json:"advDhcpPtSelectTimeout,omitempty" yaml:"advDhcpPtSelectTimeout,omitempty"`
	// AdvDHCPPTReboot is the time to wait before rebooting the DHCP client.
	AdvDHCPPTReboot string `json:"advDhcpPtReboot,omitempty" yaml:"advDhcpPtReboot,omitempty"`
	// AdvDHCPPTBackoffCutoff is the maximum backoff time for DHCP retries.
	AdvDHCPPTBackoffCutoff string `json:"advDhcpPtBackoffCutoff,omitempty" yaml:"advDhcpPtBackoffCutoff,omitempty"`
	// AdvDHCPPTInitialInterval is the initial retry interval for DHCP requests.
	AdvDHCPPTInitialInterval string `json:"advDhcpPtInitialInterval,omitempty" yaml:"advDhcpPtInitialInterval,omitempty"`
	// AdvDHCPPTValues contains additional protocol timing values.
	AdvDHCPPTValues string `json:"advDhcpPtValues,omitempty" yaml:"advDhcpPtValues,omitempty"`

	// Advanced DHCPv4 option fields.

	// AdvDHCPSendOptions specifies additional DHCP options to send.
	AdvDHCPSendOptions string `json:"advDhcpSendOptions,omitempty" yaml:"advDhcpSendOptions,omitempty"`
	// AdvDHCPRequestOptions specifies additional DHCP options to request.
	AdvDHCPRequestOptions string `json:"advDhcpRequestOptions,omitempty" yaml:"advDhcpRequestOptions,omitempty"`
	// AdvDHCPRequiredOptions specifies DHCP options that must be present.
	AdvDHCPRequiredOptions string `json:"advDhcpRequiredOptions,omitempty" yaml:"advDhcpRequiredOptions,omitempty"`
	// AdvDHCPOptionModifiers contains DHCP option modifier expressions.
	AdvDHCPOptionModifiers string `json:"advDhcpOptionModifiers,omitempty" yaml:"advDhcpOptionModifiers,omitempty"`

	// Advanced DHCPv4 configuration override fields.

	// AdvDHCPConfigAdvanced contains raw advanced DHCP configuration text.
	AdvDHCPConfigAdvanced string `json:"advDhcpConfigAdvanced,omitempty" yaml:"advDhcpConfigAdvanced,omitempty"`
	// AdvDHCPConfigFileOverride enables overriding the DHCP config file.
	AdvDHCPConfigFileOverride string `json:"advDhcpConfigFileOverride,omitempty" yaml:"advDhcpConfigFileOverride,omitempty"`
	// AdvDHCPConfigFileOverridePath is the filesystem path for the DHCP config override file.
	AdvDHCPConfigFileOverridePath string `json:"advDhcpConfigFileOverridePath,omitempty" yaml:"advDhcpConfigFileOverridePath,omitempty"`
}

// InterfaceDHCPAdvancedV6 holds the advanced DHCPv6 client settings an interface
// carries. See InterfaceDHCPAdvancedV4 for why this does not reuse DHCPAdvancedV6.
type InterfaceDHCPAdvancedV6 struct {
	// IPv6 tracking fields.

	// Track6Interface is the upstream interface used for IPv6 prefix tracking.
	Track6Interface string `json:"track6Interface,omitempty" yaml:"track6Interface,omitempty"`
	// Track6PrefixID is the prefix delegation ID for IPv6 tracking.
	Track6PrefixID string `json:"track6PrefixId,omitempty" yaml:"track6PrefixId,omitempty"`

	// Advanced DHCPv6 interface statement fields.

	// AdvDHCP6InterfaceStatementSendOptions specifies DHCPv6 options to send.
	AdvDHCP6InterfaceStatementSendOptions string `json:"advDhcp6InterfaceStatementSendOptions,omitempty" yaml:"advDhcp6InterfaceStatementSendOptions,omitempty"`
	// AdvDHCP6InterfaceStatementRequestOptions specifies DHCPv6 options to request.
	AdvDHCP6InterfaceStatementRequestOptions string `json:"advDhcp6InterfaceStatementRequestOptions,omitempty" yaml:"advDhcp6InterfaceStatementRequestOptions,omitempty"`
	// AdvDHCP6InterfaceStatementInformationOnlyEnable enables information-only mode.
	AdvDHCP6InterfaceStatementInformationOnlyEnable bool `json:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty" yaml:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty"`
	// AdvDHCP6InterfaceStatementScript is the script path for DHCPv6 events.
	AdvDHCP6InterfaceStatementScript string `json:"advDhcp6InterfaceStatementScript,omitempty" yaml:"advDhcp6InterfaceStatementScript,omitempty"`

	// Advanced DHCPv6 identity association address fields.

	// AdvDHCP6IDAssocStatementAddressEnable enables IA_NA address assignment.
	AdvDHCP6IDAssocStatementAddressEnable bool `json:"advDhcp6IdAssocStatementAddressEnable,omitempty" yaml:"advDhcp6IdAssocStatementAddressEnable,omitempty"`
	// AdvDHCP6IDAssocStatementAddress is the requested IA_NA address.
	AdvDHCP6IDAssocStatementAddress string `json:"advDhcp6IdAssocStatementAddress,omitempty" yaml:"advDhcp6IdAssocStatementAddress,omitempty"`
	// AdvDHCP6IDAssocStatementAddressID is the identity association ID for addresses.
	AdvDHCP6IDAssocStatementAddressID string `json:"advDhcp6IdAssocStatementAddressId,omitempty" yaml:"advDhcp6IdAssocStatementAddressId,omitempty"`
	// AdvDHCP6IDAssocStatementAddressPLTime is the preferred lifetime for IA_NA addresses.
	AdvDHCP6IDAssocStatementAddressPLTime string `json:"advDhcp6IdAssocStatementAddressPlTime,omitempty" yaml:"advDhcp6IdAssocStatementAddressPlTime,omitempty"`
	// AdvDHCP6IDAssocStatementAddressVLTime is the valid lifetime for IA_NA addresses.
	AdvDHCP6IDAssocStatementAddressVLTime string `json:"advDhcp6IdAssocStatementAddressVlTime,omitempty" yaml:"advDhcp6IdAssocStatementAddressVlTime,omitempty"`

	// Advanced DHCPv6 identity association prefix fields.

	// AdvDHCP6IDAssocStatementPrefixEnable enables IA_PD prefix delegation.
	AdvDHCP6IDAssocStatementPrefixEnable bool `json:"advDhcp6IdAssocStatementPrefixEnable,omitempty" yaml:"advDhcp6IdAssocStatementPrefixEnable,omitempty"`
	// AdvDHCP6IDAssocStatementPrefix is the requested IA_PD prefix.
	AdvDHCP6IDAssocStatementPrefix string `json:"advDhcp6IdAssocStatementPrefix,omitempty" yaml:"advDhcp6IdAssocStatementPrefix,omitempty"`
	// AdvDHCP6IDAssocStatementPrefixID is the identity association ID for prefixes.
	AdvDHCP6IDAssocStatementPrefixID string `json:"advDhcp6IdAssocStatementPrefixId,omitempty" yaml:"advDhcp6IdAssocStatementPrefixId,omitempty"`
	// AdvDHCP6IDAssocStatementPrefixPLTime is the preferred lifetime for IA_PD prefixes.
	AdvDHCP6IDAssocStatementPrefixPLTime string `json:"advDhcp6IdAssocStatementPrefixPlTime,omitempty" yaml:"advDhcp6IdAssocStatementPrefixPlTime,omitempty"`
	// AdvDHCP6IDAssocStatementPrefixVLTime is the valid lifetime for IA_PD prefixes.
	AdvDHCP6IDAssocStatementPrefixVLTime string `json:"advDhcp6IdAssocStatementPrefixVlTime,omitempty" yaml:"advDhcp6IdAssocStatementPrefixVlTime,omitempty"`

	// Advanced DHCPv6 SLA prefix interface field.

	// AdvDHCP6PrefixInterfaceStatementSLALen is the SLA prefix length for interface delegation.
	AdvDHCP6PrefixInterfaceStatementSLALen string `json:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty" yaml:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty"`

	// Advanced DHCPv6 authentication fields.

	// AdvDHCP6AuthenticationStatementAuthName is the authentication profile name.
	AdvDHCP6AuthenticationStatementAuthName string `json:"advDhcp6AuthenticationStatementAuthName,omitempty" yaml:"advDhcp6AuthenticationStatementAuthName,omitempty"`
	// AdvDHCP6AuthenticationStatementProtocol is the authentication protocol.
	AdvDHCP6AuthenticationStatementProtocol string `json:"advDhcp6AuthenticationStatementProtocol,omitempty" yaml:"advDhcp6AuthenticationStatementProtocol,omitempty"`
	// AdvDHCP6AuthenticationStatementAlgorithm is the authentication algorithm.
	AdvDHCP6AuthenticationStatementAlgorithm string `json:"advDhcp6AuthenticationStatementAlgorithm,omitempty" yaml:"advDhcp6AuthenticationStatementAlgorithm,omitempty"`
	// AdvDHCP6AuthenticationStatementRDM is the replay detection method.
	AdvDHCP6AuthenticationStatementRDM string `json:"advDhcp6AuthenticationStatementRdm,omitempty" yaml:"advDhcp6AuthenticationStatementRdm,omitempty"`

	// Advanced DHCPv6 key info fields.

	// AdvDHCP6KeyInfoStatementKeyName is the key name for DHCPv6 authentication.
	AdvDHCP6KeyInfoStatementKeyName string `json:"advDhcp6KeyInfoStatementKeyName,omitempty" yaml:"advDhcp6KeyInfoStatementKeyName,omitempty"`
	// AdvDHCP6KeyInfoStatementRealm is the authentication realm.
	AdvDHCP6KeyInfoStatementRealm string `json:"advDhcp6KeyInfoStatementRealm,omitempty" yaml:"advDhcp6KeyInfoStatementRealm,omitempty"`
	// AdvDHCP6KeyInfoStatementKeyID is the key identifier.
	AdvDHCP6KeyInfoStatementKeyID string `json:"advDhcp6KeyInfoStatementKeyId,omitempty" yaml:"advDhcp6KeyInfoStatementKeyId,omitempty"`
	// AdvDHCP6KeyInfoStatementSecret is the shared secret for DHCPv6 authentication.
	AdvDHCP6KeyInfoStatementSecret string `json:"advDhcp6KeyInfoStatementSecret,omitempty" yaml:"advDhcp6KeyInfoStatementSecret,omitempty"`
	// AdvDHCP6KeyInfoStatementExpire is the key expiration time.
	AdvDHCP6KeyInfoStatementExpire string `json:"advDhcp6KeyInfoStatementExpire,omitempty" yaml:"advDhcp6KeyInfoStatementExpire,omitempty"`

	// Advanced DHCPv6 configuration override fields.

	// AdvDHCP6ConfigAdvanced contains raw advanced DHCPv6 configuration text.
	AdvDHCP6ConfigAdvanced string `json:"advDhcp6ConfigAdvanced,omitempty" yaml:"advDhcp6ConfigAdvanced,omitempty"`
	// AdvDHCP6ConfigFileOverride enables overriding the DHCPv6 config file.
	AdvDHCP6ConfigFileOverride string `json:"advDhcp6ConfigFileOverride,omitempty" yaml:"advDhcp6ConfigFileOverride,omitempty"`
	// AdvDHCP6ConfigFileOverridePath is the filesystem path for the DHCPv6 config override file.
	AdvDHCP6ConfigFileOverridePath string `json:"advDhcp6ConfigFileOverridePath,omitempty" yaml:"advDhcp6ConfigFileOverridePath,omitempty"`
}
