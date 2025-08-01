// Package validator provides comprehensive validation functionality for OPNsense configuration files.
// It validates system settings, network interfaces, DHCP server configuration, firewall rules,
// NAT rules, user and group settings, and sysctl tunables to ensure configuration integrity
// and prevent deployment of invalid configurations.
package validator

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidateOpnSenseDocument validates an entire OPNsense configuration document and returns all detected validation errors.
// It checks system settings, network interfaces, DHCP server, firewall rules, NAT rules, users and groups, and sysctl tunables for correctness and consistency.
func ValidateOpnSenseDocument(o *model.OpnSenseDocument) []ValidationError {
	var errors []ValidationError

	// Validate system configuration
	errors = append(errors, validateSystem(&o.System)...)

	// Validate interfaces
	errors = append(errors, validateInterfaces(&o.Interfaces)...)

	// Validate DHCP configuration
	errors = append(errors, validateDhcpd(&o.Dhcpd, &o.Interfaces)...)

	// Validate filter rules
	errors = append(errors, validateFilter(&o.Filter, &o.Interfaces)...)

	// Validate NAT configuration
	errors = append(errors, validateNat(&o.Nat)...)

	// Validate system users and groups
	errors = append(errors, validateUsersAndGroups(&o.System)...)

	// Validate sysctl items
	errors = append(errors, validateSysctl(o.Sysctl)...)

	return errors
}

// validateSystem checks the system-level configuration fields for required values and valid formats.
// It returns a slice of ValidationError for any invalid or missing system configuration fields, including hostname, domain, timezone, optimization, web GUI protocol, power management modes, and bogons interval.
func validateSystem(system *model.System) []ValidationError {
	var errors []ValidationError

	// Hostname is required and must be valid
	if system.Hostname == "" {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: "hostname is required",
		})
	} else if !isValidHostname(system.Hostname) {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: fmt.Sprintf("hostname '%s' contains invalid characters", system.Hostname),
		})
	}

	// Domain is required
	if system.Domain == "" {
		errors = append(errors, ValidationError{
			Field:   "system.domain",
			Message: "domain is required",
		})
	}

	// Validate timezone format
	if system.Timezone != "" && !isValidTimezone(system.Timezone) {
		errors = append(errors, ValidationError{
			Field:   "system.timezone",
			Message: "invalid timezone format: " + system.Timezone,
		})
	}

	// Validate optimization setting
	validOptimizations := []string{"normal", "high-latency", "aggressive", "conservative"}
	if system.Optimization != "" && !contains(validOptimizations, system.Optimization) {
		errors = append(errors, ValidationError{
			Field:   "system.optimization",
			Message: fmt.Sprintf("optimization '%s' must be one of: %v", system.Optimization, validOptimizations),
		})
	}

	// Validate webgui protocol
	validProtocols := []string{"http", "https"}
	if system.WebGUI.Protocol != "" && !contains(validProtocols, system.WebGUI.Protocol) {
		errors = append(errors, ValidationError{
			Field:   "system.webgui.protocol",
			Message: fmt.Sprintf("protocol '%s' must be one of: %v", system.WebGUI.Protocol, validProtocols),
		})
	}

	// Validate power management modes
	validPowerModes := []string{"hadp", "hiadp", "adaptive", "minimum", "maximum"}
	if system.PowerdACMode != "" && !contains(validPowerModes, system.PowerdACMode) {
		errors = append(errors, ValidationError{
			Field:   "system.powerd_ac_mode",
			Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdACMode, validPowerModes),
		})
	}

	if system.PowerdBatteryMode != "" && !contains(validPowerModes, system.PowerdBatteryMode) {
		errors = append(errors, ValidationError{
			Field:   "system.powerd_battery_mode",
			Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdBatteryMode, validPowerModes),
		})
	}

	if system.PowerdNormalMode != "" && !contains(validPowerModes, system.PowerdNormalMode) {
		errors = append(errors, ValidationError{
			Field:   "system.powerd_normal_mode",
			Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdNormalMode, validPowerModes),
		})
	}

	// Validate bogons interval
	validBogonsIntervals := []string{"monthly", "weekly", "daily", "never"}
	if system.Bogons.Interval != "" && !contains(validBogonsIntervals, system.Bogons.Interval) {
		errors = append(errors, ValidationError{
			Field: "system.bogons.interval",
			Message: fmt.Sprintf(
				"bogons interval '%s' must be one of: %v",
				system.Bogons.Interval,
				validBogonsIntervals,
			),
		})
	}

	return errors
}

// validateInterfaces validates all configured network interfaces and returns any validation errors found.
func validateInterfaces(interfaces *model.Interfaces) []ValidationError {
	var errors []ValidationError

	if interfaces == nil || interfaces.Items == nil {
		return errors
	}

	// Validate each configured interface
	for name, iface := range interfaces.Items {
		ifaceCopy := iface // Create a copy to get a pointer
		errors = append(errors, validateInterface(&ifaceCopy, name, interfaces)...)
	}

	return errors
}

// validateInterface checks a single network interface configuration for valid IP address types and formats, subnet masks, MTU range, and required fields for track6 IPv6 addressing.
// It returns a slice of ValidationError for any invalid or missing configuration fields.
func validateInterface(iface *model.Interface, name string, interfaces *model.Interfaces) []ValidationError {
	var errors []ValidationError

	if iface == nil {
		return errors
	}

	validInterfaceNames := collectInterfaceNames(interfaces)

	errors = append(errors, validateIPAddress(iface, name)...)                   // IP Address Validation
	errors = append(errors, validateIPv6Address(iface, name)...)                 // IPv6 Address Validation
	errors = append(errors, validateSubnet(iface, name)...)                      // Subnet Mask Validation
	errors = append(errors, validateMTU(iface, name)...)                         // MTU Validation
	errors = append(errors, validateTrack6(iface, validInterfaceNames, name)...) // Track6 Specific Validation

	return errors
}

// validateIPAddress validates the IP address of an interface.
func validateIPAddress(iface *model.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddr != "" {
		validIPTypes := []string{"dhcp", "dhcp6", "track6", "none"}
		if !contains(validIPTypes, iface.IPAddr) && !isValidIP(iface.IPAddr) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("interfaces.%s.ipaddr", name),
				Message: fmt.Sprintf(
					"IP address '%s' must be a valid IP address or one of: %v",
					iface.IPAddr,
					validIPTypes,
				),
			})
		}
	}
	return errors
}

// validateIPv6Address validates the IPv6 address of an interface.
func validateIPv6Address(iface *model.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddrv6 != "" {
		validIPv6Types := []string{"dhcp6", "slaac", "track6", "none"}
		if !contains(validIPv6Types, iface.IPAddrv6) && !isValidIPv6(iface.IPAddrv6) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("interfaces.%s.ipaddrv6", name),
				Message: fmt.Sprintf(
					"IPv6 address '%s' must be a valid IPv6 address or one of: %v",
					iface.IPAddrv6,
					validIPv6Types,
				),
			})
		}
	}
	return errors
}

// validateSubnet validates the subnet mask of an interface.
func validateSubnet(iface *model.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.Subnet != "" {
		if subnet, err := strconv.Atoi(iface.Subnet); err != nil || subnet < 0 || subnet > 32 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnet", name),
				Message: fmt.Sprintf("subnet mask '%s' must be a valid subnet mask (0-32)", iface.Subnet),
			})
		}
	}
	if iface.Subnetv6 != "" {
		if subnet, err := strconv.Atoi(iface.Subnetv6); err != nil || subnet < 0 || subnet > 128 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnetv6", name),
				Message: fmt.Sprintf("IPv6 subnet mask '%s' must be a valid IPv6 subnet mask (0-128)", iface.Subnetv6),
			})
		}
	}
	return errors
}

// validateMTU validates the MTU of an interface.
func validateMTU(iface *model.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.MTU != "" {
		if mtu, err := strconv.Atoi(iface.MTU); err != nil || mtu < 68 || mtu > 9000 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.mtu", name),
				Message: fmt.Sprintf("MTU '%s' must be a valid MTU (68-9000)", iface.MTU),
			})
		}
	}
	return errors
}

// validateTrack6 performs cross-field validation for track6 configurations.
func validateTrack6(iface *model.Interface, validInterfaceNames map[string]struct{}, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddrv6 == "track6" {
		if iface.Track6Interface == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-interface", name),
				Message: "track6-interface is required when using track6 IPv6 addressing",
			})
		} else {
			// Validate that the referenced interface exists
			if _, exists := validInterfaceNames[iface.Track6Interface]; !exists {
				// Create a sorted slice of interface names for error message
				interfaceList := make([]string, 0, len(validInterfaceNames))
				for interfaceName := range validInterfaceNames {
					interfaceList = append(interfaceList, interfaceName)
				}

				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("interfaces.%s.track6-interface", name),
					Message: fmt.Sprintf("track6-interface '%s' must reference a configured interface: %v", iface.Track6Interface, interfaceList),
				})
			}
		}

		if iface.Track6PrefixID == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-prefix-id", name),
				Message: "track6-prefix-id is required when using track6 IPv6 addressing",
			})
		}
	}
	return errors
}

// It iterates over the interface map and validates each DHCP block that exists in the dhcpd section.
// Returns a slice of ValidationError for any invalid or inconsistent DHCP configuration fields.
func validateDhcpd(dhcpd *model.Dhcpd, interfaces *model.Interfaces) []ValidationError {
	var errors []ValidationError

	if dhcpd == nil || dhcpd.Items == nil {
		return errors
	}

	// Get valid interface names for cross-validation
	ifaceSet := collectInterfaceNames(interfaces)

	// Validate each DHCP interface configuration
	for name, cfg := range dhcpd.Items {
		errors = append(errors, validateDhcpdInterface(name, cfg, ifaceSet)...)
	}

	return errors
}

// validateDhcpdInterface checks a DHCP interface configuration for validity, ensuring the referenced interface exists and that any specified DHCP range addresses are valid IPs with the 'from' address less than the 'to' address.
//
// Returns a slice of ValidationError for any detected issues.
func validateDhcpdInterface(name string, cfg model.DhcpdInterface, ifaceSet map[string]struct{}) []ValidationError {
	var errors []ValidationError

	// Validate that the interface exists in the configuration
	if _, exists := ifaceSet[name]; !exists {
		// Create a sorted slice of interface names for error message
		interfaceList := make([]string, 0, len(ifaceSet))
		for interfaceName := range ifaceSet {
			interfaceList = append(interfaceList, interfaceName)
		}

		errors = append(errors, ValidationError{
			Field:   "dhcpd." + name,
			Message: fmt.Sprintf("DHCP interface '%s' must reference a configured interface: %v", name, interfaceList),
		})
	}

	// Validate DHCP range if either from or to is set
	if cfg.Range.From != "" || cfg.Range.To != "" {
		if cfg.Range.From != "" && !isValidIP(cfg.Range.From) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("dhcpd.%s.range.from", name),
				Message: fmt.Sprintf("DHCP range 'from' address '%s' must be a valid IP address", cfg.Range.From),
			})
		}

		if cfg.Range.To != "" && !isValidIP(cfg.Range.To) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("dhcpd.%s.range.to", name),
				Message: fmt.Sprintf("DHCP range 'to' address '%s' must be a valid IP address", cfg.Range.To),
			})
		}

		// Cross-validation: from address should be less than to address
		if isValidIP(cfg.Range.From) && isValidIP(cfg.Range.To) {
			fromIP := net.ParseIP(cfg.Range.From).To4()

			toIP := net.ParseIP(cfg.Range.To).To4()
			if fromIP != nil && toIP != nil {
				// Compare byte by byte
				for i := range 4 {
					if fromIP[i] > toIP[i] {
						errors = append(errors, ValidationError{
							Field: fmt.Sprintf("dhcpd.%s.range", name),
							Message: fmt.Sprintf(
								"DHCP range 'from' address (%s) must be less than 'to' address (%s)",
								cfg.Range.From,
								cfg.Range.To,
							),
						})

						break
					} else if fromIP[i] < toIP[i] {
						break
					}
				}
			}
		}
	}

	return errors
}

// collectInterfaceNames returns every key from the interfaces map as a set.
func collectInterfaceNames(ifaces *model.Interfaces) map[string]struct{} {
	interfaceNames := make(map[string]struct{})

	if ifaces != nil && ifaces.Items != nil {
		for name := range ifaces.Items {
			interfaceNames[name] = struct{}{}
		}
	}

	return interfaceNames
}

// validateFilter checks each firewall filter rule for valid type, IP protocol, interface, and source network values.
// stripIPSuffix removes the trailing "ip" suffix from a network string, if present.
func stripIPSuffix(network string) string {
	if strings.HasSuffix(network, "ip") {
		return strings.TrimSuffix(network, "ip")
	}

	return network
}

// isReservedNetwork returns true if the provided network string is a reserved keyword such as "any", "lan", "wan", "localhost", "loopback", or "(self)".
func isReservedNetwork(network string) bool {
	reserved := []string{"any", "lan", "wan", "localhost", "loopback", "(self)"}
	return slices.Contains(reserved, network)
}

// validateFilter checks each firewall filter rule for valid types, protocols, interface references, and network specifications.
// It returns a list of validation errors for any rule fields that are invalid or reference non-existent interfaces.
func validateFilter(filter *model.Filter, interfaces *model.Interfaces) []ValidationError {
	var errors []ValidationError

	// Collect valid interface names from the configuration
	validInterfaceNames := collectInterfaceNames(interfaces)

	for i, rule := range filter.Rule {
		// Validate rule type
		validTypes := []string{"pass", "block", "reject"}
		if rule.Type != "" && !contains(validTypes, rule.Type) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].type", i),
				Message: fmt.Sprintf("rule type '%s' must be one of: %v", rule.Type, validTypes),
			})
		}

		// Validate IP protocol
		validIPProtocols := []string{"inet", "inet6"}
		if rule.IPProtocol != "" && !contains(validIPProtocols, rule.IPProtocol) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].ipprotocol", i),
				Message: fmt.Sprintf("IP protocol '%s' must be one of: %v", rule.IPProtocol, validIPProtocols),
			})
		}

		// Validate interface against configured interfaces
		if rule.Interface != "" {
			if _, exists := validInterfaceNames[rule.Interface]; !exists {
				// Create a sorted slice of interface names for error message
				interfaceList := make([]string, 0, len(validInterfaceNames))
				for name := range validInterfaceNames {
					interfaceList = append(interfaceList, name)
				}

				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("filter.rule[%d].interface", i),
					Message: fmt.Sprintf(
						"interface '%s' must be one of the configured interfaces: %v",
						rule.Interface,
						interfaceList,
					),
				})
			}
		}

		// Validate source network
		network := stripIPSuffix(rule.Source.Network)
		if rule.Source.Network != "" && !isReservedNetwork(network) && !isValidCIDR(rule.Source.Network) {
			if _, exists := validInterfaceNames[network]; !exists {
				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("filter.rule[%d].source.network", i),
					Message: fmt.Sprintf(
						"source network '%s' must be a valid CIDR, reserved word, or an interface key followed by 'ip'",
						rule.Source.Network,
					),
				})
			}
		}

		// Validate destination network
		destNetwork := stripIPSuffix(rule.Destination.Network)
		if rule.Destination.Network != "" && !isReservedNetwork(destNetwork) && !isValidCIDR(rule.Destination.Network) {
			if _, exists := validInterfaceNames[destNetwork]; !exists {
				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("filter.rule[%d].destination.network", i),
					Message: fmt.Sprintf(
						"destination network '%s' must be a valid CIDR, reserved word, or an interface key followed by 'ip'",
						rule.Destination.Network,
					),
				})
			}
		}
	}

	return errors
}

// validateNat checks that the NAT outbound mode is set to one of the allowed values: "automatic", "hybrid", "advanced", or "disabled".
// It returns a slice of ValidationError for any invalid mode detected.
func validateNat(nat *model.Nat) []ValidationError {
	var errors []ValidationError

	// Validate outbound NAT mode
	validModes := []string{"automatic", "hybrid", "advanced", "disabled"}
	if nat.Outbound.Mode != "" && !contains(validModes, nat.Outbound.Mode) {
		errors = append(errors, ValidationError{
			Field:   "nat.outbound.mode",
			Message: fmt.Sprintf("NAT outbound mode '%s' must be one of: %v", nat.Outbound.Mode, validModes),
		})
	}

	return errors
}

// validateUsersAndGroups checks system users and groups for required fields, uniqueness, valid IDs, valid scopes, and correct group references.
// It returns a slice of ValidationError for any invalid or inconsistent user or group entries.
func validateUsersAndGroups(system *model.System) []ValidationError {
	var errors []ValidationError

	// Track group names and GIDs to ensure uniqueness
	groupNames := make(map[string]bool)
	groupGIDs := make(map[string]bool)

	errors = append(errors, validateGroups(system.Group, groupNames, groupGIDs)...)
	errors = append(errors, validateUsers(system.User, groupNames)...)

	return errors
}

// validateGroups validates all groups and tracks names and GIDs for uniqueness.
func validateGroups(groups []model.Group, groupNames, groupGIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	for i, group := range groups {
		errors = append(errors, validateGroupName(group, i, groupNames)...)
		errors = append(errors, validateGroupGID(group, i, groupGIDs)...)
		errors = append(errors, validateGroupScope(group, i)...)
	}

	return errors
}

// validateGroupName validates group name requirements and uniqueness.
func validateGroupName(group model.Group, index int, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError

	switch {
	case group.Name == "":
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].name", index),
			Message: "group name is required",
		})
	case groupNames[group.Name]:
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].name", index),
			Message: fmt.Sprintf("group name '%s' must be unique", group.Name),
		})
	default:
		groupNames[group.Name] = true
	}

	return errors
}

// validateGroupGID validates group GID requirements and uniqueness.
func validateGroupGID(group model.Group, index int, groupGIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	if group.Gid == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: "group GID is required",
		})
		return errors
	}

	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: fmt.Sprintf("GID '%s' must be a positive integer", group.Gid),
		})
		return errors
	}

	if groupGIDs[group.Gid] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: fmt.Sprintf("group GID '%s' must be unique", group.Gid),
		})
		return errors
	}

	groupGIDs[group.Gid] = true
	return errors
}

// validateGroupScope validates group scope requirements.
func validateGroupScope(group model.Group, index int) []ValidationError {
	var errors []ValidationError

	if group.Scope == "" {
		return errors
	}

	validScopes := []string{"system", "local"}
	if !contains(validScopes, group.Scope) {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].scope", index),
			Message: fmt.Sprintf("group scope '%s' must be one of: %v", group.Scope, validScopes),
		})
	}

	return errors
}

// validateUsers validates all users.
func validateUsers(users []model.User, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError
	userNames := make(map[string]bool)
	userUIDs := make(map[string]bool)

	for i, user := range users {
		errors = append(errors, validateUserName(user, i, userNames)...)
		errors = append(errors, validateUserUID(user, i, userUIDs)...)
		errors = append(errors, validateUserGroupMembership(user, i, groupNames)...)
		errors = append(errors, validateUserScope(user, i)...)
	}

	return errors
}

// validateUserName validates user name requirements and uniqueness.
func validateUserName(user model.User, index int, userNames map[string]bool) []ValidationError {
	var errors []ValidationError

	switch {
	case user.Name == "":
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].name", index),
			Message: "user name is required",
		})
	case userNames[user.Name]:
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].name", index),
			Message: fmt.Sprintf("user name '%s' must be unique", user.Name),
		})
	default:
		userNames[user.Name] = true
	}

	return errors
}

// validateUserUID validates user UID requirements and uniqueness.
func validateUserUID(user model.User, index int, userUIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	if user.UID == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: "user UID is required",
		})
		return errors
	}

	uid, err := strconv.Atoi(user.UID)
	if err != nil || uid < 0 {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: fmt.Sprintf("UID '%s' must be a positive integer", user.UID),
		})
		return errors
	}

	if userUIDs[user.UID] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: fmt.Sprintf("user UID '%s' must be unique", user.UID),
		})
		return errors
	}

	userUIDs[user.UID] = true
	return errors
}

// validateUserGroupMembership validates user group membership.
func validateUserGroupMembership(user model.User, index int, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError

	if user.Groupname != "" && !groupNames[user.Groupname] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].groupname", index),
			Message: fmt.Sprintf("referenced group '%s' does not exist", user.Groupname),
		})
	}

	return errors
}

// validateUserScope validates user scope requirements.
func validateUserScope(user model.User, index int) []ValidationError {
	var errors []ValidationError

	if user.Scope == "" {
		return errors
	}

	validScopes := []string{"system", "local"}
	if !contains(validScopes, user.Scope) {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].scope", index),
			Message: fmt.Sprintf("user scope '%s' must be one of: %v", user.Scope, validScopes),
		})
	}

	return errors
}

// validateSysctl checks sysctl tunable items for required fields, uniqueness, valid naming format, and presence of values.
// It returns a slice of ValidationError for any missing, duplicate, or improperly formatted tunable names, or missing values.
func validateSysctl(items []model.SysctlItem) []ValidationError {
	var errors []ValidationError

	tunables := make(map[string]bool)

	for i, item := range items {
		// Tunable is required and must be unique
		switch {
		case item.Tunable == "":
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: "tunable name is required",
			})
		case tunables[item.Tunable]:
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: fmt.Sprintf("tunable name '%s' must be unique", item.Tunable),
			})
		default:
			tunables[item.Tunable] = true
		}

		// Validate tunable name format (basic validation)
		if item.Tunable != "" && !isValidSysctlName(item.Tunable) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: fmt.Sprintf("tunable name '%s' has invalid format", item.Tunable),
			})
		}

		// Value is required
		if item.Value == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].value", i),
				Message: "tunable value is required",
			})
		}
	}

	return errors
}

// Helper functions for validation

// contains reports whether a slice of strings contains a specified string.
func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

// isValidHostname returns true if the given string is a valid hostname according to length and character rules.
func isValidHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 {
		return false
	}
	// Basic hostname validation - allows letters, numbers, and hyphens
	matched, err := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`, hostname)
	if err != nil {
		return false
	}

	return matched
}

// isValidTimezone returns true if the given timezone string matches common timezone patterns such as "Region/City", "Etc/UTC", "UTC", or "GMT" with optional offset.
func isValidTimezone(timezone string) bool {
	// More restrictive timezone validation - common timezone patterns
	// Allow: America/New_York, Europe/London, Etc/UTC, UTC, GMT+/-offset
	validPatterns := []string{
		`^(America|Europe|Asia|Africa|Australia|Antarctica)/[A-Za-z_]+$`,
		`^Etc/(UTC|GMT[+-]?\d*)$`,
		`^UTC$`,
		`^GMT[+-]?\d*$`,
	}

	for _, pattern := range validPatterns {
		if matched, err := regexp.MatchString(pattern, timezone); err == nil && matched {
			return true
		}
	}

	return false
}

// isValidIP returns true if the input string is a valid IPv4 address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil
}

// isValidIPv6 returns true if the input string is a valid IPv6 address.
func isValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// isValidCIDR returns true if the input string is a valid CIDR notation, otherwise false.
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// isValidSysctlName returns true if the provided string is a valid sysctl tunable name, requiring it to start with a letter, contain only letters, digits, underscores, or dots, and include at least one dot.
func isValidSysctlName(name string) bool {
	// Basic sysctl name validation - allows dots, letters, numbers, and underscores
	matched, err := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9_.]*$`, name)
	if err != nil {
		return false
	}

	return matched && strings.Contains(name, ".")
}
