package builder

import (
	"strconv"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// MaxDescriptionLength is the maximum rune length for table cell descriptions.
const MaxDescriptionLength = 80

// TruncationEllipsisLen is the length of the "..." ellipsis used in truncation.
const TruncationEllipsisLen = 3

// TruncateString truncates a string to the specified maximum rune length.
// It is rune-aware to avoid splitting multi-byte UTF-8 characters.
// Unlike formatters.TruncateDescription which truncates at word boundaries,
// this function truncates at exact rune positions.
func TruncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= TruncationEllipsisLen {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-TruncationEllipsisLen]) + "..."
}

// Time unit constants for lease time formatting.
const (
	secondsPerMinute = 60
	secondsPerHour   = 3600
	secondsPerDay    = 86400
	secondsPerWeek   = 604800
)

// EscapeTableContent escapes content for safe display in markdown tables.
func (b *MarkdownBuilder) EscapeTableContent(content any) string {
	return formatters.EscapeTableContent(content)
}

// TruncateDescription truncates a description to the specified maximum length.
func (b *MarkdownBuilder) TruncateDescription(description string, maxLength int) string {
	return formatters.TruncateDescription(description, maxLength)
}

// IsLastInSlice checks if the given index is the last element in a slice or array.
func (b *MarkdownBuilder) IsLastInSlice(index int, slice any) bool {
	return formatters.IsLastInSlice(index, slice)
}

// DefaultValue returns the default value if the primary value is empty.
func (b *MarkdownBuilder) DefaultValue(value, defaultVal any) any {
	return formatters.DefaultValue(value, defaultVal)
}

// IsEmpty checks if a value is considered empty according to Go conventions.
func (b *MarkdownBuilder) IsEmpty(value any) bool {
	return formatters.IsEmpty(value)
}

// ToUpper converts a string to uppercase.
func (b *MarkdownBuilder) ToUpper(s string) string {
	return formatters.ToUpper(s)
}

// ToLower converts a string to lowercase.
func (b *MarkdownBuilder) ToLower(s string) string {
	return formatters.ToLower(s)
}

// TrimSpace removes leading and trailing whitespace from a string.
func (b *MarkdownBuilder) TrimSpace(s string) string {
	return formatters.TrimSpace(s)
}

// BoolToString converts a boolean value to a standardized string representation with emojis.
func (b *MarkdownBuilder) BoolToString(val bool) string {
	return formatters.BoolToString(val)
}

// FormatBytes formats a byte count as a human-readable string.
func (b *MarkdownBuilder) FormatBytes(bytes int64) string {
	return formatters.FormatBytes(bytes)
}

// SanitizeID converts a string to a valid HTML/markdown anchor ID.
func (b *MarkdownBuilder) SanitizeID(s string) string {
	return formatters.SanitizeID(s)
}

// AssessRiskLevel returns a consistent emoji + text representation.
func (b *MarkdownBuilder) AssessRiskLevel(severity string) string {
	return formatters.AssessRiskLevel(severity)
}

// CalculateSecurityScore computes an overall score (0-100).
func (b *MarkdownBuilder) CalculateSecurityScore(data *common.CommonDevice) int {
	return formatters.CalculateSecurityScore(data)
}

// AssessServiceRisk maps common services to risk levels.
func (b *MarkdownBuilder) AssessServiceRisk(serviceName string) string {
	return formatters.AssessServiceRisk(serviceName)
}

// FilterSystemTunables filters system tunables based on security-related prefixes.
func (b *MarkdownBuilder) FilterSystemTunables(tunables []common.SysctlItem, includeTunables bool) []common.SysctlItem {
	return formatters.FilterSystemTunables(tunables, includeTunables)
}

// AggregatePackageStats aggregates statistics about packages.
func (b *MarkdownBuilder) AggregatePackageStats(packages []common.Package) map[string]int {
	return formatters.AggregatePackageStats(packages)
}

// FilterRulesByType filters firewall rules by their type.
func (b *MarkdownBuilder) FilterRulesByType(
	rules []common.FirewallRule,
	ruleType common.FirewallRuleType,
) []common.FirewallRule {
	return formatters.FilterRulesByType(rules, ruleType)
}

// ExtractUniqueValues extracts unique values from a slice of strings.
func (b *MarkdownBuilder) ExtractUniqueValues(items []string) []string {
	return formatters.ExtractUniqueValues(items)
}

// FormatLeaseTime converts DHCP lease time seconds to human-readable format.
// Empty string or "0" returns "-".
// Invalid input returns the original string.
// Examples:
//   - "" → "-"
//   - "0" → "-"
//   - "3600" → "1 hour"
//   - "7200" → "2 hours"
//   - "86400" → "1 day"
//   - "172800" → "2 days"
//   - "604800" → "1 week"
//   - "1209600" → "2 weeks"
//   - "5400" → "1 hour, 30 minutes"
func FormatLeaseTime(seconds string) string {
	if seconds == "" || seconds == "0" {
		return "-"
	}

	secs, err := strconv.Atoi(seconds)
	if err != nil {
		return seconds
	}

	if secs <= 0 {
		return "-"
	}

	return formatDuration(secs)
}

// formatDuration converts seconds to a human-readable duration string.
func formatDuration(totalSeconds int) string {
	if totalSeconds >= secondsPerWeek {
		weeks := totalSeconds / secondsPerWeek
		remainder := totalSeconds % secondsPerWeek
		if remainder == 0 {
			return pluralize(weeks, "week")
		}
		return pluralize(weeks, "week") + ", " + formatDuration(remainder)
	}

	if totalSeconds >= secondsPerDay {
		days := totalSeconds / secondsPerDay
		remainder := totalSeconds % secondsPerDay
		if remainder == 0 {
			return pluralize(days, "day")
		}
		return pluralize(days, "day") + ", " + formatDuration(remainder)
	}

	if totalSeconds >= secondsPerHour {
		hours := totalSeconds / secondsPerHour
		remainder := totalSeconds % secondsPerHour
		if remainder == 0 {
			return pluralize(hours, "hour")
		}
		return pluralize(hours, "hour") + ", " + formatDuration(remainder)
	}

	if totalSeconds >= secondsPerMinute {
		minutes := totalSeconds / secondsPerMinute
		remainder := totalSeconds % secondsPerMinute
		if remainder == 0 {
			return pluralize(minutes, "minute")
		}
		return pluralize(minutes, "minute") + ", " + pluralize(remainder, "second")
	}

	return pluralize(totalSeconds, "second")
}

// pluralize returns the singular or plural form of a unit based on the count.
func pluralize(count int, unit string) string {
	if count == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(count) + " " + unit + "s"
}

// HasAdvancedDHCPConfig checks if any advanced DHCPv4 fields are populated in a DHCPScope.
func HasAdvancedDHCPConfig(dhcp common.DHCPScope) bool {
	if dhcp.AdvancedV4 == nil {
		return false
	}

	v4 := dhcp.AdvancedV4

	return v4.AliasAddress != "" || v4.AliasSubnet != "" || v4.DHCPRejectFrom != "" ||
		v4.AdvDHCPPTTimeout != "" ||
		v4.AdvDHCPPTRetry != "" ||
		v4.AdvDHCPPTSelectTimeout != "" ||
		v4.AdvDHCPPTReboot != "" ||
		v4.AdvDHCPPTBackoffCutoff != "" ||
		v4.AdvDHCPPTInitialInterval != "" ||
		v4.AdvDHCPPTValues != "" ||
		v4.AdvDHCPSendOptions != "" ||
		v4.AdvDHCPRequestOptions != "" ||
		v4.AdvDHCPRequiredOptions != "" ||
		v4.AdvDHCPOptionModifiers != "" ||
		v4.AdvDHCPConfigAdvanced != "" ||
		v4.AdvDHCPConfigFileOverride != "" ||
		v4.AdvDHCPConfigFileOverridePath != ""
}

// HasDHCPv6Config checks if any DHCPv6 fields are populated in a DHCPScope.
//
//nolint:cyclop // flat disjunction over 27 DHCPv6 schema fields; each || is one branch but the intent is a single "any field populated?" check
func HasDHCPv6Config(dhcp common.DHCPScope) bool {
	if dhcp.AdvancedV6 == nil {
		return false
	}

	v6 := dhcp.AdvancedV6

	return v6.Track6Interface != "" || v6.Track6PrefixID != "" ||
		v6.AdvDHCP6InterfaceStatementSendOptions != "" ||
		v6.AdvDHCP6InterfaceStatementRequestOptions != "" ||
		v6.AdvDHCP6InterfaceStatementInformationOnlyEnable != "" ||
		v6.AdvDHCP6InterfaceStatementScript != "" ||
		v6.AdvDHCP6IDAssocStatementAddressEnable != "" ||
		v6.AdvDHCP6IDAssocStatementAddress != "" ||
		v6.AdvDHCP6IDAssocStatementAddressID != "" ||
		v6.AdvDHCP6IDAssocStatementAddressPLTime != "" ||
		v6.AdvDHCP6IDAssocStatementAddressVLTime != "" ||
		v6.AdvDHCP6IDAssocStatementPrefixEnable != "" ||
		v6.AdvDHCP6IDAssocStatementPrefix != "" ||
		v6.AdvDHCP6IDAssocStatementPrefixID != "" ||
		v6.AdvDHCP6IDAssocStatementPrefixPLTime != "" ||
		v6.AdvDHCP6IDAssocStatementPrefixVLTime != "" ||
		v6.AdvDHCP6PrefixInterfaceStatementSLALen != "" ||
		v6.AdvDHCP6AuthenticationStatementAuthName != "" ||
		v6.AdvDHCP6AuthenticationStatementProtocol != "" ||
		v6.AdvDHCP6AuthenticationStatementAlgorithm != "" ||
		v6.AdvDHCP6AuthenticationStatementRDM != "" ||
		v6.AdvDHCP6KeyInfoStatementKeyName != "" ||
		v6.AdvDHCP6KeyInfoStatementRealm != "" ||
		v6.AdvDHCP6KeyInfoStatementKeyID != "" ||
		v6.AdvDHCP6KeyInfoStatementSecret != "" ||
		v6.AdvDHCP6KeyInfoStatementExpire != "" ||
		v6.AdvDHCP6ConfigAdvanced != "" ||
		v6.AdvDHCP6ConfigFileOverride != "" ||
		v6.AdvDHCP6ConfigFileOverridePath != ""
}

// dhcpItem formats one advanced-DHCP bullet item. The value comes from
// config.xml, so it is escaped: these items go to markdown.BulletList, which
// passes content through verbatim, and an unescaped newline followed by "## "
// injects a fabricated heading and body into the report.
func dhcpItem(label, value string) string {
	return label + ": " + formatters.EscapeMarkdownValue(value)
}

// buildAdvancedDHCPItems builds a list of advanced DHCP configuration items for display.
func buildAdvancedDHCPItems(dhcp common.DHCPScope) []string {
	if dhcp.AdvancedV4 == nil {
		return make([]string, 0)
	}

	v4 := dhcp.AdvancedV4
	items := make([]string, 0)

	if v4.AliasAddress != "" {
		items = append(items, dhcpItem("Alias Address", v4.AliasAddress))
	}
	if v4.AliasSubnet != "" {
		items = append(items, dhcpItem("Alias Subnet", v4.AliasSubnet))
	}
	if v4.DHCPRejectFrom != "" {
		items = append(items, dhcpItem("DHCP Reject From", v4.DHCPRejectFrom))
	}
	if v4.AdvDHCPPTTimeout != "" {
		items = append(items, dhcpItem("Protocol Timeout", v4.AdvDHCPPTTimeout))
	}
	if v4.AdvDHCPPTRetry != "" {
		items = append(items, dhcpItem("Protocol Retry", v4.AdvDHCPPTRetry))
	}
	if v4.AdvDHCPPTSelectTimeout != "" {
		items = append(items, dhcpItem("Select Timeout", v4.AdvDHCPPTSelectTimeout))
	}
	if v4.AdvDHCPPTReboot != "" {
		items = append(items, dhcpItem("Reboot", v4.AdvDHCPPTReboot))
	}
	if v4.AdvDHCPPTBackoffCutoff != "" {
		items = append(items, dhcpItem("Backoff Cutoff", v4.AdvDHCPPTBackoffCutoff))
	}
	if v4.AdvDHCPPTInitialInterval != "" {
		items = append(items, dhcpItem("Initial Interval", v4.AdvDHCPPTInitialInterval))
	}
	if v4.AdvDHCPPTValues != "" {
		items = append(items, dhcpItem("PT Values", v4.AdvDHCPPTValues))
	}
	if v4.AdvDHCPSendOptions != "" {
		items = append(items, dhcpItem("Send Options", v4.AdvDHCPSendOptions))
	}
	if v4.AdvDHCPRequestOptions != "" {
		items = append(items, dhcpItem("Request Options", v4.AdvDHCPRequestOptions))
	}
	if v4.AdvDHCPRequiredOptions != "" {
		items = append(items, dhcpItem("Required Options", v4.AdvDHCPRequiredOptions))
	}
	if v4.AdvDHCPOptionModifiers != "" {
		items = append(items, dhcpItem("Option Modifiers", v4.AdvDHCPOptionModifiers))
	}
	if v4.AdvDHCPConfigAdvanced != "" {
		items = append(items, "Advanced Config: Enabled")
	}
	if v4.AdvDHCPConfigFileOverride != "" {
		items = append(items, "Config File Override: Enabled")
	}
	if v4.AdvDHCPConfigFileOverridePath != "" {
		items = append(items, dhcpItem("Override Path", v4.AdvDHCPConfigFileOverridePath))
	}

	return items
}

// buildDHCPv6Items builds a list of DHCPv6 configuration items for display.
//
//nolint:cyclop // per-field presence checks over 28 DHCPv6 schema fields; factoring by subsystem (Track6/IDAssoc/Auth/KeyInfo) would obscure the field ordering that matches the OPNsense UI form
func buildDHCPv6Items(dhcp common.DHCPScope) []string {
	if dhcp.AdvancedV6 == nil {
		return make([]string, 0)
	}

	v6 := dhcp.AdvancedV6
	items := make([]string, 0)

	if v6.Track6Interface != "" {
		items = append(items, dhcpItem("Track6 Interface", v6.Track6Interface))
	}
	if v6.Track6PrefixID != "" {
		items = append(items, dhcpItem("Track6 Prefix ID", v6.Track6PrefixID))
	}
	if v6.AdvDHCP6InterfaceStatementSendOptions != "" {
		items = append(items, dhcpItem("Send Options", v6.AdvDHCP6InterfaceStatementSendOptions))
	}
	if v6.AdvDHCP6InterfaceStatementRequestOptions != "" {
		items = append(items, dhcpItem("Request Options", v6.AdvDHCP6InterfaceStatementRequestOptions))
	}
	if v6.AdvDHCP6InterfaceStatementInformationOnlyEnable != "" {
		items = append(items, "Information Only: Enabled")
	}
	if v6.AdvDHCP6InterfaceStatementScript != "" {
		items = append(items, dhcpItem("Script", v6.AdvDHCP6InterfaceStatementScript))
	}
	if v6.AdvDHCP6IDAssocStatementAddressEnable != "" {
		items = append(items, "ID Assoc Address: Enabled")
	}
	if v6.AdvDHCP6IDAssocStatementAddress != "" {
		items = append(items, dhcpItem("Address", v6.AdvDHCP6IDAssocStatementAddress))
	}
	if v6.AdvDHCP6IDAssocStatementAddressID != "" {
		items = append(items, dhcpItem("Address ID", v6.AdvDHCP6IDAssocStatementAddressID))
	}
	if v6.AdvDHCP6IDAssocStatementAddressPLTime != "" {
		items = append(items, dhcpItem("Address Preferred Lifetime", v6.AdvDHCP6IDAssocStatementAddressPLTime))
	}
	if v6.AdvDHCP6IDAssocStatementAddressVLTime != "" {
		items = append(items, dhcpItem("Address Valid Lifetime", v6.AdvDHCP6IDAssocStatementAddressVLTime))
	}
	if v6.AdvDHCP6IDAssocStatementPrefixEnable != "" {
		items = append(items, "ID Assoc Prefix: Enabled")
	}
	if v6.AdvDHCP6IDAssocStatementPrefix != "" {
		items = append(items, dhcpItem("Prefix", v6.AdvDHCP6IDAssocStatementPrefix))
	}
	if v6.AdvDHCP6IDAssocStatementPrefixID != "" {
		items = append(items, dhcpItem("Prefix ID", v6.AdvDHCP6IDAssocStatementPrefixID))
	}
	if v6.AdvDHCP6IDAssocStatementPrefixPLTime != "" {
		items = append(items, dhcpItem("Prefix Preferred Lifetime", v6.AdvDHCP6IDAssocStatementPrefixPLTime))
	}
	if v6.AdvDHCP6IDAssocStatementPrefixVLTime != "" {
		items = append(items, dhcpItem("Prefix Valid Lifetime", v6.AdvDHCP6IDAssocStatementPrefixVLTime))
	}
	if v6.AdvDHCP6PrefixInterfaceStatementSLALen != "" {
		items = append(items, dhcpItem("SLA Length", v6.AdvDHCP6PrefixInterfaceStatementSLALen))
	}
	if v6.AdvDHCP6AuthenticationStatementAuthName != "" {
		items = append(items, dhcpItem("Auth Name", v6.AdvDHCP6AuthenticationStatementAuthName))
	}
	if v6.AdvDHCP6AuthenticationStatementProtocol != "" {
		items = append(items, dhcpItem("Auth Protocol", v6.AdvDHCP6AuthenticationStatementProtocol))
	}
	if v6.AdvDHCP6AuthenticationStatementAlgorithm != "" {
		items = append(items, dhcpItem("Auth Algorithm", v6.AdvDHCP6AuthenticationStatementAlgorithm))
	}
	if v6.AdvDHCP6AuthenticationStatementRDM != "" {
		items = append(items, dhcpItem("Auth RDM", v6.AdvDHCP6AuthenticationStatementRDM))
	}
	if v6.AdvDHCP6KeyInfoStatementKeyName != "" {
		items = append(items, dhcpItem("Key Name", v6.AdvDHCP6KeyInfoStatementKeyName))
	}
	if v6.AdvDHCP6KeyInfoStatementRealm != "" {
		items = append(items, dhcpItem("Key Realm", v6.AdvDHCP6KeyInfoStatementRealm))
	}
	if v6.AdvDHCP6KeyInfoStatementKeyID != "" {
		items = append(items, dhcpItem("Key ID", v6.AdvDHCP6KeyInfoStatementKeyID))
	}
	if v6.AdvDHCP6KeyInfoStatementSecret != "" {
		items = append(items, dhcpItem("Key Secret", v6.AdvDHCP6KeyInfoStatementSecret))
	}
	if v6.AdvDHCP6KeyInfoStatementExpire != "" {
		items = append(items, dhcpItem("Key Expire", v6.AdvDHCP6KeyInfoStatementExpire))
	}
	if v6.AdvDHCP6ConfigAdvanced != "" {
		items = append(items, "Advanced Config: Enabled")
	}
	if v6.AdvDHCP6ConfigFileOverride != "" {
		items = append(items, "Config File Override: Enabled")
	}
	if v6.AdvDHCP6ConfigFileOverridePath != "" {
		items = append(items, dhcpItem("Override Path", v6.AdvDHCP6ConfigFileOverridePath))
	}

	return items
}
