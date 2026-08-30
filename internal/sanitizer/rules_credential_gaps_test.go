package sanitizer

import (
	"testing"
)

// Tests for the two credential gaps closed alongside the terminal-segment
// anchoring in fieldNameMatches: a bare ldap_bindpw outside the authserver
// path, and the pfSense DHCP dynamic-DNS TSIG key.

const testTSIGKey = "aGVsbG8gd29ybGQgc2VjcmV0"

// TestRedact_LDAPBindPW covers the leak directly. "ldap_bindpw" contains none
// of the password rule's other patterns ("pwd" does not appear in it), so
// before the "bindpw" pattern was added the value was emitted verbatim
// wherever authserver_config's path patterns did not reach it.
func TestRedact_LDAPBindPW(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "ldap_bindpw"},
		{ModeModerate, "ldap_bindpw"},
		{ModeMinimal, "ldap_bindpw"},
		{ModeAggressive, "system.ldap_bindpw"},
		{ModeModerate, "system.ldap_bindpw"},
		{ModeMinimal, "system.ldap_bindpw"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)

			should, rule := engine.ShouldRedactField(tt.field)
			if !should {
				t.Fatalf("ShouldRedactField(%q) = false, want true", tt.field)
			}
			if rule.Name != "password" {
				t.Fatalf("ShouldRedactField(%q) matched %q, want password", tt.field, rule.Name)
			}

			result := engine.Redact(tt.field, "SuperSecret123")
			if result != expectedRedactedPassValue {
				t.Errorf("Redact(%q, bind password) = %q, want %q", tt.field, result, expectedRedactedPassValue)
			}
		})
	}
}

// TestRedact_LDAPBindPW_AuthserverPathUnchanged pins the other half: the
// nested path must still reach authserver_config and be pseudonymized rather
// than flat-redacted by the new password pattern.
func TestRedact_LDAPBindPW_AuthserverPathUnchanged(t *testing.T) {
	t.Parallel()

	const field = "system.authserver.ldap_bindpw"

	for _, mode := range []Mode{ModeAggressive, ModeModerate, ModeMinimal} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(mode)

			should, rule := engine.ShouldRedactField(field)
			if !should {
				t.Fatalf("ShouldRedactField(%q) = false, want true", field)
			}
			if rule.Name != "authserver_config" {
				t.Fatalf("ShouldRedactField(%q) matched %q, want authserver_config", field, rule.Name)
			}

			result := engine.Redact(field, "SuperSecret123")
			if result == "SuperSecret123" {
				t.Errorf("Redact(%q, bind password) left the value unchanged", field)
			}
			if result == expectedRedactedPassValue {
				t.Errorf("Redact(%q, ...) = %q, want a pseudonym, not the flat password placeholder", field, result)
			}
		})
	}
}

// TestRedact_DDNSDomainKey covers the pfSense DHCP dynamic-DNS TSIG key, a
// shared HMAC secret that no rule claimed before.
func TestRedact_DDNSDomainKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "ddnsdomainkey"},
		{ModeModerate, "ddnsdomainkey"},
		{ModeMinimal, "ddnsdomainkey"},
		{ModeAggressive, "dhcpd.lan.ddnsdomainkey"},
		{ModeModerate, "dhcpd.lan.ddnsdomainkey"},
		{ModeMinimal, "dhcpd.lan.ddnsdomainkey"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)

			should, rule := engine.ShouldRedactField(tt.field)
			if !should {
				t.Fatalf("ShouldRedactField(%q) = false, want true", tt.field)
			}
			if rule.Name != "private_key" {
				t.Fatalf("ShouldRedactField(%q) matched %q, want private_key", tt.field, rule.Name)
			}

			result := engine.Redact(tt.field, testTSIGKey)
			if result != "[REDACTED-PRIVATE-KEY]" {
				t.Errorf("Redact(%q, TSIG key) = %q, want %q", tt.field, result, "[REDACTED-PRIVATE-KEY]")
			}
		})
	}
}

// TestShouldRedactField_DDNSDomainKeySiblings guards the reason ddnsdomainkey
// is an exact-match pattern. As a substring it would also swallow its
// siblings, redacting the literal "hmac-md5" the audit engine reads.
//
// It also pins the fix for the hostname rule claiming those same siblings.
// All three sibling names contain "domain", which the hostname rule lists as
// a FieldPattern and matches as a substring, and a field-name match redacts
// unconditionally (GOTCHAS 14.2). In aggressive mode that turned the literal
// TSIG algorithm name into a pseudonymised host. The hostname rule now
// carries FieldExclusions for these fields, so the value survives in every
// mode.
func TestShouldRedactField_DDNSDomainKeySiblings(t *testing.T) {
	t.Parallel()

	siblings := []string{
		"ddnsdomainkeyname",
		"ddnsdomainkeyalgorithm",
		"ddnsdomainalgorithm",
		"dhcpd.lan.ddnsdomainkeyname",
		"dhcpd.lan.ddnsdomainkeyalgorithm",
		"dhcpd.lan.ddnsdomainalgorithm",
	}

	for _, mode := range []Mode{ModeAggressive, ModeModerate, ModeMinimal} {
		for _, field := range siblings {
			t.Run(string(mode)+"_"+field, func(t *testing.T) {
				t.Parallel()
				engine := NewRuleEngine(mode)

				_, rule := engine.ShouldRedactField(field)
				if rule.Name == "private_key" {
					t.Errorf("ShouldRedactField(%q) matched private_key, want the exact-match guard to hold", field)
				}

				// Assert on the emitted value, not just the rule name. A
				// weaker assertion would also pass if some other rule rewrote
				// the value, which is what the hostname rule used to do in
				// aggressive mode. The value must now survive in every mode.
				got := engine.Redact(field, siblingProbeValue)
				want := siblingProbeValue

				if got != want {
					t.Errorf("Redact(%q, %q) in %s = %q, want %q",
						field, siblingProbeValue, mode, got, want)
				}
			})
		}
	}
}

// siblingProbeValue is the literal TSIG algorithm name the audit engine reads
// from <ddnsdomainkeyalgorithm>. It is deliberately not hostname-shaped.
const siblingProbeValue = "hmac-md5"

// TestTerminalSegment covers the anchoring helper directly, including the
// slice index the reflection path appends.
func TestTerminalSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		field string
		want  string
	}{
		{"key", "key"},
		{"system.key", "key"},
		{"opnsense.system.key", "key"},
		{"apikeys[0]", "apikeys"},
		{"system.apikeys[0]", "apikeys"},
		{"system.apikeys[12]", "apikeys"},
		{"ddnsdomainkeyalgorithm", "ddnsdomainkeyalgorithm"},
		{"dhcpd.lan.ddnsdomainkey", "ddnsdomainkey"},
		{"", ""},
		{"[0]", ""},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			t.Parallel()
			if got := terminalSegment(tt.field); got != tt.want {
				t.Errorf("terminalSegment(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

// TestFieldNameMatches_TerminalSegmentAnchoring pins why "exact" is anchored on
// the last path segment rather than the whole string: sanitizeCharData looks up
// the full dotted path before the bare element name, and the reflection path
// only ever passes a dotted path, so a whole-string comparison could never win
// the full-path lookup.
func TestFieldNameMatches_TerminalSegmentAnchoring(t *testing.T) {
	t.Parallel()

	tests := []struct {
		field   string
		pattern string
		want    bool
	}{
		{"key", "key", true},
		{"system.key", "key", true},
		{"opnsense.system.key", "key", true},
		{"sshkey", "key", false},
		{"system.sshkey", "key", false},
		{"apikeys[0]", "key", false},
		{"dhcpd.lan.range.from", "from", true},
		{"platformfrom", "from", false},
		{"dhcpd.lan.ddnsdomainkey", "ddnsdomainkey", true},
		{"dhcpd.lan.ddnsdomainkeyalgorithm", "ddnsdomainkey", false},
		{"system.ldap_bindpw", "bindpw", true},
	}

	for _, tt := range tests {
		t.Run(tt.field+"_"+tt.pattern, func(t *testing.T) {
			t.Parallel()
			if got := fieldNameMatches(tt.field, tt.pattern); got != tt.want {
				t.Errorf("fieldNameMatches(%q, %q) = %v, want %v", tt.field, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestAggressiveMode_HostnameCoverageUnchanged pins the redaction the TSIG
// field exclusions must not narrow. Every <hostname> value in testdata is a
// single label with no dot ("firewall", "OPNsense"), and IsHostname requires a
// dot, so a value-shaped guard on the hostname rule would have released all of
// them in aggressive mode. The exclusions are keyed on the field name for
// exactly that reason.
func TestAggressiveMode_HostnameCoverageUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		field string
		value string
	}{
		{"hostname", "firewall"},
		{"hostname", "OPNsense"},
		{"hostname", "fw.example.com"},
		{"domain", "example.com"},
		{"domain", "localdomain"},
		{"ddnsdomain", "dyn.example.com"},
		{"ddnsdomainprimary", "ns1.example.com"},
		{"domainsearchlist", "corp.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.field+"_"+tt.value, func(t *testing.T) {
			t.Parallel()

			engine := NewRuleEngine(ModeAggressive)

			got := engine.Redact(tt.field, tt.value)
			if got != expectedMappedHostname1 {
				t.Errorf("Redact(%q, %q) in aggressive = %q, want %q",
					tt.field, tt.value, got, expectedMappedHostname1)
			}
		})
	}
}

// TestAggressiveMode_ExcludedTSIGFieldStillRedactsHostname pins the residual
// safety net. A field exclusion suppresses only the unconditional field-name
// claim; ShouldRedactValue still runs its value-detector pass afterward, and
// the hostname rule's ValueDetector is in it. So the exclusions release TSIG
// algorithm names without releasing a hostname an operator stored in one of
// these fields.
func TestAggressiveMode_ExcludedTSIGFieldStillRedactsHostname(t *testing.T) {
	t.Parallel()

	excluded := []string{
		"ddnsdomainkeyname",
		"ddnsdomainkeyalgorithm",
		"ddnsdomainalgorithm",
	}

	for _, field := range excluded {
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			engine := NewRuleEngine(ModeAggressive)

			got := engine.Redact(field, "tsig-key.internal.example.com")
			if got != expectedMappedHostname1 {
				t.Errorf("Redact(%q, hostname-shaped value) in aggressive = %q, want %q",
					field, got, expectedMappedHostname1)
			}
		})
	}
}
