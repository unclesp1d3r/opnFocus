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
// siblings, redacting the literal "hmac-md5" the audit engine reads. The
// siblings may still match other rules in aggressive mode (hostname claims
// anything containing "domain"), so this asserts only that private_key never
// takes them.
func TestShouldRedactField_DDNSDomainKeySiblings(t *testing.T) {
	t.Parallel()

	siblings := []string{
		"ddnsdomainkeyname",
		"ddnsdomainkeyalgorithm",
		"dhcpd.lan.ddnsdomainkeyname",
		"dhcpd.lan.ddnsdomainkeyalgorithm",
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
			})
		}
	}
}

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
