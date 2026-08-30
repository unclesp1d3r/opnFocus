package sanitizer

import (
	"testing"
)

// Tests for field-pattern-based rules: exact-match patterns, aggressive-mode
// network/identity rules, mode restrictions, and guard behavior.

func TestFieldNameMatches_KeyExactMatch(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// Exact "key" field must be redacted (matched by private_key rule).
	result := engine.Redact("key", "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg=\n-----END PRIVATE KEY-----")
	if result == "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg=\n-----END PRIVATE KEY-----" {
		t.Error("Redact('key', privateKey) should redact")
	}

	// Compound names containing "key" as a substring must NOT match the "key"
	// exact-match pattern. Use names that don't match any other rule's patterns.
	compoundNames := []string{"monkeybar", "keychain", "hotkey", "keystone"}
	for _, name := range compoundNames {
		plain := "some-plain-value"
		got := engine.Redact(name, plain)
		if got != plain {
			t.Errorf(
				"Redact(%q, %q) = %q, want unchanged (compound name should not match 'key' pattern)",
				name,
				plain,
				got,
			)
		}
	}
}

func TestFieldNameMatches_FromToExactMatch(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// Compound names containing "from"/"to" as substrings must NOT match.
	compoundNames := []string{"timeout", "protocol", "platformfrom", "migratedfrom", "factory"}
	for _, name := range compoundNames {
		plain := "some-plain-value"
		got := engine.Redact(name, plain)
		if got != plain {
			t.Errorf(
				"Redact(%q, %q) = %q, want unchanged (compound name should not match exact-match pattern)",
				name,
				plain,
				got,
			)
		}
	}

	// Exact "from" and "to" with IP values should still redact.
	result := engine.Redact("from", "192.168.1.1")
	if result == "192.168.1.1" {
		t.Error("Redact('from', '192.168.1.1') should redact an IP value")
	}
	result = engine.Redact("to", "8.8.8.8")
	if result == "8.8.8.8" {
		t.Error("Redact('to', '8.8.8.8') should redact an IP value")
	}
}

func TestRedact_SubnetField_NonCIDRValue(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// A "subnet" field holding a non-CIDR value must never be redacted as a
	// subnet. It may still be claimed by a later rule: FieldGuard declines the
	// match rather than consuming it, so scanning continues. That is the point
	// of the guard, and these two cases show both outcomes.
	for _, val := range []string{"office network", "24", ""} {
		if result := engine.Redact("subnet", val); result != val {
			t.Errorf("Redact('subnet', %q) = %q, want unchanged", val, result)
		}
	}

	// "255.255.255.0" is a netmask, not a CIDR, so subnet_field declines it --
	// and the value-based public-IP rule then claims it, exactly as it already
	// did in moderate mode. Before FieldGuard, subnet_field consumed the match
	// and returned the value untouched, so aggressive leaked a value moderate
	// redacted. Asserting the redaction here is what pins that fix.
	if got := engine.Redact("subnet", "255.255.255.0"); got == "255.255.255.0" {
		t.Errorf("Redact('subnet', '255.255.255.0') = %q, want it claimed by the public-IP rule", got)
	}
	if got := NewRuleEngine(ModeModerate).Redact("subnet", "255.255.255.0"); got == "255.255.255.0" {
		t.Errorf("moderate must redact it too, else the monotonicity premise is wrong; got %q", got)
	}

	// A real CIDR is still redacted as a subnet.
	result := engine.Redact("subnet", "192.168.1.0/24")
	if result != "[REDACTED-SUBNET]" {
		t.Errorf("Redact('subnet', '192.168.1.0/24') = %q, want '[REDACTED-SUBNET]'", result)
	}
}

func TestRedact_OTPSeed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "otp_seed"},
		{ModeModerate, "otp_seed"},
		{ModeMinimal, "otp_seed"},
		{ModeAggressive, "otpseed"},
		{ModeModerate, "otpseed"},
		{ModeMinimal, "otpseed"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			result := engine.Redact(tt.field, "TOTP_BASE32_SEED")
			if result != redactedSecretValue {
				t.Errorf("Redact(%q, otp seed) = %q, want %q", tt.field, result, redactedSecretValue)
			}
		})
	}
}

func TestRedact_NetBirdSetupKey_RedactsSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "setupKey"},
		{ModeModerate, "setupKey"},
		{ModeMinimal, "setupKey"},
		{ModeAggressive, "setup_key"},
		{ModeModerate, "setup_key"},
		{ModeMinimal, "setup_key"},
		{ModeAggressive, "setup-key"},
		{ModeModerate, "setup-key"},
		{ModeMinimal, "setup-key"},
		{ModeAggressive, "OPNsense.netbird.authentication.setupKey"},
		{ModeMinimal, "netbird.authentication.setupKey"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			should, rule := engine.ShouldRedactField(tt.field)
			if !should {
				t.Fatalf("ShouldRedactField(%q) = false, want true", tt.field)
			}
			if rule.Name != "secret" {
				t.Fatalf("ShouldRedactField(%q) matched %q, want secret (not private_key)", tt.field, rule.Name)
			}
			result := engine.Redact(tt.field, "A1B2C3D4-E5F6-7890-ABCD-EF1234567890")
			if result != redactedSecretValue {
				t.Errorf("Redact(%q, setup key) = %q, want %q", tt.field, result, redactedSecretValue)
			}
		})
	}
}

func TestRedact_KeyField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode Mode
	}{
		{ModeAggressive},
		{ModeModerate},
		{ModeMinimal},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			result := engine.Redact("key", "some-key-value")
			if result != "[REDACTED-PRIVATE-KEY]" {
				t.Errorf("Redact(%q, key value) = %q, want %q", "key", result, "[REDACTED-PRIVATE-KEY]")
			}
		})
	}
}

func TestRedact_DomainField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "hostname"},
		{ModeModerate, "hostname"},
		{ModeMinimal, "hostname"},
		{ModeAggressive, "domain"},
		{ModeModerate, "domain"},
		{ModeMinimal, "domain"},
		{ModeAggressive, "althostnames"},
		{ModeModerate, "althostnames"},
		{ModeMinimal, "althostnames"},
		{ModeAggressive, "hostnames"},
		{ModeModerate, "hostnames"},
		{ModeMinimal, "hostnames"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			value := "fw.corp.local"
			result := engine.Redact(tt.field, value)

			if tt.mode == ModeAggressive {
				if result == value {
					t.Errorf("Redact(%q, %q) = %q, want redacted value", tt.field, value, result)
				}
				if result != expectedMappedHostname1 {
					t.Errorf("Redact(%q, %q) = %q, want %q", tt.field, value, result, expectedMappedHostname1)
				}
				return
			}

			if result != value {
				t.Errorf("Redact(%q, %q) = %q, want unchanged", tt.field, value, result)
			}
		})
	}
}

func TestRedact_MacFieldPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode         Mode
		wantRedacted bool
	}{
		{ModeAggressive, true},
		{ModeModerate, true},
		{ModeMinimal, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			value := "00:11:22:33:44:55"
			result := engine.Redact("mac", value)

			if tt.wantRedacted {
				if result != "XX:XX:XX:XX:XX:01" {
					t.Errorf("Redact(%q, %q) = %q, want %q", "mac", value, result, "XX:XX:XX:XX:XX:01")
				}
				return
			}

			if result != value {
				t.Errorf("Redact(%q, %q) = %q, want unchanged", "mac", value, result)
			}
		})
	}
}

func TestRedact_EmailFieldPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode         Mode
		wantRedacted bool
	}{
		{ModeAggressive, true},
		{ModeModerate, true},
		{ModeMinimal, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			value := "admin@company.com"
			result := engine.Redact("email", value)

			if tt.wantRedacted {
				if result != expectedMappedEmail1 {
					t.Errorf("Redact(%q, %q) = %q, want %q", "email", value, result, expectedMappedEmail1)
				}
				return
			}

			if result != value {
				t.Errorf("Redact(%q, %q) = %q, want unchanged", "email", value, result)
			}
		})
	}
}

func TestRedact_Endpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "endpoint"},
		{ModeModerate, "endpoint"},
		{ModeMinimal, "endpoint"},
		{ModeAggressive, "tunneladdress"},
		{ModeModerate, "tunneladdress"},
		{ModeMinimal, "tunneladdress"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			value := "203.0.113.1:51820"
			result := engine.Redact(tt.field, value)

			if tt.mode == ModeAggressive {
				if result != "[REDACTED-ENDPOINT]" {
					t.Errorf("Redact(%q, %q) = %q, want %q", tt.field, value, result, "[REDACTED-ENDPOINT]")
				}
				return
			}

			if result != value {
				t.Errorf("Redact(%q, %q) = %q, want unchanged", tt.field, value, result)
			}
		})
	}
}

func TestRedact_Endpoint_EmptyValue(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// Empty endpoint values must pass through unchanged.
	result := engine.Redact("endpoint", "")
	if result != "" {
		t.Errorf("Redact('endpoint', '') = %q, want empty", result)
	}
}

func TestRedact_IPAddrField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
		value string
		want  string
	}{
		{ModeAggressive, "ipaddr", "192.168.1.100", expectedRedactedPrivateIP1},
		{ModeModerate, "ipaddr", "192.168.1.100", "192.168.1.100"},
		{ModeMinimal, "ipaddr", "192.168.1.100", "192.168.1.100"},
		{ModeAggressive, "ipaddrv6", "192.168.1.100", expectedRedactedPrivateIP1},
		{ModeModerate, "ipaddrv6", "192.168.1.100", "192.168.1.100"},
		{ModeMinimal, "ipaddrv6", "192.168.1.100", "192.168.1.100"},
		{ModeAggressive, "ipaddrv6", "2001:db8::1", expectedRedactedPublicIP1},
		{ModeAggressive, "ipaddrv6", "fd00::1", expectedRedactedPrivateIP1},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			result := engine.Redact(tt.field, tt.value)

			if result != tt.want {
				t.Errorf("Redact(%q, %q) = %q, want %q", tt.field, tt.value, result, tt.want)
			}
		})
	}
}

func TestRedact_SubnetField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
		value string
	}{
		{ModeAggressive, "subnet", "192.168.1.0/24"},
		{ModeModerate, "subnet", "192.168.1.0/24"},
		{ModeMinimal, "subnet", "192.168.1.0/24"},
		{ModeAggressive, "subnetv6", "192.168.1.0/24"},
		{ModeModerate, "subnetv6", "192.168.1.0/24"},
		{ModeMinimal, "subnetv6", "192.168.1.0/24"},
		{ModeAggressive, "subnetv6", "fd00::/8"},
		{ModeAggressive, "subnet", "2001:db8::/32"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field+"_"+tt.value, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			result := engine.Redact(tt.field, tt.value)

			if tt.mode == ModeAggressive {
				if result != "[REDACTED-SUBNET]" {
					t.Errorf("Redact(%q, %q) = %q, want %q", tt.field, tt.value, result, "[REDACTED-SUBNET]")
				}
				return
			}

			if result != tt.value {
				t.Errorf("Redact(%q, %q) = %q, want unchanged", tt.field, tt.value, result)
			}
		})
	}
}

func TestRedact_CloudIdentifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "dns_cf_account_id"},
		{ModeModerate, "dns_cf_account_id"},
		{ModeMinimal, "dns_cf_account_id"},
		{ModeAggressive, "zone_id"},
		{ModeModerate, "zone_id"},
		{ModeMinimal, "zone_id"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			value := "abc123def456"
			result := engine.Redact(tt.field, value)

			if tt.mode == ModeAggressive {
				if result != "[REDACTED-CLOUD-ID]" {
					t.Errorf("Redact(%q, %q) = %q, want %q", tt.field, value, result, "[REDACTED-CLOUD-ID]")
				}
				return
			}

			if result != value {
				t.Errorf("Redact(%q, %q) = %q, want unchanged", tt.field, value, result)
			}
		})
	}
}

func TestRedact_CloudIdentifier_EmptyValue(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// Empty cloud ID values must pass through unchanged.
	result := engine.Redact("account_id", "")
	if result != "" {
		t.Errorf("Redact('account_id', '') = %q, want empty", result)
	}
}

func TestRedact_PublicKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode         Mode
		wantRedacted bool
	}{
		{ModeAggressive, true},
		{ModeModerate, false},
		{ModeMinimal, false},
	}

	t.Run("pubkey", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tests {
			t.Run(string(tt.mode), func(t *testing.T) {
				t.Parallel()
				engine := NewRuleEngine(tt.mode)
				result := engine.Redact("pubkey", testBase64PubKey)

				if tt.wantRedacted {
					if result != redactedPublicKeyValue {
						t.Errorf(
							"Redact(%q, %q) = %q, want %q",
							"pubkey",
							testBase64PubKey,
							result,
							redactedPublicKeyValue,
						)
					}
					return
				}

				if result != testBase64PubKey {
					t.Errorf("Redact(%q, %q) = %q, want unchanged", "pubkey", testBase64PubKey, result)
				}
			})
		}
	})

	t.Run("pub_key", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tests {
			t.Run(string(tt.mode), func(t *testing.T) {
				t.Parallel()
				engine := NewRuleEngine(tt.mode)
				result := engine.Redact("pub_key", testBase64PubKey)

				if tt.wantRedacted {
					if result != redactedPublicKeyValue {
						t.Errorf(
							"Redact(%q, %q) = %q, want %q",
							"pub_key",
							testBase64PubKey,
							result,
							redactedPublicKeyValue,
						)
					}
					return
				}

				if result != testBase64PubKey {
					t.Errorf("Redact(%q, %q) = %q, want unchanged", "pub_key", testBase64PubKey, result)
				}
			})
		}
	})
}

func TestShouldRedactField_OTPSeed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode  Mode
		field string
	}{
		{ModeAggressive, "otp_seed"},
		{ModeModerate, "otp_seed"},
		{ModeMinimal, "otp_seed"},
		{ModeAggressive, "otpseed"},
		{ModeModerate, "otpseed"},
		{ModeMinimal, "otpseed"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.field, func(t *testing.T) {
			t.Parallel()
			engine := NewRuleEngine(tt.mode)
			should, rule := engine.ShouldRedactField(tt.field)
			if !should {
				t.Errorf("ShouldRedactField(%q) = false, want true", tt.field)
			}
			if rule.Name == "" {
				t.Errorf("ShouldRedactField(%q) returned zero-value rule (no Name)", tt.field)
			}
		})
	}
}

// TestRuleMatchesFieldName_FieldExclusions covers the field-name counterpart to
// FieldGuard: a rule names fields it must never claim even when one of its
// FieldPatterns matches. FieldGuard cannot express this because it only ever
// sees the value. See GOTCHAS.md section 19.3.
func TestRuleMatchesFieldName_FieldExclusions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		exclusions []string
		field      string
		want       bool
	}{
		{"no exclusions leaves the match intact", nil, "ddnsdomainkeyalgorithm", true},
		{
			"exclusion equal to the field suppresses the match",
			[]string{"ddnsdomainkeyalgorithm"},
			"ddnsdomainkeyalgorithm",
			false,
		},
		{
			"exclusion anchors on the terminal segment",
			[]string{"ddnsdomainkeyalgorithm"},
			"dhcpd.lan.ddnsdomainkeyalgorithm",
			false,
		},
		{"a mixed-case field is excluded", []string{"ddnsdomainkeyalgorithm"}, "DDNSDomainKeyAlgorithm", false},
		{"a mixed-case exclusion still excludes", []string{"DDNSDomainKeyAlgorithm"}, "ddnsdomainkeyalgorithm", false},
		{
			"a substring of the terminal segment does not suppress",
			[]string{"ddnsdomain"},
			"ddnsdomainkeyalgorithm",
			true,
		},
		{"an unrelated exclusion leaves the match intact", []string{"unrelated"}, "ddnsdomainkeyalgorithm", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := Rule{
				Name:            "test_rule",
				FieldPatterns:   []string{"domain"},
				FieldExclusions: tt.exclusions,
			}

			if got := ruleMatchesFieldName(&rule, tt.field); got != tt.want {
				t.Errorf("ruleMatchesFieldName(%q) with exclusions %v = %v, want %v",
					tt.field, tt.exclusions, got, tt.want)
			}
		})
	}
}
