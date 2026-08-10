package audit

import (
	"maps"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/stretchr/testify/assert"
)

// TestApplyFindingsToCompliance pins the inventory-skip invariant documented in
// GOTCHAS.md §2.4: a finding referencing a control flips that control to
// non-compliant, EXCEPT inventory findings, which are informational and must
// never touch the compliance map.
//
// The finding Type values here are deliberately raw string literals rather than
// constants.FindingType* references. Asserting against the constant would be
// tautological — it could not catch an accidental change to the constant's own
// value, which is exactly the regression this test exists to catch.
func TestApplyFindingsToCompliance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		initial  map[string]bool
		findings []compliance.Finding
		expected map[string]bool
	}{
		{
			name:    "inventory finding does not flip its referenced controls",
			initial: map[string]bool{},
			findings: []compliance.Finding{
				{
					Type:       "inventory",
					Title:      "DHCP Scopes Configured",
					References: []string{"FIREWALL-062"},
				},
			},
			expected: map[string]bool{},
		},
		{
			name:    "compliance finding flips its referenced control to false",
			initial: map[string]bool{"FIREWALL-001": true},
			findings: []compliance.Finding{
				{
					Type:       "compliance",
					Title:      "SSH Warning Banner Not Configured",
					References: []string{"FIREWALL-001"},
				},
			},
			expected: map[string]bool{"FIREWALL-001": false},
		},
		{
			name:    "inventory finding is skipped while a sibling compliance finding still flips",
			initial: map[string]bool{"FIREWALL-001": true, "FIREWALL-062": true},
			findings: []compliance.Finding{
				{
					Type:       "inventory",
					Title:      "Active Interfaces",
					References: []string{"FIREWALL-062"},
				},
				{
					Type:       "compliance",
					Title:      "SSH Warning Banner Not Configured",
					References: []string{"FIREWALL-001"},
				},
			},
			expected: map[string]bool{"FIREWALL-001": false, "FIREWALL-062": true},
		},
		{
			name:    "a finding with multiple references flips every one of them",
			initial: map[string]bool{"FIREWALL-001": true, "FIREWALL-008": true},
			findings: []compliance.Finding{
				{
					Type:       "compliance",
					Title:      "Multi-control failure",
					References: []string{"FIREWALL-001", "FIREWALL-008"},
				},
			},
			expected: map[string]bool{"FIREWALL-001": false, "FIREWALL-008": false},
		},
		{
			name:     "no findings leaves the map untouched",
			initial:  map[string]bool{"FIREWALL-001": true},
			findings: nil,
			expected: map[string]bool{"FIREWALL-001": true},
		},
		{
			name:    "inventory finding with no references is a no-op",
			initial: map[string]bool{"FIREWALL-001": true},
			findings: []compliance.Finding{
				{Type: "inventory", Title: "Inventory note"},
			},
			expected: map[string]bool{"FIREWALL-001": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			out := make(map[string]bool, len(tt.initial))
			maps.Copy(out, tt.initial)

			// Act
			applyFindingsToCompliance(out, tt.findings)

			// Assert
			assert.Equal(t, tt.expected, out)
		})
	}
}
