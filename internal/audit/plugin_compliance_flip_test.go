package audit

import (
	"bytes"
	"maps"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
			// Pins current behavior rather than asserting it is desirable. The
			// caller seeds the map only with controls the plugin actually
			// evaluated, so a reference to an unevaluated control injects a new
			// key — turning an unconfirmed control into an evaluated failing
			// one. Reachable via a control-ID typo in a plugin's finding or
			// drift between a finding's References and the plugin's control
			// table. If that is ever deemed wrong, this row is the place the
			// decision surfaces.
			name:    "a reference to a control absent from the map injects it as failing",
			initial: map[string]bool{"FIREWALL-001": true},
			findings: []compliance.Finding{
				{
					Type:       "compliance",
					Title:      "References a control the plugin never evaluated",
					References: []string{"FIREWALL-999"},
				},
			},
			expected: map[string]bool{"FIREWALL-001": true, "FIREWALL-999": false},
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
			applyFindingsToCompliance(out, tt.findings, "test-plugin", nil)

			// Assert
			assert.Equal(t, tt.expected, out)
		})
	}
}

// TestRunComplianceChecks_InventoryFinding_LeavesComplianceMapUnflipped drives the inventory-skip
// invariant through the real RunComplianceChecks -> runPluginChecks ->
// applyFindingsToCompliance chain, rather than calling the unexported helper in
// isolation. Without this, a wiring regression in the caller (wrong map passed,
// the call dropped) would go uncaught.
//
// The mock reports every one of its controls as evaluated, so the inventory
// finding's referenced control IS present in the compliance map. That makes the
// skip directly observable — in production, inventory controls are excluded from
// the evaluated slice (GOTCHAS.md 2.4), so the flip would be a no-op either way.
func TestRunComplianceChecks_InventoryFinding_LeavesComplianceMapUnflipped(t *testing.T) {
	t.Parallel()

	// Arrange
	registry := NewPluginRegistry()

	mockPlugin := &mockPluginWithFindings{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "test-inventory-skip",
			description: "Plugin emitting one inventory and one compliance finding",
			version:     "1.0.0",
		},
		findings: []compliance.Finding{
			{
				Type:       "inventory",
				Severity:   "info",
				Title:      "DHCP Scopes Configured",
				References: []string{"CONTROL-INV"},
			},
			{
				Type:       "compliance",
				Severity:   "high",
				Title:      "Security Issue",
				References: []string{"CONTROL-SEC"},
			},
		},
		controls: []compliance.Control{
			{ID: "CONTROL-INV", Title: "Inventory control", Severity: "info"},
			{ID: "CONTROL-SEC", Title: "Security control", Severity: "high"},
		},
	}

	if err := registry.RegisterPlugin(mockPlugin); err != nil {
		t.Fatalf("RegisterPlugin() error = %v", err)
	}

	device := &common.CommonDevice{System: common.System{Hostname: "test-host"}}

	// Act
	result, err := registry.RunComplianceChecks(device, []string{"test-inventory-skip"}, newTestLogger(t))
	if err != nil {
		t.Fatalf("RunComplianceChecks() error = %v", err)
	}

	// Assert
	pluginCompliance := result.Compliance["test-inventory-skip"]
	if pluginCompliance == nil {
		t.Fatal("RunComplianceChecks() missing compliance map for plugin")
	}

	assert.True(t, pluginCompliance["CONTROL-INV"],
		"inventory finding must not flip its referenced control to non-compliant")
	assert.False(t, pluginCompliance["CONTROL-SEC"],
		"compliance finding must flip its referenced control to non-compliant")
}

// TestApplyFindingsToCompliance_MislabeledType_WarnsWithoutChangingGate covers the two diagnostics that
// keep the inventory exemption from being a silent suppression path. Finding.Type
// is an unvalidated string supplied by an arbitrary plugin, including a
// dynamically loaded one (GOTCHAS.md 2.5), so a finding mislabeled "inventory"
// can exempt itself from the compliance flip. The exemption still applies — a
// plugin must not be able to change gate behavior — but it no longer happens
// without a trace.
func TestApplyFindingsToCompliance_MislabeledType_WarnsWithoutChangingGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		finding     compliance.Finding
		wantLogged  string
		wantFlipped bool
	}{
		{
			name: "escalated severity on an inventory finding is warned",
			finding: compliance.Finding{
				Type:       "inventory",
				Severity:   "critical",
				Title:      "Mislabeled as inventory",
				References: []string{"CONTROL-A"},
			},
			wantLogged:  "escalated severity",
			wantFlipped: false,
		},
		{
			name: "unrecognized type is warned and still treated as compliance-affecting",
			finding: compliance.Finding{
				Type:       "complaince",
				Severity:   "high",
				Title:      "Typo in the Type value",
				References: []string{"CONTROL-A"},
			},
			wantLogged:  "unrecognized Type",
			wantFlipped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			var buf bytes.Buffer

			logger, err := logging.New(logging.Config{Level: "warn", Output: &buf})
			if err != nil {
				t.Fatalf("logging.New() error = %v", err)
			}

			out := map[string]bool{"CONTROL-A": true}

			// Act
			applyFindingsToCompliance(out, []compliance.Finding{tt.finding}, "test-plugin", logger)

			// Assert
			assert.Contains(t, buf.String(), tt.wantLogged)
			assert.Equal(t, !tt.wantFlipped, out["CONTROL-A"])
		})
	}
}

// TestApplyFindingsToCompliance_NilLogger_DoesNotPanic pins that the diagnostics above
// are optional. The unit table passes a nil logger throughout, so a regression
// that dereferenced it unconditionally would surface here rather than as a panic
// deep in an unrelated test.
func TestApplyFindingsToCompliance_NilLogger_DoesNotPanic(t *testing.T) {
	t.Parallel()

	out := map[string]bool{"CONTROL-A": true}

	assert.NotPanics(t, func() {
		applyFindingsToCompliance(out, []compliance.Finding{
			{Type: "inventory", Severity: "critical", References: []string{"CONTROL-A"}},
			{Type: "complaince", Severity: "high", References: []string{"CONTROL-A"}},
		}, "test-plugin", nil)
	})
}
