package opnsense

import (
	"encoding/xml"
	"strings"
	"testing"
)

const testInterfaceDevice = "em0"

// TestBridges_BridgedElementRoundTrip verifies that OPNsense <bridged> elements
// unmarshal into Bridges and that the same element name is emitted on the way
// back out. The struct tag governs both directions, so marshal is asserted
// alongside unmarshal rather than left unpinned.
func TestBridges_BridgedElementRoundTrip(t *testing.T) {
	t.Parallel()
	const raw = `<bridges>
  <bridged>
    <bridgeif>bridge0</bridgeif>
    <members>opt1,opt2</members>
    <descr>LAN</descr>
    <stp>1</stp>
  </bridged>
</bridges>`
	var got Bridges
	if err := xml.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Bridge) != 1 {
		t.Fatalf("got %d bridges, want 1", len(got.Bridge))
	}
	assertBridgeFields(t, "unmarshal", got.Bridge[0])

	data, err := xml.Marshal(&got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "<bridged>") {
		t.Fatalf("marshal did not emit <bridged>: %s", out)
	}
	// "<bridge>" cannot match "<bridged>", so this catches a regression to the
	// pre-fix element name.
	if strings.Contains(out, "<bridge>") {
		t.Fatalf("marshal emitted the pre-fix <bridge> element: %s", out)
	}

	var back Bridges
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal after marshal: %v", err)
	}
	if len(back.Bridge) != 1 {
		t.Fatalf("after round-trip got %d bridges, want 1", len(back.Bridge))
	}
	assertBridgeFields(t, "round-trip", back.Bridge[0])
}

// assertBridgeFields checks every field the round-trip fixture populates, so a
// tag or marshaler regression on any one of them fails loudly.
func assertBridgeFields(t *testing.T, stage string, b Bridge) {
	t.Helper()

	if b.Bridgeif != "bridge0" {
		t.Errorf("%s: bridgeif = %q, want %q", stage, b.Bridgeif, "bridge0")
	}
	if b.Members != "opt1,opt2" {
		t.Errorf("%s: members = %q, want %q", stage, b.Members, "opt1,opt2")
	}
	if b.Descr != "LAN" {
		t.Errorf("%s: descr = %q, want %q", stage, b.Descr, "LAN")
	}
	if !bool(b.STP) {
		t.Errorf("%s: stp = false, want true", stage)
	}
}

// TestInterfaces_MarshalUnmarshal_Simple tests XML round-trip for Interfaces.
func TestInterfaces_MarshalUnmarshal_Simple(t *testing.T) {
	t.Parallel()

	i := &Interfaces{Items: map[string]Interface{
		"wan": {If: testInterfaceDevice, Enable: "1"},
	}}

	data, err := xml.Marshal(i)
	if err != nil {
		t.Fatalf("MarshalXML failed: %v", err)
	}

	var result Interfaces
	if err := xml.Unmarshal(data, &result); err != nil {
		t.Fatalf("UnmarshalXML failed: %v", err)
	}

	if len(result.Items) != 1 {
		t.Errorf("Expected 1 item, got %d", len(result.Items))
	}

	wan, exists := result.Items["wan"]
	if !exists {
		t.Fatal("Expected wan interface to exist after round-trip")
	}

	if wan.If != testInterfaceDevice {
		t.Errorf("wan.If = %q, want %q", wan.If, testInterfaceDevice)
	}

	if wan.Enable != "1" {
		t.Errorf("wan.Enable = %q, want %q", wan.Enable, "1")
	}
}

// TestPPP_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero covers the
// empty-<ppp/> guard. OPNsense writes a self-closing placeholder inside <ppps>
// when no PPP link is configured, and the predicate must recognize it while
// retaining any entry that carries data.
func TestPPP_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ppp  PPP
		want bool
	}{
		{name: "zero value is a placeholder", ppp: PPP{}, want: true},
		{name: "description only is retained", ppp: PPP{Descr: "backup link"}, want: false},
		{name: "interface only is retained", ppp: PPP{If: "pppoe0"}, want: false},
		{name: "type only is retained", ppp: PPP{Type: "pppoe"}, want: false},
		{
			name: "fully populated is retained",
			ppp:  PPP{If: "pppoe0", Type: "pppoe", Descr: "WAN uplink"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ppp.IsPlaceholder(); got != tt.want {
				t.Errorf("IsPlaceholder() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPPP_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder pins the reason
// the predicate compares named fields instead of the zero value: encoding/xml
// populates XMLName on unmarshal, so a decoded <ppp/> is never equal to PPP{}.
func TestPPP_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	var got PPP
	if err := xml.Unmarshal([]byte(`<ppp/>`), &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if got == (PPP{}) {
		t.Fatal("decoded <ppp/> equals PPP{}; the XMLName premise for IsPlaceholder no longer holds")
	}

	if !got.IsPlaceholder() {
		t.Error("decoded <ppp/> must be reported as a placeholder")
	}
}

// TestBridge_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero covers the
// empty-<bridged/> guard relocated from the OPNsense converter so both parsers
// can share it.
func TestBridge_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		bridge Bridge
		want   bool
	}{
		{name: "zero value is a placeholder", bridge: Bridge{}, want: true},
		{name: "description only is retained", bridge: Bridge{Descr: "guest bridge"}, want: false},
		{name: "stp only is retained", bridge: Bridge{STP: BoolFlag(true)}, want: false},
		{
			name:   "fully populated is retained",
			bridge: Bridge{Bridgeif: "bridge0", Members: "opt1,opt2", Descr: "LAN"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.bridge.IsPlaceholder(); got != tt.want {
				t.Errorf("IsPlaceholder() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBridge_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder is the Bridge
// counterpart to TestPPP_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder.
func TestBridge_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	var got Bridge
	if err := xml.Unmarshal([]byte(`<bridged/>`), &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !got.IsPlaceholder() {
		t.Error("decoded <bridged/> must be reported as a placeholder")
	}
}
