package opnsense

import (
	"encoding/xml"
	"testing"
)

const testInterfaceDevice = "em0"

// TestInterfaces_MarshalUnmarshal_Simple tests XML round-trip for Interfaces.
//

func TestBridges_UnmarshalBridgedElements(t *testing.T) {
	t.Parallel()
	const raw = `<bridges>
  <bridged>
    <bridgeif>bridge0</bridgeif>
    <members>opt1,opt2</members>
    <descr>LAN</descr>
  </bridged>
</bridges>`
	var got Bridges
	if err := xml.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Bridge) != 1 {
		t.Fatalf("got %d bridges, want 1", len(got.Bridge))
	}
	if got.Bridge[0].Bridgeif != "bridge0" {
		t.Fatalf("bridgeif = %q", got.Bridge[0].Bridgeif)
	}
}

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
