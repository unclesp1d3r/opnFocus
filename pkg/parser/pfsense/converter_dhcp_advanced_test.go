package pfsense_test

import (
	"reflect"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	pfsense "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// populateAdvancedFields sets every field named in advanced to its own name on
// the schema struct, so a value that arrives in the wrong output field is
// distinguishable from one that arrives in the right one. It fails the test
// rather than skipping when a field has no same-named schema counterpart or
// carries a type it cannot populate, so a schema rename surfaces here instead
// of silently narrowing coverage.
func populateAdvancedFields(t *testing.T, d *pfsenseSchema.DhcpdInterface, advanced reflect.Type) {
	t.Helper()

	target := reflect.ValueOf(d).Elem()
	for i := range advanced.NumField() {
		name := advanced.Field(i).Name

		field := target.FieldByName(name)
		if !field.IsValid() {
			t.Fatalf("%s.%s has no same-named field on pfsense.DhcpdInterface", advanced.Name(), name)
		}

		if field.Kind() != reflect.String {
			t.Fatalf("pfsense.DhcpdInterface.%s is %s, not a string; extend this test", name, field.Kind())
		}

		field.SetString(name)
	}
}

// TestConverter_DHCPAdvanced_EveryFieldSurvivesConversion proves the pfSense
// converter carries the advanced DHCPv4/v6 settings from schema.DhcpdInterface
// through to common.DHCPScope. Before buildDHCPAdvancedV4/V6 existed on the
// pfSense side these ~45 fields parsed cleanly and were then dropped at the
// converter boundary with no warning (GOTCHAS 3.6).
//
// The field list is driven by reflection over the common structs rather than
// written out by hand, so adding a field to common.DHCPAdvancedV4/V6 without
// mapping it in the pfSense builder fails here.
func TestConverter_DHCPAdvanced_EveryFieldSurvivesConversion(t *testing.T) {
	t.Parallel()

	v4Type := reflect.TypeOf(common.DHCPAdvancedV4{})
	v6Type := reflect.TypeOf(common.DHCPAdvancedV6{})

	var iface pfsenseSchema.DhcpdInterface
	populateAdvancedFields(t, &iface, v4Type)
	populateAdvancedFields(t, &iface, v6Type)

	doc := pfsenseSchema.NewDocument()
	doc.Dhcpd.Items = map[string]pfsenseSchema.DhcpdInterface{"lan": iface}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.DHCP, 1)

	scope := device.DHCP[0]
	require.NotNil(t, scope.AdvancedV4, "advanced DHCPv4 settings must not be dropped")
	require.NotNil(t, scope.AdvancedV6, "advanced DHCPv6 settings must not be dropped")

	v4 := reflect.ValueOf(*scope.AdvancedV4)
	for i := range v4Type.NumField() {
		name := v4Type.Field(i).Name
		assert.Equal(t, name, v4.Field(i).String(), "DHCPAdvancedV4.%s", name)
	}

	v6 := reflect.ValueOf(*scope.AdvancedV6)
	for i := range v6Type.NumField() {
		name := v6Type.Field(i).Name
		assert.Equal(t, name, v6.Field(i).String(), "DHCPAdvancedV6.%s", name)
	}
}

// TestConverter_DHCPAdvanced_NilWhenUnset pins the omit-empty contract: a scope
// with no advanced settings must leave both pointers nil so they disappear from
// JSON and YAML output rather than serializing as empty objects.
func TestConverter_DHCPAdvanced_NilWhenUnset(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Dhcpd.Items = map[string]pfsenseSchema.DhcpdInterface{
		"lan": {
			Enable:    true,
			Range:     opnsense.Range{From: "192.168.1.10", To: "192.168.1.245"},
			Dnsserver: []string{"192.168.1.1"},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.DHCP, 1)

	assert.Nil(t, device.DHCP[0].AdvancedV4)
	assert.Nil(t, device.DHCP[0].AdvancedV6)
	assert.Equal(t, []string{"192.168.1.1"}, device.DHCP[0].DNSServers, "basic fields must still convert")
}
