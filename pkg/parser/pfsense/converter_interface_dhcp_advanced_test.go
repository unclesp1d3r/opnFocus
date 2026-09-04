package pfsense_test

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// advDHCPConfigTemplate wraps a generated <lan> body. Advanced DHCP *client*
// settings live under <interfaces>, not under <dhcpd>; see
// testdata/sample.config.5.xml, which carries the whole set under <interfaces>.
const advDHCPConfigTemplate = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <lan>
      <if>vtnet0</if>
%s    </lan>
  </interfaces>
</pfsense>`

// advDHCPSentinel returns a value unique to the field, so a builder that reads
// the wrong source field produces a mismatch rather than an accidental pass.
func advDHCPSentinel(field string) string { return "sentinel-" + field }

// advDHCPFieldNames lists the string fields of a common advanced-DHCP struct.
// The common struct is the source of truth for what must be wired: a field added
// there without a matching builder assignment fails the tests below.
func advDHCPFieldNames(v any) []string {
	rt := reflect.TypeOf(v)
	names := make([]string, 0, rt.NumField())

	for f := range rt.Fields() {
		names = append(names, f.Name)
	}

	return names
}

// advDHCPXMLTags resolves each field name to the XML element the schema declares
// for it, so the fixture is generated from the schema rather than from a
// hand-maintained second copy of the element names. A field the common struct
// carries but the schema interface struct does not is a parser-boundary drop:
// the element never survives unmarshaling, so no converter change can recover it.
func advDHCPXMLTags(t *testing.T, ifaceType reflect.Type, fields []string) map[string]string {
	t.Helper()

	tags := make(map[string]string, len(fields))

	for _, name := range fields {
		sf, ok := ifaceType.FieldByName(name)
		require.Truef(t, ok,
			"schema interface struct declares no %s field, so the element is dropped before conversion", name)

		tag, _, _ := strings.Cut(sf.Tag.Get("xml"), ",")
		require.NotEmptyf(t, tag, "%s has no xml element name", name)

		tags[name] = tag
	}

	return tags
}

// advDHCPAssertFields checks every field against its own sentinel.
func advDHCPAssertFields(t *testing.T, got reflect.Value, fields []string) {
	t.Helper()

	for _, name := range fields {
		assert.Equalf(t, advDHCPSentinel(name), got.FieldByName(name).String(),
			"%s is unwired or cross-wired in the interface advanced-DHCP builder", name)
	}
}

// TestConverter_InterfaceDHCPAdvanced_AllFieldsWired drives XML through the full
// parse -> convert path, so it covers both halves of the gap: the schema must
// declare the element, and the converter must carry it onto the common model.
func TestConverter_InterfaceDHCPAdvanced_AllFieldsWired(t *testing.T) {
	t.Parallel()

	v4Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV4{})
	v6Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV6{})
	tags := advDHCPXMLTags(t, reflect.TypeFor[schema.Interface](), slices.Concat(v4Fields, v6Fields))

	var body strings.Builder
	for _, name := range slices.Concat(v4Fields, v6Fields) {
		fmt.Fprintf(&body, "      <%s>%s</%s>\n", tags[name], advDHCPSentinel(name), tags[name])
	}

	xmlBody := fmt.Sprintf(advDHCPConfigTemplate, body.String())

	device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
	require.NoError(t, err)
	require.Len(t, device.Interfaces, 1)

	iface := device.Interfaces[0]
	require.NotNil(t, iface.DHCPAdvancedV4, "advanced DHCPv4 client settings under <interfaces> must be converted")
	require.NotNil(t, iface.DHCPAdvancedV6, "advanced DHCPv6 client settings under <interfaces> must be converted")

	advDHCPAssertFields(t, reflect.ValueOf(*iface.DHCPAdvancedV4), v4Fields)
	advDHCPAssertFields(t, reflect.ValueOf(*iface.DHCPAdvancedV6), v6Fields)
}

// TestConverter_InterfaceDHCPAdvanced_NilWhenUnset asserts the pointers stay nil
// for the two shapes real configs actually produce: elements absent entirely, and
// elements present but self-closing. testdata/sample.config.5.xml is the latter,
// so without this the fixture would grow two empty objects per interface.
func TestConverter_InterfaceDHCPAdvanced_NilWhenUnset(t *testing.T) {
	t.Parallel()

	v4Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV4{})
	v6Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV6{})
	tags := advDHCPXMLTags(t, reflect.TypeFor[schema.Interface](), slices.Concat(v4Fields, v6Fields))

	var empties strings.Builder
	for _, name := range slices.Concat(v4Fields, v6Fields) {
		fmt.Fprintf(&empties, "      <%s/>\n", tags[name])
	}

	tests := []struct {
		name string
		body string
	}{
		{name: "elements absent", body: ""},
		{name: "elements present but empty", body: empties.String()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlBody := fmt.Sprintf(advDHCPConfigTemplate, tt.body)

			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
			require.NoError(t, err)
			require.Len(t, device.Interfaces, 1)

			assert.Nil(t, device.Interfaces[0].DHCPAdvancedV4,
				"an all-empty advanced DHCPv4 set must be omitted, not serialized as an empty object")
			assert.Nil(t, device.Interfaces[0].DHCPAdvancedV6,
				"an all-empty advanced DHCPv6 set must be omitted, not serialized as an empty object")
		})
	}
}
