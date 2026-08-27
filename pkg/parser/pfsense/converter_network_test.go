package pfsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_PPPs_EndToEnd_PlaceholderNotCounted drives config.xml content
// through the full parse -> convert path. pfSense shares the OPNsense PPP schema
// type, so it inherits the same empty-<ppp/> placeholder shape.
func TestConverter_PPPs_EndToEnd_PlaceholderNotCounted(t *testing.T) {
	t.Parallel()

	const configTemplate = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <ppps>%s</ppps>
</pfsense>`

	tests := []struct {
		name          string
		pppsInner     string
		wantPPPs      int
		wantInterface string
	}{
		{
			name:      "empty ppp placeholder reports zero PPPs",
			pppsInner: `<ppp/>`,
			wantPPPs:  0,
		},
		{
			name:      "ppp carrying only a description is retained",
			pppsInner: `<ppp><descr>backup link</descr></ppp>`,
			wantPPPs:  1,
		},
		{
			name:          "populated ppp element is counted",
			pppsInner:     `<ppp><if>pppoe0</if><type>pppoe</type><descr>WAN</descr></ppp>`,
			wantPPPs:      1,
			wantInterface: "pppoe0",
		},
		{
			// A per-item filter must drop only the placeholder, never a sibling.
			name:          "placeholder alongside a real ppp yields only the real one",
			pppsInner:     `<ppp/><ppp><if>pppoe0</if><type>pppoe</type><descr>WAN</descr></ppp>`,
			wantPPPs:      1,
			wantInterface: "pppoe0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlBody := strings.Replace(configTemplate, "%s", tt.pppsInner, 1)
			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Len(t, device.PPPs, tt.wantPPPs,
				"PPPs must not include empty <ppp/> placeholders")

			if tt.wantInterface != "" {
				require.Len(t, device.PPPs, 1)
				assert.Equal(t, tt.wantInterface, device.PPPs[0].Interface)
			}
		})
	}
}

// TestConverter_StaticRoutes_EndToEnd_PlaceholderNotCounted asserts the consumer
// that makes the phantom user-visible: HasRoutes decides whether a report renders
// a routing section. The fixtures carry no <gateways> because HasRoutes ORs
// static routes with gateways and gateway groups.
func TestConverter_StaticRoutes_EndToEnd_PlaceholderNotCounted(t *testing.T) {
	t.Parallel()

	const configTemplate = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <staticroutes>%s</staticroutes>
</pfsense>`

	tests := []struct {
		name          string
		routesInner   string
		wantRoutes    int
		wantHasRoutes bool
		wantNetwork   string
	}{
		{
			name:          "empty route placeholder reports zero routes",
			routesInner:   `<route/>`,
			wantRoutes:    0,
			wantHasRoutes: false,
		},
		{
			name:          "route carrying only a description is retained",
			routesInner:   `<route><descr>staged route</descr></route>`,
			wantRoutes:    1,
			wantHasRoutes: true,
		},
		{
			name:          "populated route element is counted",
			routesInner:   `<route><network>10.0.0.0/8</network><gateway>WAN_GW</gateway></route>`,
			wantRoutes:    1,
			wantHasRoutes: true,
			wantNetwork:   "10.0.0.0/8",
		},
		{
			// A per-item filter must drop only the placeholder, never a sibling.
			name:          "placeholder alongside a real route yields only the real one",
			routesInner:   `<route/><route><network>10.0.0.0/8</network><gateway>WAN_GW</gateway></route>`,
			wantRoutes:    1,
			wantHasRoutes: true,
			wantNetwork:   "10.0.0.0/8",
		},
		{
			// Disabled is the one guarded field with non-trivial unmarshal
			// semantics (BoolFlag: a self-closing tag decodes to true), so it is
			// driven through real XML rather than built as a struct.
			name:          "route carrying only a self-closing disabled marker is retained",
			routesInner:   `<route><disabled/></route>`,
			wantRoutes:    1,
			wantHasRoutes: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlBody := strings.Replace(configTemplate, "%s", tt.routesInner, 1)
			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Len(t, device.Routing.StaticRoutes, tt.wantRoutes,
				"StaticRoutes must not include empty <route/> placeholders")
			assert.Equal(t, tt.wantHasRoutes, device.HasRoutes(),
				"HasRoutes must not be flipped true by an empty <route/> placeholder")

			if tt.wantNetwork != "" {
				require.Len(t, device.Routing.StaticRoutes, 1)
				assert.Equal(t, tt.wantNetwork, device.Routing.StaticRoutes[0].Network)
			}
		})
	}
}

// TestConverter_EmptyContainers_YieldNilSlices confirms the placeholder guard did
// not disturb the absent-container path.
func TestConverter_EmptyContainers_YieldNilSlices(t *testing.T) {
	t.Parallel()

	const xmlBody = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
</pfsense>`

	device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Nil(t, device.PPPs)
	assert.Nil(t, device.Routing.StaticRoutes)
	assert.False(t, device.HasRoutes())
}
