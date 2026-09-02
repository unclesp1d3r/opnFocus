package opnsense_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip_SampleConfigs(t *testing.T) {
	t.Parallel()

	pattern := filepath.Join("..", "..", "..", "testdata", "sample.config.*.xml")
	files, err := filepath.Glob(pattern)
	require.NoError(t, err, "failed to glob testdata")
	require.NotEmpty(t, files, "no sample config files found at %s", pattern)

	factory := parser.NewFactory(cfgparser.NewXMLParser())

	for _, fpath := range files {
		name := filepath.Base(fpath)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(fpath)
			require.NoError(t, err)
			defer f.Close()

			device, _, err := factory.CreateDevice(context.Background(), f, common.DeviceTypeUnknown, false)
			require.NoError(t, err, "CreateDevice failed for %s", name)
			require.NotNil(t, device, "device is nil for %s", name)

			assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
			assert.NotEmpty(t, device.System.Hostname, "hostname empty for %s", name)
			assert.NotEmpty(t, device.System.Domain, "domain empty for %s", name)
			assert.NotEmpty(t, device.Interfaces, "no interfaces for %s", name)

			// Sysctl is asserted here because this is the only test that
			// drives the whole pipeline over every shipped fixture. The
			// tunables were collapsing into a single entry with empty
			// Tunable and Value, and both the schema tests and the
			// converter tests agreed with each other while the CLI path
			// disagreed with both, so the defect survived them all.
			//
			// The count is deliberately not pinned: the fixtures carry 36
			// tunables each except sample.config.5.xml, which carries 35.
			// The property that actually broke is that entries arrive
			// populated, so that is what is asserted.
			assert.NotEmpty(t, device.Sysctl, "no sysctl tunables for %s", name)
			for i, item := range device.Sysctl {
				assert.NotEmptyf(t, item.Tunable,
					"%s: sysctl[%d] has an empty Tunable, the shape the collapse produced", name, i)
				assert.NotEmptyf(t, item.Value,
					"%s: sysctl[%d] (%s) has an empty Value", name, i, item.Tunable)
			}
		})
	}
}
