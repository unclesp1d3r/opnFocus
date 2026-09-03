package opnsense_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
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
			// The expected count is read from the fixture rather than
			// written here. A hardcoded number would be wrong for
			// sample.config.5.xml, which carries 35 where the others carry
			// 36, and would need editing whenever a fixture changes. More
			// importantly, asserting only that entries arrive populated
			// does not prove they all survived: a file could collapse to a
			// single populated tunable and still pass.
			assert.Len(t, device.Sysctl, countSysctlItems(t, fpath),
				"%s: sysctl tunable count does not match the fixture", name)
			for i, item := range device.Sysctl {
				assert.NotEmptyf(t, item.Tunable,
					"%s: sysctl[%d] has an empty Tunable, the shape the collapse produced", name, i)
				assert.NotEmptyf(t, item.Value,
					"%s: sysctl[%d] (%s) has an empty Value", name, i, item.Tunable)
			}
		})
	}
}

// countSysctlItems reports how many <item> elements the fixture declares
// inside its <sysctl> container, which is the number the parser should
// return.
//
// It counts the opening tag, so a self-closing placeholder <item/> is not
// counted, matching the parser dropping it. A placeholder spelled
// <item></item> would be counted here and dropped there; no shipped fixture
// contains one, and if that changes this is the assertion that will say so.
func countSysctlItems(t *testing.T, path string) int {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	section := regexp.MustCompile(`(?s)<sysctl>(.*?)</sysctl>`).FindSubmatch(raw)
	require.NotNil(t, section, "%s has no <sysctl> container", filepath.Base(path))

	return len(regexp.MustCompile(`<item>`).FindAll(section[1], -1))
}
