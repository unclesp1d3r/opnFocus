package opnsense_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
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

// countSysctlItems reports how many sysctl tunables the fixture declares,
// which is the number the parser should return.
//
// It decodes the file with encoding/xml rather than matching tag spellings:
// a regex oracle breaks on an attribute or stray whitespace (<item attr="x">,
// <sysctl >), which are valid XML and would silently skew the count.
//
// Items carrying no content are excluded, because the parser drops them.
// That rule is applied here by inspecting the decoded fields directly rather
// than by calling IsPlaceholder, so the oracle stays independent of the code
// it is checking: coupling it would let both sides agree while both were
// wrong, which is how the original defect survived its tests.
func countSysctlItems(t *testing.T, path string) int {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	// Mirrors only the shape this count needs, not the real schema.
	var doc struct {
		Sysctl []struct {
			Items []struct {
				Descr   string `xml:"descr"`
				Tunable string `xml:"tunable"`
				Value   string `xml:"value"`
				Key     string `xml:"key"`
				Secret  string `xml:"secret"`
			} `xml:"item"`
		} `xml:"sysctl"`
	}

	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = charsetReaderPassthrough
	require.NoError(t, decoder.Decode(&doc), "%s: could not decode", filepath.Base(path))
	require.NotEmpty(t, doc.Sysctl, "%s has no <sysctl> container", filepath.Base(path))

	count := 0
	for _, container := range doc.Sysctl {
		for _, item := range container.Items {
			if item.Descr != "" || item.Tunable != "" || item.Value != "" ||
				item.Key != "" || item.Secret != "" {
				count++
			}
		}
	}

	return count
}

// charsetReaderPassthrough lets the decoder accept the us-ascii declaration
// the shipped fixtures carry. encoding/xml refuses any non-UTF-8 charset
// without one, and us-ascii is a UTF-8 subset so the bytes need no
// conversion.
func charsetReaderPassthrough(_ string, input io.Reader) (io.Reader, error) {
	return input, nil
}
