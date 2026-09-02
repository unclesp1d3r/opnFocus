package cfgparser_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CLI reaches <sysctl> through this package, not through a plain
// xml.Unmarshal into the schema type. A bespoke handler used to sit on this
// path and understood only the container shape, so the schema's own
// SysctlItems.UnmarshalXML never ran for any CLI command: the legacy flat
// shape was silently skipped and a bare <item/> survived as a phantom
// tunable. Fixing the codec without removing that handler left the two
// decoders disagreeing with no signal either way, which is the failure
// GOTCHAS 3.6 is about. These pin the CLI path to the same behaviour the
// library path has.

func TestParse_SysctlContainerShape_KeepsEveryTunable(t *testing.T) {
	t.Parallel()

	const doc = `<opnsense><sysctl>` +
		`<item><tunable>net.inet.ip.redirect</tunable><value>0</value></item>` +
		`<item><tunable>net.inet.tcp.blackhole</tunable><value>2</value></item>` +
		`</sysctl></opnsense>`

	cfg, err := cfgparser.NewXMLParser().Parse(t.Context(), strings.NewReader(doc))
	require.NoError(t, err)
	require.Len(t, cfg.Sysctl, 2)
	assert.Equal(t, "net.inet.ip.redirect", cfg.Sysctl[0].Tunable)
	assert.Equal(t, "net.inet.tcp.blackhole", cfg.Sysctl[1].Tunable)
}

func TestParse_SysctlLegacyFlatShape_IsNotDropped(t *testing.T) {
	t.Parallel()

	// Older configs write the tunable directly under <sysctl> with no <item>
	// wrapper. The removed handler decoded this into zero items and then
	// skipped the element, so the values vanished without a warning.
	const doc = `<opnsense><sysctl>` +
		`<tunable>net.inet.ip.redirect</tunable><value>0</value><descr>no redirects</descr>` +
		`</sysctl></opnsense>`

	cfg, err := cfgparser.NewXMLParser().Parse(t.Context(), strings.NewReader(doc))
	require.NoError(t, err)
	require.Len(t, cfg.Sysctl, 1, "a legacy flat tunable must not be silently discarded")
	assert.Equal(t, "net.inet.ip.redirect", cfg.Sysctl[0].Tunable)
	assert.Equal(t, "0", cfg.Sysctl[0].Value)
}

func TestParse_SysctlBarePlaceholderItem_IsDropped(t *testing.T) {
	t.Parallel()

	// The DTD makes every child of <item> optional, so <item/> is valid and
	// decodes to an entry the schema's own validate:"required" tags reject.
	const doc = `<opnsense><sysctl><item/></sysctl></opnsense>`

	cfg, err := cfgparser.NewXMLParser().Parse(t.Context(), strings.NewReader(doc))
	require.NoError(t, err)
	assert.Empty(t, cfg.Sysctl, "a placeholder <item/> must not become a phantom tunable")
}

func TestParse_SysctlMultipleContainers_Accumulate(t *testing.T) {
	t.Parallel()

	const doc = `<opnsense>` +
		`<sysctl><item><tunable>first</tunable><value>1</value></item></sysctl>` +
		`<sysctl><item><tunable>second</tunable><value>2</value></item></sysctl>` +
		`</opnsense>`

	cfg, err := cfgparser.NewXMLParser().Parse(t.Context(), strings.NewReader(doc))
	require.NoError(t, err)
	require.Len(t, cfg.Sysctl, 2, "a second <sysctl> container must not replace the first")
	assert.Equal(t, "first", cfg.Sysctl[0].Tunable)
	assert.Equal(t, "second", cfg.Sysctl[1].Tunable)
}

func TestParse_SysctlShippedFixture_TunableCountUnchanged(t *testing.T) {
	t.Parallel()

	// Guards the routing change against a regression in the ordinary case:
	// this fixture carries 36 tunables and must continue to yield exactly
	// that through the CLI parser.
	path := filepath.Join("..", "..", "testdata", "sample.config.1.xml")
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	cfg, err := cfgparser.NewXMLParser().Parse(t.Context(), f)
	require.NoError(t, err)
	assert.Len(t, cfg.Sysctl, 36)
}
