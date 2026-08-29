package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDerivePerInputOutputPathSuffixSeparatesCommands checks that an audit and a
// convert of the same input do not land on the same filename. Both commands
// derive per-input paths from the same helper, so without the suffix whichever
// ran second would silently overwrite the other's report.
func TestDerivePerInputOutputPathSuffixSeparatesCommands(t *testing.T) {
	// No t.Parallel: forbidden throughout cmd/ (GOTCHAS 1.1), since the package
	// binds CLI flags to globals.
	auditPath := derivePerInputOutputPath("config.xml", auditOutputSuffix, ".md")
	convertPath := derivePerInputOutputPath("config.xml", "", ".md")

	assert.NotEqual(t, auditPath, convertPath, "audit and convert derived the same path")
	assert.Equal(t, "config.md", convertPath,
		"the convert help text documents config.xml -> config.md")
	assert.Equal(t, "config-audit.md", auditPath)
}

// TestMultiFileConvertWritesSeparateDocuments is the regression test for
// concatenated structured output.
//
// convert used to write every report of a multi-file run to stdout back to back.
// Markdown and text merge readably, but the structured formats do not: two JSON
// documents produce "}{" and fail to parse, two HTML documents give two
// doctypes, and two YAML documents without separators parse as a single mapping
// in which the later keys silently replace the earlier ones. That last case is
// the worst of the three, because it loses an entire configuration with no
// error at all.
//
// Multi-file runs now derive a path per input, the same as audit, so each report
// is a standalone document.
func TestMultiFileConvertWritesSeparateDocuments(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(fixture); os.IsNotExist(err) {
		t.Fatal("required testdata not available, ensure testdata/ is checked out")
	}

	content, err := os.ReadFile(fixture)
	require.NoError(t, err)

	tmpDir := t.TempDir()

	inputs := []string{"alpha.xml", "beta.xml"}
	for _, in := range inputs {
		path := filepath.Join(tmpDir, in)
		//nolint:gosec // in is a literal from the slice above, joined onto t.TempDir
		require.NoError(t, os.WriteFile(path, content, 0o600))
	}

	// Derived paths are relative names resolved against the working directory,
	// the same as audit, so run from the fixture directory and pass bare
	// filenames. That is also how an operator invokes it.
	t.Chdir(tmpDir)

	sharedSnap := captureSharedFlags()
	t.Cleanup(sharedSnap.restore)

	origFormat, origOutput, origForce := format, outputFile, force

	t.Cleanup(func() {
		format, outputFile, force = origFormat, origOutput, origForce
	})

	format = "json"
	outputFile = ""
	force = true

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	var stdout bytes.Buffer

	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&stdout)
	cmd.SetContext(context.Background())
	//nolint:staticcheck // SA1019: exercising deprecated flat field for backward-compat coverage.
	SetCommandContext(cmd, &CommandContext{
		Config: &config.Config{Format: "json"},
		Logger: testLogger,
	})

	require.NoError(t, runConvert(cmd, inputs))

	assert.Empty(t, stdout.String(),
		"a multi-file run should write to per-input files, not concatenate onto stdout")

	for _, in := range inputs {
		out := derivePerInputOutputPath(in, "", ".json")

		raw, err := os.ReadFile(out)
		require.NoErrorf(t, err, "expected a standalone report for %s", in)

		var doc map[string]any
		assert.NoErrorf(t, json.Unmarshal(raw, &doc),
			"%s is not a standalone JSON document", out)
	}
}
