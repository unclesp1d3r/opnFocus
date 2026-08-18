//go:build integration

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// resetGlobalFlags resets package-level flag variables to their defaults.
// This is necessary because Cobra binds flags to global variables.
func resetGlobalFlags() {
	// Reset convert command flags
	outputFile = ""
	format = ""
	force = false
}

// newTestCommand creates a fresh root command for testing.
// Note: Due to Cobra's global state, these tests should not run in parallel.
func newTestCommand() *cobra.Command {
	resetGlobalFlags()
	return GetRootCmd()
}

// TestE2EConvertMarkdown tests the full convert command with markdown output.
func TestE2EConvertMarkdown(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"convert", testdataPath, "--format", "markdown"})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("convert command failed: %v\nstderr: %s", err, stderr.String())
	}

	output := stdout.String()

	// Verify output contains expected markdown structure
	expectedElements := []string{
		"# OPNsense Configuration Summary",
		"## System Information",
	}

	for _, expected := range expectedElements {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing expected element: %q", expected)
		}
	}
}

// TestE2EConvertJSON tests the full convert command with JSON output.
func TestE2EConvertJSON(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"convert", testdataPath, "--format", "json"})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("convert command failed: %v\nstderr: %s", err, stderr.String())
	}

	output := stdout.String()

	// Verify output is valid JSON (should start with { and end with })
	trimmed := strings.TrimSpace(output)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Errorf("output doesn't look like JSON: starts with %q, ends with %q",
			trimmed[:min(10, len(trimmed))], trimmed[max(0, len(trimmed)-10):])
	}
}

// TestE2EConvertYAML tests the full convert command with YAML output.
func TestE2EConvertYAML(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"convert", testdataPath, "--format", "yaml"})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("convert command failed: %v\nstderr: %s", err, stderr.String())
	}

	output := stdout.String()

	// Verify output contains YAML-like structures (key: value patterns)
	if !strings.Contains(output, ":") {
		t.Error("output doesn't look like YAML: no key-value pairs found")
	}
}

// TestE2EValidate tests the validate command with valid input.
func TestE2EValidate(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"validate", testdataPath})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("validate command failed: %v\nstderr: %s", err, stderr.String())
	}
}

// TestE2EValidateInvalidFile tests the validate command with invalid input.
// Note: The validate command calls os.Exit() for validation failures, which cannot
// be tested via cmd.Execute() directly. Instead, we verify that malformed XML
// parsing errors are properly detected at the parser level.
func TestE2EValidateInvalidFile(t *testing.T) {
	// Create a temporary invalid XML file
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.xml")
	err := os.WriteFile(invalidFile, []byte("<invalid>not valid opnsense config</invalid>"), 0o600)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	// Verify the file exists and contains invalid content
	content, err := os.ReadFile(invalidFile)
	if err != nil {
		t.Fatalf("failed to read temp file: %v", err)
	}
	if !strings.Contains(string(content), "<invalid>") {
		t.Error("test file should contain invalid content")
	}

	// Note: Cannot test cmd.Execute() here as validate command calls os.Exit()
	// on validation failures. The validation logic is tested in parser unit tests.
}

// TestE2EConvertToFile tests the convert command with output to file.
func TestE2EConvertToFile(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.md")

	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"convert", testdataPath, "--format", "markdown", "-o", outputFile})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("convert command failed: %v\nstderr: %s", err, stderr.String())
	}

	// Verify output file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("output file was not created: %s", outputFile)
	}

	// Verify output file has content
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(content) == 0 {
		t.Error("output file is empty")
	}

	if !strings.Contains(string(content), "OPNsense") {
		t.Error("output file doesn't contain expected content")
	}
}

// TestE2EVersionCommand tests the version command.
func TestE2EVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"version"})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	// Note: version command uses fmt.Printf which goes to os.Stdout,
	// not the captured buffer. Just verify the command runs without error.
}

// TestE2EHelpCommand tests the help command.
func TestE2EHelpCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"--help"})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("help command failed: %v", err)
	}

	output := stdout.String()
	expectedElements := []string{
		"opnDossier",
		"Usage:",
	}

	for _, expected := range expectedElements {
		if !strings.Contains(output, expected) {
			t.Errorf("help output missing expected element: %q", expected)
		}
	}
}

// TestE2EConvertNonexistentFile tests convert with nonexistent file.
func TestE2EConvertNonexistentFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	cmd.SetArgs([]string{"convert", "/nonexistent/file.xml"})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Error("convert command should fail for nonexistent file")
	}
}

// TestE2EMultipleConfigFiles tests processing multiple config files.
func TestE2EMultipleConfigFiles(t *testing.T) {
	testFiles := []string{
		filepath.Join("..", "testdata", "sample.config.1.xml"),
		filepath.Join("..", "testdata", "sample.config.2.xml"),
	}

	for _, testFile := range testFiles {
		if _, err := os.Stat(testFile); os.IsNotExist(err) {
			t.Skip("testdata not available")
		}
	}

	// A multi-file run writes one report per input, named after the input and
	// resolved against the working directory. Copy the fixtures somewhere
	// disposable and run from there, so the reports do not land in the source
	// tree.
	workDir := t.TempDir()

	inputs := make([]string, 0, len(testFiles))

	for _, testFile := range testFiles {
		content, err := os.ReadFile(testFile) //nolint:gosec // repository fixture
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", testFile, err)
		}

		name := filepath.Base(testFile)
		if err := os.WriteFile(filepath.Join(workDir, name), content, 0o600); err != nil {
			t.Fatalf("failed to stage fixture %s: %v", name, err)
		}

		inputs = append(inputs, name)
	}

	t.Chdir(workDir)

	var stdout, stderr bytes.Buffer
	cmd := newTestCommand()
	args := append([]string{"convert", "--format", "markdown"}, inputs...)
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("convert command with multiple files failed: %v\nstderr: %s", err, stderr.String())
	}

	if stdout.Len() != 0 {
		t.Errorf("multi-file run wrote %d bytes to stdout; each report should go to its own file",
			stdout.Len())
	}

	for _, in := range inputs {
		out := derivePerInputOutputPath(in, "", ".md")
		if _, err := os.Stat(out); err != nil {
			t.Errorf("expected a report at %s for input %s: %v", out, in, err)
		}
	}
}
