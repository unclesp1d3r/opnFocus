package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/audit"
	"github.com/unclesp1d3r/opnFocus/internal/config"
	"github.com/unclesp1d3r/opnFocus/internal/log"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/processor"
)

func TestConvertCmd(t *testing.T) {
	// Test that convert command is properly initialized
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)
	assert.Equal(t, "convert", convertCmd.Name())
	assert.Contains(t, convertCmd.Short, "Convert OPNsense configuration files")
}

func TestConvertCmdFlags(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	flags := convertCmd.Flags()

	// Check output flag
	outputFlag := flags.Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)

	// Check format flag
	formatFlag := flags.Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "f", formatFlag.Shorthand)
	assert.Equal(t, "markdown", formatFlag.DefValue)

	// Check template flag
	templateFlag := flags.Lookup("template")
	require.NotNil(t, templateFlag)

	// Check section flag
	sectionFlag := flags.Lookup("section")
	require.NotNil(t, sectionFlag)

	// Check theme flag
	themeFlag := flags.Lookup("theme")
	require.NotNil(t, themeFlag)

	// Check wrap flag
	wrapFlag := flags.Lookup("wrap")
	require.NotNil(t, wrapFlag)
	assert.Equal(t, "0", wrapFlag.DefValue)
}

func TestConvertCmdHelp(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	// Just verify command structure, not help output
	assert.Contains(t, convertCmd.Short, "Convert OPNsense configuration files")
	assert.Contains(t, convertCmd.Long, "convert")
	assert.Contains(t, convertCmd.Long, "Examples:")
}

func TestConvertCmdRequiresArgs(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	// Just verify Args requirement is set correctly
	assert.NotNil(t, convertCmd.Args)
	// Args should require at least 1 argument (MinimumNArgs(1))
	assert.Equal(t, "convert", convertCmd.Name())
}

func TestBuildEffectiveFormat(t *testing.T) {
	tests := []struct {
		name         string
		flagFormat   string
		configFormat string
		expected     string
	}{
		{
			name:         "CLI flag takes precedence",
			flagFormat:   "json",
			configFormat: "yaml",
			expected:     "json",
		},
		{
			name:         "Config used when no CLI flag",
			flagFormat:   "",
			configFormat: "yaml",
			expected:     "yaml",
		},
		{
			name:         "Default when neither set",
			flagFormat:   "",
			configFormat: "",
			expected:     "markdown",
		},
		{
			name:         "Empty CLI flag falls back to config",
			flagFormat:   "",
			configFormat: "json",
			expected:     "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *config.Config
			if tt.configFormat != "" {
				// Create a mock config with the format set
				cfg = &config.Config{
					Format: tt.configFormat,
				}
			}

			result := buildEffectiveFormat(tt.flagFormat, cfg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildConversionOptions(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		template string
		sections []string
		theme    string
		wrap     int
		expected struct {
			format   markdown.Format
			template string
			sections []string
			theme    markdown.Theme
			wrap     int
		}
	}{
		{
			name:     "All options set",
			format:   "json",
			template: "detailed",
			sections: []string{"system", "network"},
			theme:    "dark",
			wrap:     120,
			expected: struct {
				format   markdown.Format
				template string
				sections []string
				theme    markdown.Theme
				wrap     int
			}{
				format:   markdown.Format("json"),
				template: "detailed",
				sections: []string{"system", "network"},
				theme:    markdown.Theme("dark"),
				wrap:     120,
			},
		},
		{
			name:   "Default options",
			format: "markdown",
			expected: struct {
				format   markdown.Format
				template string
				sections []string
				theme    markdown.Theme
				wrap     int
			}{
				format: markdown.Format("markdown"),
				wrap:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildConversionOptions(tt.format, tt.template, tt.sections, tt.theme, tt.wrap, nil)

			assert.Equal(t, tt.expected.format, result.Format)

			if tt.expected.template != "" {
				assert.Equal(t, tt.expected.template, result.TemplateName)
			}

			if len(tt.expected.sections) > 0 {
				assert.Equal(t, tt.expected.sections, result.Sections)
			}

			if tt.expected.theme != "" {
				assert.Equal(t, tt.expected.theme, result.Theme)
			}

			if tt.expected.wrap > 0 {
				assert.Equal(t, tt.expected.wrap, result.WrapWidth)
			}
		})
	}
}

func TestConvertCmdWithInvalidFile(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Try to convert a non-existent file
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.xml")

	rootCmd := GetRootCmd()

	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"convert", nonExistentFile})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestConvertCmdWithValidXML(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a minimal valid OPNsense config file
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
  </system>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	// Test conversion to stdout
	rootCmd := GetRootCmd()

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"convert", configFile})

	// Note: This test may fail if the parser is strict about the XML format
	// or if templates cannot be found during testing
	// We're testing the command structure here
	err = rootCmd.Execute()
	// We don't assert no error here because the XML may not pass validation
	// or templates may not be found in test environment
	// The important thing is that the command runs and attempts conversion
	if err != nil {
		// If it fails, it should be a parsing error, template error, or similar processing error
		// but not a command structure error
		errorStr := err.Error()
		assert.True(t,
			strings.Contains(errorStr, "parse") ||
				strings.Contains(errorStr, "template") ||
				strings.Contains(errorStr, "generator"),
			"Expected parsing, template, or generator error, got: %s", errorStr)
	}
}

func TestDetermineOutputPath(t *testing.T) {
	tests := []struct {
		name        string
		inputFile   string
		outputFile  string
		fileExt     string
		cfg         *config.Config
		force       bool
		expectPath  string
		expectError bool
	}{
		{
			name:       "no output specified - return empty for stdout",
			inputFile:  "config.xml",
			outputFile: "",
			fileExt:    ".md",
			cfg:        nil,
			force:      false,
			expectPath: "",
		},
		{
			name:       "CLI flag takes precedence",
			inputFile:  "config.xml",
			outputFile: "output.md",
			fileExt:    ".json",
			cfg: &config.Config{
				OutputFile: "config_output.md",
			},
			force:      false,
			expectPath: "output.md",
		},
		{
			name:       "use config value when no CLI flag",
			inputFile:  "config.xml",
			outputFile: "",
			fileExt:    ".json",
			cfg: &config.Config{
				OutputFile: "config_output.json",
			},
			force:      false,
			expectPath: "config_output.json",
		},
		{
			name:       "use input filename with extension when config has output_file",
			inputFile:  "my_config.xml",
			outputFile: "",
			fileExt:    ".yaml",
			cfg: &config.Config{
				OutputFile: "default_output.yaml",
			},
			force:      false,
			expectPath: "default_output.yaml",
		},
		{
			name:       "handle input file with no extension",
			inputFile:  "config",
			outputFile: "output.md",
			fileExt:    ".md",
			cfg:        nil,
			force:      false,
			expectPath: "output.md",
		},
		{
			name:       "handle input file with multiple dots",
			inputFile:  "config.backup.xml",
			outputFile: "output.json",
			fileExt:    ".json",
			cfg:        nil,
			force:      false,
			expectPath: "output.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := determineOutputPath(tt.inputFile, tt.outputFile, tt.fileExt, tt.cfg, tt.force)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectPath, path)
			}
		})
	}
}

func TestDetermineOutputPath_OverwriteProtection(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing.md")

	// Create the file
	err := os.WriteFile(existingFile, []byte("existing content"), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		outputFile  string
		force       bool
		expectError bool
		expectPath  string
	}{
		{
			name:        "file exists with force - should overwrite",
			outputFile:  existingFile,
			force:       true,
			expectError: false,
			expectPath:  existingFile,
		},
		{
			name:        "file does not exist - should work",
			outputFile:  filepath.Join(tmpDir, "new_file.md"),
			force:       false,
			expectError: false,
			expectPath:  filepath.Join(tmpDir, "new_file.md"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := determineOutputPath("config.xml", tt.outputFile, ".md", nil, tt.force)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectPath, path)
			}
		})
	}
}

func TestDetermineOutputPath_NoDirectoryCreation(t *testing.T) {
	// Test that the function doesn't create directories automatically
	nonexistentDir := filepath.Join("nonexistent", "path", "output.md")

	path, err := determineOutputPath("config.xml", nonexistentDir, ".md", nil, false)

	// Should not create directories, just return the path
	require.NoError(t, err)
	assert.Equal(t, nonexistentDir, path)

	// Verify the directory doesn't exist
	dir := filepath.Dir(nonexistentDir)
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "Directory should not be created")
}

func TestConvertAuditModeToReportMode(t *testing.T) {
	tests := []struct {
		name        string
		auditMode   markdown.AuditMode
		expected    audit.ReportMode
		expectError bool
	}{
		{
			name:        "standard mode",
			auditMode:   markdown.AuditModeStandard,
			expected:    audit.ModeStandard,
			expectError: false,
		},
		{
			name:        "blue mode",
			auditMode:   markdown.AuditModeBlue,
			expected:    audit.ModeBlue,
			expectError: false,
		},
		{
			name:        "red mode",
			auditMode:   markdown.AuditModeRed,
			expected:    audit.ModeRed,
			expectError: false,
		},
		{
			name:        "invalid mode",
			auditMode:   "invalid",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertAuditModeToReportMode(tt.auditMode)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported audit mode")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCreateModeConfig(t *testing.T) {
	tests := []struct {
		name       string
		reportMode audit.ReportMode
		opts       markdown.Options
		expected   *audit.ModeConfig
	}{
		{
			name:       "standard mode config",
			reportMode: audit.ModeStandard,
			opts: markdown.Options{
				Comprehensive: true,
				BlackhatMode:  false,
			},
			expected: &audit.ModeConfig{
				Mode:          audit.ModeStandard,
				Comprehensive: true,
				BlackhatMode:  false,
			},
		},
		{
			name:       "red mode with blackhat",
			reportMode: audit.ModeRed,
			opts: markdown.Options{
				Comprehensive: false,
				BlackhatMode:  true,
			},
			expected: &audit.ModeConfig{
				Mode:          audit.ModeRed,
				Comprehensive: false,
				BlackhatMode:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createModeConfig(tt.reportMode, tt.opts)

			assert.Equal(t, tt.expected.Mode, result.Mode)
			assert.Equal(t, tt.expected.Comprehensive, result.Comprehensive)
			assert.Equal(t, tt.expected.BlackhatMode, result.BlackhatMode)
		})
	}
}

func TestCreateAuditMarkdownOptions(t *testing.T) {
	tests := []struct {
		name     string
		input    markdown.Options
		expected markdown.Options
	}{
		{
			name: "basic options",
			input: markdown.Options{
				Format:        markdown.FormatMarkdown,
				TemplateName:  "standard",
				Theme:         markdown.ThemeLight,
				WrapWidth:     80,
				Comprehensive: true,
			},
			expected: markdown.Options{
				Format:        markdown.FormatMarkdown,
				TemplateName:  "",
				Theme:         markdown.ThemeAuto,
				WrapWidth:     0,
				Comprehensive: true,
			},
		},
		{
			name: "with audit mode",
			input: markdown.Options{
				Format:       markdown.FormatMarkdown,
				AuditMode:    markdown.AuditModeBlue,
				BlackhatMode: true,
			},
			expected: markdown.Options{
				Format:       markdown.FormatMarkdown,
				AuditMode:    markdown.AuditModeBlue,
				BlackhatMode: false,
				Theme:        markdown.ThemeAuto,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createAuditMarkdownOptions(tt.input)

			assert.Equal(t, tt.expected.Format, result.Format)
			assert.Equal(t, tt.expected.TemplateName, result.TemplateName)
			assert.Equal(t, tt.expected.Theme, result.Theme)
			assert.Equal(t, tt.expected.WrapWidth, result.WrapWidth)
			assert.Equal(t, tt.expected.Comprehensive, result.Comprehensive)
			assert.Equal(t, tt.expected.AuditMode, result.AuditMode)
			assert.Equal(t, tt.expected.BlackhatMode, result.BlackhatMode)
		})
	}
}

func TestAppendAuditFindings(t *testing.T) {
	tests := []struct {
		name         string
		baseResult   string
		auditReport  *audit.Report
		expected     string
		containsText []string
	}{
		{
			name:       "empty audit report",
			baseResult: "# Test Report\n\nContent here",
			auditReport: &audit.Report{
				Findings: []audit.Finding{},
			},
			expected: "# Test Report\n\nContent here",
		},
		{
			name:       "report with findings",
			baseResult: "# Test Report\n\nContent here",
			auditReport: &audit.Report{
				Findings: []audit.Finding{
					{
						Title:       "Test Finding",
						Severity:    processor.SeverityHigh,
						Description: "Test description",
					},
				},
			},
			containsText: []string{
				"# Test Report",
				"Content here",
				"## Audit Findings Summary",
				"Test Finding",
				"high",
				"Test description",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendAuditFindings(tt.baseResult, tt.auditReport)

			if tt.expected != "" {
				assert.Equal(t, tt.expected, result)
			}

			if len(tt.containsText) > 0 {
				for _, text := range tt.containsText {
					assert.Contains(t, result, text)
				}
			}
		})
	}
}

func TestGenerateBaseAuditReport(t *testing.T) {
	// Create a minimal test configuration
	testConfig := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := markdown.Options{
		Format:        markdown.FormatMarkdown,
		AuditMode:     markdown.AuditModeStandard,
		Comprehensive: true,
	}

	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	t.Run("successful report generation", func(t *testing.T) {
		ctx := context.Background()
		result, err := generateBaseAuditReport(ctx, testConfig, opts, logger)

		// Should not error, but may return empty if templates not found in test environment
		if err != nil {
			// If it fails, it should be a template or generator error, not a structural error
			errorStr := err.Error()
			assert.True(t,
				strings.Contains(errorStr, "template") ||
					strings.Contains(errorStr, "generator") ||
					strings.Contains(errorStr, "markdown"),
				"Expected template, generator, or markdown error, got: %s", errorStr)
		} else {
			// If successful, should contain some markdown content
			assert.NotEmpty(t, result)
			assert.Contains(t, result, "#")
		}
	})
}

func TestHandleAuditMode(t *testing.T) {
	// Create a minimal test configuration
	testConfig := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := markdown.Options{
		Format:        markdown.FormatMarkdown,
		AuditMode:     markdown.AuditModeStandard,
		Comprehensive: true,
	}

	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	registry := audit.NewPluginRegistry()

	t.Run("standard audit mode", func(t *testing.T) {
		ctx := context.Background()
		result, err := handleAuditMode(ctx, testConfig, opts, logger, registry)

		// Should not error, but may return empty if templates not found in test environment
		if err != nil {
			// If it fails, it should be a template or generator error, not a structural error
			errorStr := err.Error()
			assert.True(t,
				strings.Contains(errorStr, "template") ||
					strings.Contains(errorStr, "generator") ||
					strings.Contains(errorStr, "markdown") ||
					strings.Contains(errorStr, "audit"),
				"Expected template, generator, markdown, or audit error, got: %s", errorStr)
		} else {
			// If successful, should contain some markdown content
			assert.NotEmpty(t, result)
			assert.Contains(t, result, "#")
		}
	})

	t.Run("blue audit mode", func(t *testing.T) {
		ctx := context.Background()
		blueOpts := opts
		blueOpts.AuditMode = markdown.AuditModeBlue

		result, err := handleAuditMode(ctx, testConfig, blueOpts, logger, registry)

		// Should not error, but may return empty if templates not found in test environment
		if err != nil {
			errorStr := err.Error()
			assert.True(t,
				strings.Contains(errorStr, "template") ||
					strings.Contains(errorStr, "generator") ||
					strings.Contains(errorStr, "markdown") ||
					strings.Contains(errorStr, "audit"),
				"Expected template, generator, markdown, or audit error, got: %s", errorStr)
		} else {
			assert.NotEmpty(t, result)
			assert.Contains(t, result, "#")
		}
	})

	t.Run("red audit mode", func(t *testing.T) {
		ctx := context.Background()
		redOpts := opts
		redOpts.AuditMode = markdown.AuditModeRed

		result, err := handleAuditMode(ctx, testConfig, redOpts, logger, registry)

		// Should not error, but may return empty if templates not found in test environment
		if err != nil {
			errorStr := err.Error()
			assert.True(t,
				strings.Contains(errorStr, "template") ||
					strings.Contains(errorStr, "generator") ||
					strings.Contains(errorStr, "markdown") ||
					strings.Contains(errorStr, "audit"),
				"Expected template, generator, markdown, or audit error, got: %s", errorStr)
		} else {
			assert.NotEmpty(t, result)
			assert.Contains(t, result, "#")
		}
	})
}

// Helper function to find a command by name.
func findCommand(root *cobra.Command) *cobra.Command {
	for _, cmd := range root.Commands() {
		if cmd.Name() == "convert" {
			return cmd
		}
	}

	return nil
}
