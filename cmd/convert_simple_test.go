package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestDetermineOutputPathSimple covers destination resolution. Overwrite
// protection moved to confirmOverwrite, so this function no longer touches the
// filesystem and cannot fail.
func TestDetermineOutputPathSimple(t *testing.T) {
	if got := determineOutputPath("", nil); got != "" {
		t.Errorf("no output configured should mean stdout, got: %s", got)
	}

	if got := determineOutputPath("output.md", nil); got != "output.md" {
		t.Errorf("Expected 'output.md', got: %s", got)
	}

	cfg := &config.Config{OutputFile: "config-output.md"}
	if got := determineOutputPath("", cfg); got != "config-output.md" {
		t.Errorf("Expected 'config-output.md', got: %s", got)
	}

	// The CLI flag wins over a configured output_file.
	if got := determineOutputPath("flag.md", cfg); got != "flag.md" {
		t.Errorf("CLI flag should take precedence, got: %s", got)
	}
}

// TestGenerateOutputByFormatSimple tests the format-based generation.
func TestGenerateOutputByFormatSimple(t *testing.T) {
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
		},
	}

	ctx := context.Background()

	// Test markdown format
	opt := converter.Options{
		Format: converter.FormatMarkdown,
		Theme:  converter.ThemeAuto,
	}

	result, handler, err := generateOutputByFormat(ctx, device, opt, logger)
	if err != nil {
		t.Errorf("Unexpected error for markdown: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for markdown")
	}
	if handler == nil {
		t.Errorf("Expected non-nil handler for markdown")
	} else if handler.FileExtension() != ".md" {
		t.Errorf("Expected .md extension, got: %s", handler.FileExtension())
	}

	// Test JSON format - programmatic generation should succeed
	opt.Format = converter.FormatJSON
	jsonResult, jsonHandler, err := generateOutputByFormat(ctx, device, opt, logger)
	if err != nil {
		t.Errorf("JSON format should succeed with programmatic generator: %v", err)
	}
	if jsonResult == "" {
		t.Errorf("Expected non-empty result for JSON format")
	}
	if jsonHandler == nil {
		t.Errorf("Expected non-nil handler for JSON")
	} else if jsonHandler.FileExtension() != ".json" {
		t.Errorf("Expected .json extension, got: %s", jsonHandler.FileExtension())
	}

	// Test unknown format (should return an error)
	opt.Format = converter.Format("unknown")
	_, unknownHandler, err := generateOutputByFormat(ctx, device, opt, logger)
	if err == nil {
		t.Errorf("Expected error for unknown format, got nil")
	} else if !errors.Is(err, ErrUnsupportedOutputFormat) {
		t.Errorf("Expected ErrUnsupportedOutputFormat, got: %v", err)
	}
	if unknownHandler != nil {
		t.Errorf("Expected nil handler for unknown format, got: %v", unknownHandler)
	}
}

// TestGenerateWithProgrammaticGeneratorSimple tests the programmatic generator function.
func TestGenerateWithProgrammaticGeneratorSimple(t *testing.T) {
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
		},
	}

	ctx := context.Background()

	// Test programmatic mode (default)
	opt := converter.Options{
		Format: converter.FormatMarkdown,
		Theme:  converter.ThemeAuto,
	}

	result, err := generateWithProgrammaticGenerator(ctx, device, opt, logger)
	if err != nil {
		t.Errorf("Unexpected error for programmatic mode: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for programmatic mode")
	}
}

// TestBuildConversionOptionsSimple tests option building.
func TestBuildConversionOptionsSimple(t *testing.T) {
	// Save original values
	origSections := sharedSections
	origWrapWidth := sharedWrapWidth
	origComprehensive := sharedComprehensive
	origIncludeTunables := sharedIncludeTunables

	defer func() {
		sharedSections = origSections
		sharedWrapWidth = origWrapWidth
		sharedComprehensive = origComprehensive
		sharedIncludeTunables = origIncludeTunables
	}()

	// Test with nil config
	sharedSections = nil
	sharedWrapWidth = -1
	sharedComprehensive = false
	sharedIncludeTunables = false

	opts := buildConversionOptions("markdown", nil)
	if opts.Format == "" {
		t.Errorf("Expected format to be set")
	}

	// Test with config
	//nolint:staticcheck // SA1019: exercising deprecated flat field for backward-compat coverage.
	cfg := &config.Config{
		Theme: "dark",
	}
	opts = buildConversionOptions("json", cfg)
	if string(opts.Theme) != "dark" {
		t.Errorf("Expected theme 'dark', got %s", opts.Theme)
	}
}
