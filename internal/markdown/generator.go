package markdown

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/charmbracelet/log"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// Generator interface for creating documentation in various formats.
type Generator interface {
	// Generate creates documentation in a specified format from the provided OPNsense configuration.
	Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error)
}

// markdownGenerator is the default implementation that wraps the old Markdown logic.
type markdownGenerator struct {
	templates *template.Template
	logger    *log.Logger
}

// NewMarkdownGenerator creates a new Generator that produces documentation in Markdown, JSON, or YAML formats using predefined templates.
// It attempts to load and parse templates from multiple possible filesystem paths and returns an error if none are found or parsing fails.
func NewMarkdownGenerator(logger *log.Logger) (Generator, error) {
	if logger == nil {
		logger = log.NewWithOptions(os.Stderr, log.Options{})
	}
	return NewMarkdownGeneratorWithTemplates(logger, "")
}

// NewMarkdownGeneratorWithTemplates creates a new Generator with custom template directory support.
// If templateDir is provided, it will be used first for template overrides, falling back to built-in templates.
func NewMarkdownGeneratorWithTemplates(logger *log.Logger, templateDir string) (Generator, error) {
	if logger == nil {
		logger = log.NewWithOptions(os.Stderr, log.Options{})
	}

	// Create template function map with custom functions
	funcMap := createTemplateFuncMap()

	// Build list of template paths
	possiblePaths := buildTemplatePaths(templateDir)

	// Parse templates from all possible paths
	templates, err := parseTemplatesFromPaths(possiblePaths, funcMap)
	if err != nil {
		return nil, err
	}

	return &markdownGenerator{
		templates: templates,
		logger:    logger,
	}, nil
}

// createTemplateFuncMap creates a function map with sprig functions and custom template functions.
func createTemplateFuncMap() template.FuncMap {
	// Create template with sprig functions
	funcMap := sprig.FuncMap()

	// Add custom functions that aren't provided by sprig
	funcMap["isLast"] = func(index, slice any) bool {
		switch s := slice.(type) {
		case map[string]any:
			// For maps, we can't determine order, so always return false for now
			return false
		case []any:
			if i, ok := index.(int); ok {
				return i == len(s)-1
			}
		}
		return false
	}

	// Escape markdown table cell content to prevent breaking table structure
	funcMap["escapeTableContent"] = escapeTableContent

	// Add STIG-specific template functions
	funcMap["getSTIGDescription"] = func(controlID string) string {
		// This is a placeholder function for STIG description lookup
		// In a real implementation, this would look up the description from a STIG database
		return fmt.Sprintf("STIG control %s description", controlID)
	}

	// Add SANS-specific template functions
	funcMap["getSANSDescription"] = func(controlID string) string {
		// This is a placeholder function for SANS description lookup
		// In a real implementation, this would look up the description from a SANS database
		return fmt.Sprintf("SANS control %s description", controlID)
	}

	// Add security zone functions
	funcMap["getSecurityZone"] = func(interfaceName string) string {
		// This is a placeholder function for security zone lookup
		// In a real implementation, this would determine the security zone based on interface
		switch interfaceName {
		case "wan":
			return "Untrusted"
		case "lan":
			return "Trusted"
		case "dmz":
			return "DMZ"
		default:
			return "Unknown"
		}
	}

	// Add other common template functions that might be missing
	funcMap["getPortDescription"] = func(port string) string {
		return "Port " + port
	}

	funcMap["getProtocolDescription"] = func(protocol string) string {
		return "Protocol " + protocol
	}

	funcMap["getRiskLevel"] = func(severity string) string {
		switch strings.ToLower(severity) {
		case "high", "critical":
			return "High Risk"
		case "medium":
			return "Medium Risk"
		case "low":
			return "Low Risk"
		default:
			return "Unknown Risk"
		}
	}

	// Add placeholder functions for missing template functions
	funcMap["getRuleCompliance"] = func(_ any) string {
		return "Rule Compliance Check Placeholder"
	}

	funcMap["getNATRiskLevel"] = func(_ any) string {
		return "NAT Rule Risk Level Placeholder"
	}

	funcMap["getNATRecommendation"] = func(_ any) string {
		return "NAT Rule Recommendation Placeholder"
	}

	funcMap["getCertSecurityStatus"] = func(_ any) string {
		return "Certificate Security Status Placeholder"
	}

	funcMap["getDHCPSecurity"] = func(_ any) string {
		return "DHCP Security Placeholder"
	}

	funcMap["getRouteSecurityZone"] = func(_ any) string {
		return "Route Security Zone Placeholder"
	}

	return funcMap
}

// escapeTableContent escapes markdown table cell content to prevent breaking table structure.
func escapeTableContent(content any) string {
	if content == nil {
		return ""
	}
	str := fmt.Sprintf("%v", content)
	// Escape pipe characters by replacing | with \|
	str = strings.ReplaceAll(str, "|", "\\|")
	// Replace carriage return + newline first to avoid double replacement
	str = strings.ReplaceAll(str, "\r\n", "<br>")
	// Replace remaining newlines with <br> for HTML rendering
	str = strings.ReplaceAll(str, "\n", "<br>")
	// Replace remaining carriage returns with <br>
	str = strings.ReplaceAll(str, "\r", "<br>")
	return str
}

// buildTemplatePaths builds a list of possible template paths including custom and default locations.
func buildTemplatePaths(templateDir string) []string {
	var possiblePaths []string

	// Add custom template directory paths first if specified
	if templateDir != "" {
		possiblePaths = append(possiblePaths,
			filepath.Join(templateDir, "*.tmpl"),
			filepath.Join(templateDir, "reports", "*.tmpl"),
		)
	}

	// Add default template paths
	possiblePaths = append(possiblePaths,
		"internal/templates/*.tmpl",               // When running from project root
		"internal/templates/reports/*.tmpl",       // Audit mode templates
		"../../internal/templates/*.tmpl",         // When running from test directory
		"../../internal/templates/reports/*.tmpl", // Audit mode templates from test
		"../templates/*.tmpl",                     // Alternative relative path
		"../templates/reports/*.tmpl",             // Audit mode templates alternative path
	)

	return possiblePaths
}

// parseTemplatesFromPaths attempts to parse templates from multiple possible paths.
func parseTemplatesFromPaths(possiblePaths []string, funcMap template.FuncMap) (*template.Template, error) {
	templates := template.New("opnfocus").Funcs(funcMap)
	var lastErr error
	templatesLoaded := 0

	for _, path := range possiblePaths {
		matches, err := filepath.Glob(path)
		if err != nil {
			lastErr = fmt.Errorf("failed to glob pattern %s: %w", path, err)
			continue
		}

		for _, match := range matches {
			// Get template name from filename (without directory)
			templateName := filepath.Base(match)

			// Skip if template with this name already exists (custom templates take precedence)
			if templates.Lookup(templateName) != nil {
				continue
			}

			// Parse the individual template file
			_, err := templates.ParseFiles(match)
			if err != nil {
				lastErr = fmt.Errorf("failed to parse template %s: %w", match, err)
			} else {
				templatesLoaded++
			}
		}
	}

	// Only return error if no templates were successfully loaded
	if templatesLoaded == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("no templates found in any of the specified paths")
	}

	return templates, nil
}

// Generate converts an OPNsense configuration to the specified format using the Options provided.
func (g *markdownGenerator) Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error) {
	if cfg == nil {
		return "", ErrNilConfiguration
	}

	if err := opts.Validate(); err != nil {
		return "", fmt.Errorf("invalid options: %w", err)
	}

	// Enrich the model with calculated fields and analysis data
	enrichedCfg := model.EnrichDocument(cfg)
	if enrichedCfg == nil {
		return "", ErrNilConfiguration
	}

	// Add metadata for template rendering
	metadata := struct {
		*model.EnrichedOpnSenseDocument

		Generated   string
		ToolVersion string
	}{
		EnrichedOpnSenseDocument: enrichedCfg,
		Generated:                time.Now().Format(time.RFC3339),
		ToolVersion:              constants.Version,
	}

	switch opts.Format {
	case FormatMarkdown:
		return g.generateMarkdown(ctx, metadata, opts)
	case FormatJSON:
		return g.generateJSON(ctx, enrichedCfg, opts)
	case FormatYAML:
		return g.generateYAML(ctx, enrichedCfg, opts)
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

// generateMarkdown generates markdown output using templates.
func (g *markdownGenerator) generateMarkdown(_ context.Context, data any, opts Options) (string, error) {
	templateName := g.selectTemplate(opts)

	// Check if the template exists
	tmpl := g.templates.Lookup(templateName)
	if tmpl == nil {
		return "", fmt.Errorf("%w: %s", ErrTemplateNotFound, templateName)
	}

	// Render the template with the data
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	// Return raw markdown - let the display package handle theme-aware rendering
	return buf.String(), nil
}

// mapTemplateName converts logical template names to actual filenames.
func mapTemplateName(logicalName string) string {
	switch logicalName {
	case "standard":
		return "opnsense_report.md.tmpl"
	case "comprehensive":
		return "opnsense_report_comprehensive.md.tmpl"
	case "json":
		return "json_output.tmpl"
	case "yaml":
		return "yaml_output.tmpl"
	case "blue":
		return "blue.md.tmpl"
	case "red":
		return "red.md.tmpl"
	case "blue-enhanced":
		return "blue_enhanced.md.tmpl"
	default:
		// If it's not a known logical name, assume it's already a filename
		return logicalName
	}
}

// selectTemplate determines which template to use based on the options provided.
func (g *markdownGenerator) selectTemplate(opts Options) string {
	// If a custom template name is specified, use it
	if opts.TemplateName != "" {
		return mapTemplateName(opts.TemplateName)
	}

	// If audit mode is specified, use audit mode templates
	if opts.AuditMode != "" {
		switch opts.AuditMode {
		case AuditModeStandard:
			return "standard.md.tmpl"
		case AuditModeBlue:
			return "blue.md.tmpl"
		case AuditModeRed:
			return "red.md.tmpl"
		}
	}

	// Fall back to comprehensive or standard templates
	if opts.Comprehensive {
		return "opnsense_report_comprehensive.md.tmpl"
	}
	return "opnsense_report.md.tmpl"
}

// generateJSON generates JSON output.
func (g *markdownGenerator) generateJSON(
	_ context.Context,
	cfg *model.EnrichedOpnSenseDocument,
	_ Options,
) (string, error) {
	return g.generateDataOutput("json_output.tmpl", cfg)
}

// generateYAML generates YAML output.
func (g *markdownGenerator) generateYAML(
	_ context.Context,
	cfg *model.EnrichedOpnSenseDocument,
	_ Options,
) (string, error) {
	return g.generateDataOutput("yaml_output.tmpl", cfg)
}

// generateDataOutput is a helper function that generates output for JSON/YAML using templates.
func (g *markdownGenerator) generateDataOutput(
	templateName string,
	cfg *model.EnrichedOpnSenseDocument,
) (string, error) {
	// Use template data with GeneratedAt for template
	metadata := struct {
		*model.EnrichedOpnSenseDocument

		GeneratedAt string
		ToolVersion string
	}{
		EnrichedOpnSenseDocument: cfg,
		GeneratedAt:              time.Now().Format(time.RFC3339),
		ToolVersion:              constants.Version,
	}

	// Use the specified template
	tmpl := g.templates.Lookup(templateName)
	if tmpl == nil {
		// Fallback to simple JSON/YAML if template not found
		configJSON, err := json.Marshal(cfg) //nolint:musttag // EnrichedOpnSenseDocument has proper json tags
		if err != nil {
			return "", fmt.Errorf("failed to marshal configuration to JSON: %w", err)
		}

		// Determine fallback format based on template name
		if strings.Contains(templateName, "json") {
			return fmt.Sprintf(`{
			"generated": "%s",
			"tool_version": "%s",
			"configuration": %s
		}`, time.Now().Format(time.RFC3339), constants.Version, string(configJSON)), nil
		}
		return fmt.Sprintf(`generated: %s
tool_version: "%s"
configuration: %s
`, time.Now().Format(time.RFC3339), constants.Version, string(configJSON)), nil
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, metadata)
	if err != nil {
		return "", fmt.Errorf("failed to execute %s template: %w", templateName, err)
	}

	return buf.String(), nil
}
