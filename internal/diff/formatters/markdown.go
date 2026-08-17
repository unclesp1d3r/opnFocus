// Package formatters provides output formatting for diff results.
package formatters

import (
	"fmt"
	"io"
	"slices"
	"strings"

	convfmt "github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/diff"
)

// MarkdownFormatter formats diff results as markdown.
type MarkdownFormatter struct {
	writer io.Writer
}

// NewMarkdownFormatter creates a new markdown formatter.
func NewMarkdownFormatter(writer io.Writer) *MarkdownFormatter {
	return &MarkdownFormatter{
		writer: writer,
	}
}

// Format formats the diff result as markdown.
func (f *MarkdownFormatter) Format(result *diff.Result) error {
	// Header
	if _, err := fmt.Fprintln(f.writer, "# Configuration Diff"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	// Metadata
	if err := f.formatMetadata(result); err != nil {
		return err
	}

	// Summary
	if err := f.formatSummary(result); err != nil {
		return err
	}

	if !result.HasChanges() {
		_, err := fmt.Fprintln(f.writer, "*No changes detected.*")
		return err
	}

	// Changes by section
	return f.formatChanges(result)
}

// formatMetadata outputs the comparison metadata.
func (f *MarkdownFormatter) formatMetadata(result *diff.Result) error {
	meta := result.Metadata

	if meta.OldFile != "" {
		if _, err := fmt.Fprintf(f.writer, "**Old File:** %s\n", codeSpan(meta.OldFile)); err != nil {
			return err
		}
	}
	if meta.NewFile != "" {
		if _, err := fmt.Fprintf(f.writer, "**New File:** %s\n", codeSpan(meta.NewFile)); err != nil {
			return err
		}
	}
	if !meta.ComparedAt.IsZero() {
		if _, err := fmt.Fprintf(
			f.writer,
			"**Compared At:** %s\n",
			meta.ComparedAt.Format("2006-01-02 15:04:05"),
		); err != nil {
			return err
		}
	}
	if meta.ToolVersion != "" {
		if _, err := fmt.Fprintf(f.writer, "**Tool Version:** %s\n", meta.ToolVersion); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatSummary outputs the change summary.
func (f *MarkdownFormatter) formatSummary(result *diff.Result) error {
	if _, err := fmt.Fprintln(f.writer, "## Summary"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	summary := result.Summary

	// Summary table
	if _, err := fmt.Fprintln(f.writer, "| Type | Count |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer, "|------|-------|"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "| Added | %d |\n", summary.Added); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "| Removed | %d |\n", summary.Removed); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "| Modified | %d |\n", summary.Modified); err != nil {
		return err
	}
	if summary.Reordered > 0 {
		if _, err := fmt.Fprintf(f.writer, "| Reordered | %d |\n", summary.Reordered); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(f.writer, "| **Total** | **%d** |\n", summary.Total); err != nil {
		return err
	}
	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatChanges outputs all changes grouped by section.
func (f *MarkdownFormatter) formatChanges(result *diff.Result) error {
	bySection := result.ChangesBySection()

	// Get sorted section names for deterministic output
	sections := make([]diff.Section, 0, len(bySection))
	for section := range bySection {
		sections = append(sections, section)
	}
	slices.SortFunc(sections, func(a, b diff.Section) int {
		return strings.Compare(a.String(), b.String())
	})

	for _, section := range sections {
		changes := bySection[section]
		if err := f.formatSection(section, changes); err != nil {
			return err
		}
	}

	return nil
}

// formatSection outputs a single section with its changes.
func (f *MarkdownFormatter) formatSection(section diff.Section, changes []diff.Change) error {
	// Section header
	if _, err := fmt.Fprintf(f.writer, "## %s\n\n", capitalizeFirst(section.String())); err != nil {
		return err
	}

	// Changes table
	if _, err := fmt.Fprintln(f.writer, "| Change | Description | Security |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer, "|--------|-------------|----------|"); err != nil {
		return err
	}

	for _, change := range changes {
		symbol := changeSymbolMarkdown(change.Type)
		security := ""
		if change.SecurityImpact != "" {
			security = securityBadge(change.SecurityImpact)
		}

		if _, err := fmt.Fprintf(f.writer, "| %s | %s | %s |\n",
			symbol, escapeMarkdown(change.Description), security); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	// Detailed changes
	if _, err := fmt.Fprintln(f.writer, "<details>"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer, "<summary>Show details</summary>"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	for _, change := range changes {
		if err := f.formatChangeDetails(change); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(f.writer, "</details>"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatChangeDetails outputs detailed information for a single change.
func (f *MarkdownFormatter) formatChangeDetails(change diff.Change) error {
	symbol := changeSymbolMarkdown(change.Type)
	if _, err := fmt.Fprintf(f.writer, "### %s %s\n\n", symbol, escapeMarkdown(change.Description)); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(f.writer, "- **Path:** %s\n", codeSpan(change.Path)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "- **Type:** %s\n", change.Type.String()); err != nil {
		return err
	}

	if change.SecurityImpact != "" {
		if _, err := fmt.Fprintf(
			f.writer,
			"- **Security Impact:** %s\n",
			securityBadge(change.SecurityImpact),
		); err != nil {
			return err
		}
	}

	if change.OldValue != "" {
		if _, err := fmt.Fprintf(f.writer, "- **Old Value:** %s\n", codeSpan(change.OldValue)); err != nil {
			return err
		}
	}
	if change.NewValue != "" {
		if _, err := fmt.Fprintf(f.writer, "- **New Value:** %s\n", codeSpan(change.NewValue)); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(f.writer)
	return err
}

// changeSymbolMarkdown returns a markdown-formatted symbol for the change type.
func changeSymbolMarkdown(changeType diff.ChangeType) string {
	switch changeType {
	case diff.ChangeAdded:
		return "**+**"
	case diff.ChangeRemoved:
		return "**-**"
	case diff.ChangeModified:
		return "**~**"
	case diff.ChangeReordered:
		return "**↕**"
	default:
		return "**?**"
	}
}

// securityBadge returns a formatted security impact badge.
func securityBadge(impact string) string {
	switch strings.ToLower(impact) {
	case string(diff.SecurityImpactHigh):
		return "🔴 HIGH"
	case string(diff.SecurityImpactMedium):
		return "🟡 MEDIUM"
	case string(diff.SecurityImpactLow):
		return "🟢 LOW"
	default:
		return impact
	}
}

// escapeMarkdown escapes markdown metacharacters in a config-derived string.
//
// This used to escape pipes only, which kept a table row intact but not the
// value inert. Change descriptions carry configuration text (the interface and
// firewall analyzers interpolate iface.Description and the rule description),
// and the HTML diff report renders with raw HTML passthrough on for its
// <details> wrappers, so `<img src=x onerror=...>` became live markup.
func escapeMarkdown(s string) string {
	return convfmt.EscapeMarkdownValue(s)
}

// codeSpan wraps value in a markdown code span sized to its contents.
//
// Code span contents are literal and goldmark HTML-escapes them on render.
// Backslash escaping is wrong here: it does not apply inside a code span and
// would show up literally.
//
// The one way out is a backtick run matching the fence, so the fence is sized to
// one more than the longest run in the value. A value starting or ending with a
// backtick also needs the padding spaces CommonMark strips back off. Newlines
// are collapsed because a code span cannot span lines.
func codeSpan(value string) string {
	value = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(value)

	longest, current := 0, 0

	for _, r := range value {
		if r != '`' {
			current = 0

			continue
		}

		current++
		if current > longest {
			longest = current
		}
	}

	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") {
		return fence + " " + value + " " + fence
	}

	return fence + value + fence
}
