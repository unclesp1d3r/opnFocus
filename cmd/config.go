// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"github.com/spf13/cobra"
)

// configCmd is the parent command for configuration management subcommands.
var configCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     cmdNameConfig,
	Short:   "Manage opnDossier configuration",
	GroupID: groupUtility,
	Long: `The 'config' command group provides utilities for managing opnDossier configuration.

Subcommands:
  show      Display the effective configuration with source indicators
  init      Generate a template configuration file with all options commented
  validate  Validate a configuration file for syntax and semantic errors

Examples:
  # Show current effective configuration
  opndossier config show

  # Show configuration in JSON format
  opndossier config show --json

  # Generate a new configuration template
  opndossier config init

  # Generate template at a specific path
  opndossier config init --output ~/.opnDossier.yaml

  # Validate an existing configuration file
  opndossier config validate ~/.opnDossier.yaml`,
}

// init registers the config command with the root command.
func init() {
	rootCmd.AddCommand(configCmd)
}
