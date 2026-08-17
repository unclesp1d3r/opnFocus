// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer"
	"github.com/spf13/cobra"
)

// Sanitize command flag variables.
var (
	sanitizeMode        string //nolint:gochecknoglobals // Cobra flag variable
	sanitizeOutputFile  string //nolint:gochecknoglobals // Output file path
	sanitizeMappingFile string //nolint:gochecknoglobals // Mapping file output path
	sanitizeForce       bool   //nolint:gochecknoglobals // Force overwrite without prompt
)

// Sanitize mode constants matching the sanitizer package.
const (
	// SanitizeModeAggressive redacts all sensitive data for public sharing.
	SanitizeModeAggressive = "aggressive"
	// SanitizeModeModerate redacts most data but preserves some network structure.
	SanitizeModeModerate = "moderate"
	// SanitizeModeMinimal redacts only the most sensitive data (credentials and authserver values).
	SanitizeModeMinimal = "minimal"
)

// Static errors for sanitize command.
var (
	// ErrInvalidSanitizeMode is returned when an invalid sanitization mode is specified.
	ErrInvalidSanitizeMode = errors.New("invalid sanitize mode")

	// ErrSanitizePathCollision is returned when the input file, --output, and
	// --mapping paths do not all refer to distinct files.
	ErrSanitizePathCollision = errors.New("sanitize path collision")
)

// opndossier sanitize config.xml --mode aggressive --output sanitized.xml --mapping map.json --force.
func init() {
	rootCmd.AddCommand(sanitizeCmd)

	// Mode flag
	sanitizeCmd.Flags().
		StringVarP(&sanitizeMode, "mode", "m", SanitizeModeModerate,
			"Sanitization mode: aggressive (public sharing), moderate (internal sharing), minimal (credentials + authserver values)")
	setFlagAnnotation(sanitizeCmd.Flags(), "mode", []flagCategory{categorySanitize})

	// Output flag
	sanitizeCmd.Flags().
		StringVarP(&sanitizeOutputFile, "output", "o", "",
			"Output file path for sanitized configuration (default: print to console)")
	setFlagAnnotation(sanitizeCmd.Flags(), "output", []flagCategory{categoryOutput})

	// Mapping file flag
	sanitizeCmd.Flags().
		StringVar(&sanitizeMappingFile, "mapping", "",
			"Output path for mapping file (JSON) that documents original→redacted mappings")
	setFlagAnnotation(sanitizeCmd.Flags(), "mapping", []flagCategory{categoryOutput})

	// Force flag
	sanitizeCmd.Flags().
		BoolVar(&sanitizeForce, "force", false,
			"Force overwrite existing files without prompting for confirmation")
	setFlagAnnotation(sanitizeCmd.Flags(), "force", []flagCategory{categoryOutput})

	// Register flag completion functions
	registerSanitizeFlagCompletions(sanitizeCmd)

	// Flag groups for better organization
	sanitizeCmd.Flags().SortFlags = false
}

// registerSanitizeFlagCompletions registers shell completion handlers for the sanitize command's flags.
// It attaches a completer for the `--mode` flag that suggests valid sanitize modes (aggressive, moderate, minimal).
//
// cmd is the Cobra command representing the sanitize subcommand.
func registerSanitizeFlagCompletions(cmd *cobra.Command) {
	// Mode flag completion
	if err := cmd.RegisterFlagCompletionFunc("mode", ValidSanitizeModes); err != nil {
		logger.Debug("failed to register mode completion", "error", err)
	}
}

// ValidSanitizeModes provides tab-completion candidates for the sanitize command's --mode flag.
// It returns the three valid modes with brief descriptions and a shell directive that disables file completion.
func ValidSanitizeModes(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		SanitizeModeAggressive + "\tRedact all sensitive data for public sharing",
		SanitizeModeModerate + "\tRedact most sensitive data, preserve network structure",
		SanitizeModeMinimal + "\tRedact credentials and authserver values",
	}, cobra.ShellCompDirectiveNoFileComp
}

// sanitizeCmd is the cobra.Command for the sanitize subcommand.
var sanitizeCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:               "sanitize [file]",
	Short:             "Redact sensitive data from OPNsense configuration files.",
	GroupID:           groupUtility,
	ValidArgsFunction: ValidXMLFiles,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		// Validate sanitize mode
		if !sanitizer.IsValidMode(sanitizeMode) {
			validModes := []string{SanitizeModeAggressive, SanitizeModeModerate, SanitizeModeMinimal}
			return fmt.Errorf("%w: %q, must be one of: %s",
				ErrInvalidSanitizeMode, sanitizeMode, strings.Join(validModes, ", "))
		}
		return nil
	},
	Long: `The 'sanitize' command redacts sensitive information from OPNsense configuration
files, making them safe to share for troubleshooting, documentation, or public
reporting without exposing credentials, IP addresses, or other sensitive data.
Unlike --redact on other commands (which only affects the rendered report),
sanitize produces a redacted copy of the config.xml itself. The input file is
never modified.

SANITIZATION MODES:
  Choose the mode with --mode/-m based on your sharing context:

    aggressive  - Maximum redaction for public sharing (forums, GitHub issues).
                  Redacts passwords, keys, certificates, all IPs, MACs, emails,
                  hostnames, usernames, domains, OTP seeds, WireGuard endpoints,
                  tunnel addresses, subnets, Cloudflare IDs, public keys.

    moderate    - Balanced redaction for internal sharing (default).
                  Redacts passwords, keys, authserver values, public IPs, MACs,
                  emails. Preserves private IPs and hostnames for topology analysis.

    minimal     - Credentials + authserver redaction for trusted environments.
                  Redacts passwords, secrets, API keys, PSKs, private keys, SSH
                  keys, and authserver values. Preserves all network information.

REFERENTIAL INTEGRITY:
  The sanitizer keeps consistent mappings inside a single run:
    - The same original value is always replaced with the same redacted value,
      so two fields referring to one host still match after sanitizing.
    - Replacements are markers, not plausible substitutes, so a redacted value
      can never be mistaken for a real one (e.g. 192.168.1.1 becomes
      [REDACTED-PRIVATE-IP-1]).
  Aggressive mode therefore produces a document for reading and sharing, not a
  loadable configuration. Use moderate mode when the sanitized file still needs
  to parse and support topology analysis; it preserves private addresses.
  Use --mapping to write a JSON reverse-lookup table alongside the output.

OUTPUT:
  By default, sanitized XML is printed to stdout. Use --output/-o to save to a
  file, and --force to overwrite an existing file. Sanitize never modifies the
  input in place.

RELATED:
  convert    - Use --redact for single-pass redaction of the rendered report
  audit      - Use --redact to keep audit output safe to share`,
	Example: `  # Sanitize for public sharing (maximum redaction)
  opnDossier sanitize config.xml --mode aggressive -o config-sanitized.xml

  # Sanitize for internal sharing (default mode)
  opnDossier sanitize config.xml -o sanitized.xml

  # Sanitize with mapping file for reverse lookup
  opnDossier sanitize config.xml -o sanitized.xml --mapping mappings.json

  # Minimal redaction (credentials and authserver values only)
  opnDossier sanitize config.xml --mode minimal

  # Force overwrite of an existing file
  opnDossier sanitize config.xml -o output.xml --force

  # Pipe to another command
  opnDossier sanitize config.xml | less`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		// Get configuration and logger from CommandContext
		cmdCtx := GetCommandContext(cmd)
		if cmdCtx == nil {
			return errors.New("command context not initialized")
		}
		cmdLogger := cmdCtx.Logger

		inputFile := args[0]

		// Create logger with input file field
		ctxLogger := cmdLogger.WithFields("input_file", inputFile)

		// Create a timeout context for processing
		timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
		defer cancel()

		// Sanitize the file path
		cleanPath := filepath.Clean(inputFile)
		if !filepath.IsAbs(cleanPath) {
			var err error
			cleanPath, err = filepath.Abs(cleanPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for %s: %w", inputFile, err)
			}
		}

		// Must run before anything is opened for writing.
		if err := validateSanitizePaths(cleanPath, sanitizeOutputFile, sanitizeMappingFile); err != nil {
			return err
		}

		// Open input file
		file, err := os.Open(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", inputFile, err)
		}
		defer func() {
			if cerr := file.Close(); cerr != nil {
				ctxLogger.Error("failed to close input file", "error", cerr)
			}
		}()

		// Create sanitizer with specified mode
		ctxLogger.Debug("Creating sanitizer", "mode", sanitizeMode)
		s := sanitizer.NewSanitizer(sanitizer.Mode(sanitizeMode))

		// Settle overwrite protection before any work happens, so declining the
		// prompt costs nothing.
		actualOutputFile := ""

		if sanitizeOutputFile != "" {
			actualOutputFile, err = determineSanitizeOutputPath(sanitizeOutputFile, sanitizeForce)
			if err != nil {
				if errors.Is(err, ErrOperationCancelled) {
					ctxLogger.Info("Operation cancelled by user")
					return nil
				}
				return err
			}

			ctxLogger = ctxLogger.WithFields("output_file", actualOutputFile)
		}

		// Perform sanitization
		ctxLogger.Debug("Sanitizing configuration")

		// Check for context cancellation
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("operation timed out: %w", timeoutCtx.Err())
		default:
		}

		// Buffered so a sanitizer failure cannot leave a truncated file where the
		// previous contents were. SanitizeXML already holds the whole document in
		// memory, so this costs nothing.
		var sanitized bytes.Buffer
		if err := s.SanitizeXML(file, &sanitized); err != nil {
			return fmt.Errorf("failed to sanitize configuration: %w", err)
		}

		if actualOutputFile != "" {
			if err := writeSanitizeArtifact(actualOutputFile, sanitized.Bytes()); err != nil {
				return fmt.Errorf("failed to write output file %s: %w", actualOutputFile, err)
			}
		} else if _, err := cmd.OutOrStdout().Write(sanitized.Bytes()); err != nil {
			return fmt.Errorf("failed to write sanitized output: %w", err)
		}

		// Log statistics
		stats := s.GetStats()
		ctxLogger.Debug("Sanitization complete",
			"total_fields", stats.TotalFields,
			"redacted_fields", stats.RedactedFields,
			"skipped_fields", stats.SkippedFields,
		)

		// Write mapping file if requested
		if sanitizeMappingFile != "" {
			// Re-check the output/mapping collision now that the output exists on
			// disk. The preflight in validateSanitizePaths can only compare these
			// two lexically, because neither file exists when it runs; that misses a
			// symlink or a case-only difference on a case-insensitive filesystem,
			// either of which would let the mapping write land on the sanitized
			// configuration. With the output written, os.SameFile resolves both.
			if actualOutputFile != "" {
				same, err := pathsResolveToSameFile(actualOutputFile, sanitizeMappingFile)
				if err != nil {
					return err
				}

				if same {
					return fmt.Errorf(
						"%w: --mapping %s resolves to the sanitized output %s; the mapping file is written second and would replace it. Write them to different paths",
						ErrSanitizePathCollision,
						sanitizeMappingFile,
						actualOutputFile,
					)
				}
			}

			mappingPath, err := determineSanitizeOutputPath(sanitizeMappingFile, sanitizeForce)
			if err != nil {
				if errors.Is(err, ErrOperationCancelled) {
					// The configuration is already written; only the mapping is
					// missing. Warn rather than Info so the partial result is visible
					// without --verbose.
					ctxLogger.Warn("Mapping file creation cancelled by user; sanitized configuration was still written")

					return nil
				}
				return err
			}

			mappingJSON, err := s.GetMapper().ToJSON(sanitizeMode)
			if err != nil {
				return fmt.Errorf("failed to generate mapping JSON: %w", err)
			}

			if err := writeSanitizeArtifact(mappingPath, mappingJSON); err != nil {
				return fmt.Errorf("failed to write mapping file %s: %w", mappingPath, err)
			}

			ctxLogger.Debug("Mapping file written", "mapping_file", mappingPath)
		}

		// Output summary to stderr if writing to file (so it doesn't corrupt stdout)
		if actualOutputFile != "" {
			fmt.Fprintf(os.Stderr, "Sanitized %s → %s (%d fields redacted)\n",
				inputFile, actualOutputFile, stats.RedactedFields)
			if sanitizeMappingFile != "" {
				fmt.Fprintf(os.Stderr, "Mapping file: %s\n", sanitizeMappingFile)
			}
		}

		return nil
	},
}

// validateSanitizePaths rejects a run in which the input file, --output, and
// --mapping do not all refer to distinct files.
//
// os.Create truncates on open, so an --output aimed at the input empties the
// configuration before the sanitizer reads a byte of it: the run then sanitizes
// an empty document and exits 0 reporting "0 fields redacted". Neither --force
// nor the overwrite prompt gates this, because both read as consent to replace
// the output, not the input.
//
// inputPath is expected to be absolute; the others are as supplied and may be
// empty.
func validateSanitizePaths(inputPath, outputPath, mappingPath string) error {
	checks := []struct {
		a, b    string
		message string
	}{
		{
			a: inputPath,
			b: outputPath,
			message: fmt.Sprintf(
				"--output %s refers to the input file; sanitize never rewrites its input in place, and writing there would truncate the configuration before it is read. Write to a different path",
				outputPath,
			),
		},
		{
			a: inputPath,
			b: mappingPath,
			message: fmt.Sprintf(
				"--mapping %s refers to the input file; the mapping file would overwrite the configuration being sanitized. Write to a different path",
				mappingPath,
			),
		},
		{
			a: outputPath,
			b: mappingPath,
			message: fmt.Sprintf(
				"--output and --mapping both refer to %s; the mapping file is written second and would replace the sanitized configuration. Write them to different paths",
				mappingPath,
			),
		},
	}

	for _, check := range checks {
		if check.a == "" || check.b == "" {
			continue
		}

		same, err := pathsResolveToSameFile(check.a, check.b)
		if err != nil {
			return err
		}

		if same {
			return fmt.Errorf("%w: %s", ErrSanitizePathCollision, check.message)
		}
	}

	return nil
}

// pathsResolveToSameFile reports whether two paths refer to the same file.
//
// The absolute-path comparison is the only signal available when neither file
// exists yet, which is normal for a pair of output paths. When both exist,
// os.SameFile also catches symlinks, hard links, and case-only differences on
// case-insensitive filesystems, since os.Stat resolves the path first.
func pathsResolveToSameFile(pathA, pathB string) (bool, error) {
	absA, err := filepath.Abs(filepath.Clean(pathA))
	if err != nil {
		return false, fmt.Errorf("failed to resolve absolute path for %s: %w", pathA, err)
	}

	absB, err := filepath.Abs(filepath.Clean(pathB))
	if err != nil {
		return false, fmt.Errorf("failed to resolve absolute path for %s: %w", pathB, err)
	}

	if absA == absB {
		return true, nil
	}

	infoA, err := os.Stat(absA)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return false, fmt.Errorf("failed to inspect %s: %w", pathA, err)
	}

	infoB, err := os.Stat(absB)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return false, fmt.Errorf("failed to inspect %s: %w", pathB, err)
	}

	return os.SameFile(infoA, infoB), nil
}

// sanitizeArtifactPermissions matches export.DefaultFilePermissions. os.Create
// would give 0644, which is wrong for the --mapping file: it is the reverse
// lookup table, holding every original hostname, address, username, and email
// in cleartext beside its pseudonym.
const sanitizeArtifactPermissions = 0o600

// writeSanitizeArtifact writes content to path with owner-only permissions,
// replacing the destination only once the bytes are safely on disk.
//
// The write goes to a temporary file in the same directory and is renamed into
// place at the end. Opening the destination directly with O_TRUNC would destroy
// an existing artifact before the first byte is written, so a disk-full or sync
// failure would return an error having already lost the previous result. The
// rename is the last step and is atomic on a single filesystem, which is why the
// temporary file has to be a sibling rather than in the system temp directory.
//
// Chmod is applied to the temporary file before the rename. os.CreateTemp makes
// files 0600, but that is its behavior rather than a documented guarantee, and
// setting the mode explicitly keeps this correct if it ever changes.
//
// Close failures are returned rather than logged, since a failed close can mean
// the bytes never reached the filesystem.
func writeSanitizeArtifact(path string, content []byte) error {
	// Path is the operator's own --output or --mapping value, already checked by
	// validateSanitizePaths for collisions with the input and with each other,
	// and by determineSanitizeOutputPath for the overwrite gate.

	// A destination that is not a regular file gets written through rather than
	// replaced. Renaming onto a device node or a FIFO substitutes a regular file
	// for it, which is not what -o /dev/null or -o /dev/stdout asks for, and
	// CreateTemp in the destination's directory is not permitted in /dev anyway.
	// The truncation guarantee the temporary file provides is meaningless for
	// these targets, since there is no previous content to lose.
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		return writeSanitizeArtifactDirect(path, content)
	}

	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp_*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}

	tmpPath := tmp.Name()

	// Removes the temporary file on every failure path below. After a successful
	// rename the path no longer exists, so the Remove is a no-op.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Chmod(tmpPath, sanitizeArtifactPermissions); err != nil {
		return fmt.Errorf("set permissions: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}

	return nil
}

// writeSanitizeArtifactDirect writes to a destination that is not a regular
// file, such as /dev/null, /dev/stdout, or a FIFO.
//
// No temporary file, no rename, and no Chmod: the node already exists, its
// permissions belong to whoever created it, and replacing it is exactly the
// behavior this avoids. O_TRUNC is safe here because a character device or a
// pipe has no previous content that truncation could destroy.
func writeSanitizeArtifactDirect(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY, sanitizeArtifactPermissions) // #nosec G304
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if _, err := file.Write(content); err != nil {
		_ = file.Close()

		return fmt.Errorf("write: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}

// determineSanitizeOutputPath determines whether the provided outputPath may be used.
// If the file already exists and force is false, it prompts the user on stderr to
// confirm overwriting; an empty response is treated as "No" and only `y` or `Y`
// are accepted to proceed. It returns the original outputPath on approval.
// Returns ErrOperationCancelled when the user declines, or a wrapped error if
// reading user input fails.
func determineSanitizeOutputPath(outputPath string, force bool) (string, error) {
	// Check if file already exists
	if _, err := os.Stat(outputPath); err == nil {
		// File exists, check if we should overwrite
		if !force {
			fmt.Fprintf(os.Stderr, "File '%s' already exists. Overwrite? (y/N): ", outputPath)

			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("failed to read user input: %w", err)
			}

			response = strings.TrimSpace(response)
			if response == "" {
				response = "N"
			}

			if response != "y" && response != "Y" {
				return "", ErrOperationCancelled
			}
		}
	}

	return outputPath, nil
}
