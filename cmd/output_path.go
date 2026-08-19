// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Output destination errors shared by the commands that write report files.
var (
	// ErrMultiFileOutput is returned when a single --output destination is
	// combined with more than one input file.
	ErrMultiFileOutput = errors.New("--output cannot be used with multiple input files")

	// ErrOutputExists is returned when the destination already exists, --force
	// was not given, and stdin is not a terminal, so the operator cannot be
	// asked to confirm.
	ErrOutputExists = errors.New("output file already exists")
)

// validateMultiFileOutput rejects a single --output destination shared across
// several inputs.
//
// Inputs are processed concurrently, so a shared destination means every worker
// writes the same path. On POSIX the atomic renames succeed in turn and the last
// writer wins, so N inputs produce one report and the command exits 0. On
// Windows the second rename fails against the open handle and surfaces as a
// permission error against a temporary filename.
//
// remedy is appended so each command can name its own way out.
func validateMultiFileOutput(outputFile string, inputCount int, remedy string) error {
	if outputFile == "" || inputCount <= 1 {
		return nil
	}

	return fmt.Errorf("%w; %s", ErrMultiFileOutput, remedy)
}

// confirmOverwrite gates writing to a destination that already exists. It
// returns nil to proceed, [ErrOperationCancelled] when the operator declines,
// and [ErrOutputExists] when the file exists but there is no terminal to ask.
// Without that last case a piped or CI invocation fails with
// "failed to read user input: EOF", which explains nothing.
//
// Call this before starting concurrent work: prompting from inside a worker
// races other workers for stdin.
func confirmOverwrite(in *os.File, out io.Writer, path string, force bool) error {
	if force || path == "" {
		return nil
	}

	// Only an existing destination needs confirming. Anything else, including a
	// path that cannot be stat'd, is left to the write itself to report, which
	// gives a more accurate error than anything guessed here.
	if !fileExists(path) {
		return nil
	}

	if !term.IsTerminal(int(in.Fd())) {
		return fmt.Errorf("%w: %s; pass --force to overwrite", ErrOutputExists, path)
	}

	// Reading stdin after a failed prompt would block on an operator who never
	// saw the question.
	if _, err := fmt.Fprintf(out, "File '%s' already exists. Overwrite? (y/N): ", path); err != nil {
		return fmt.Errorf("failed to write overwrite prompt: %w", err)
	}

	response, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read user input: %w", err)
	}

	// Anything other than an explicit y declines, including an empty line.
	switch strings.TrimSpace(response) {
	case "y", "Y":
		return nil
	default:
		return ErrOperationCancelled
	}
}

// fileExists reports whether path names something that can be stat'd. A stat
// failure of any kind is treated as "not there": the subsequent write is a
// better place to surface a permissions or I/O problem than a confirmation
// prompt is.
func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
