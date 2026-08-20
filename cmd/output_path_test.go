package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMultiFileOutput(t *testing.T) {
	// Do NOT use t.Parallel() - the cmd package binds flags to globals.
	const remedy = "omit --output"

	tests := []struct {
		name       string
		outputFile string
		inputCount int
		wantErr    bool
	}{
		{name: "no output flag, several inputs", outputFile: "", inputCount: 3},
		{name: "output flag, single input", outputFile: "out.md", inputCount: 1},
		{name: "output flag, no inputs", outputFile: "out.md", inputCount: 0},
		{name: "output flag, two inputs", outputFile: "out.md", inputCount: 2, wantErr: true},
		{name: "output flag, many inputs", outputFile: "out.md", inputCount: 9, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMultiFileOutput(tt.outputFile, tt.inputCount, remedy)

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			if !errors.Is(err, ErrMultiFileOutput) {
				t.Fatalf("error does not wrap ErrMultiFileOutput: %v", err)
			}

			if !strings.Contains(err.Error(), remedy) {
				t.Errorf("error should carry the caller's remedy, got: %v", err)
			}
		})
	}
}

// TestConvertRejectsSharedOutputAcrossInputs is the regression test for the
// multi-file clobbering defect.
//
// Every input was previously resolved to the same --output path inside its own
// worker goroutine. On POSIX the atomic renames succeed in turn, so N inputs
// produced one report and the command still exited 0. The assertion that
// matters is that the run is rejected before any file is written.
func TestConvertRejectsSharedOutputAcrossInputs(t *testing.T) {
	// Do NOT use t.Parallel() - modifies package-level flag variables.
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "out.md")

	originalOutputFile := outputFile
	originalForce := force

	t.Cleanup(func() {
		outputFile = originalOutputFile
		force = originalForce
	})

	outputFile = dest
	force = true

	err := convertCmd.PreRunE(convertCmd, []string{"a.xml", "b.xml"})
	if !errors.Is(err, ErrMultiFileOutput) {
		t.Fatalf("expected ErrMultiFileOutput, got: %v", err)
	}

	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("no output file should be created by a rejected run")
	}

	// A single input with the same flag is still allowed.
	if err := convertCmd.PreRunE(convertCmd, []string{"a.xml"}); err != nil {
		t.Errorf("single input with --output should be accepted, got: %v", err)
	}
}

// TestAuditRejectsSharedOutputAcrossInputs pins the same contract on audit, so
// the two commands cannot drift apart again. Convert lacked this guard while
// audit had it, which is how the clobbering defect survived.
func TestAuditRejectsSharedOutputAcrossInputs(t *testing.T) {
	// Do NOT use t.Parallel() - modifies package-level flag variables.
	originalOutputFile := outputFile
	originalMode := auditMode

	t.Cleanup(func() {
		outputFile = originalOutputFile
		auditMode = originalMode
	})

	outputFile = "report.md"
	auditMode = auditModeBlue

	err := auditCmd.PreRunE(auditCmd, []string{"a.xml", "b.xml"})
	if !errors.Is(err, ErrMultiFileOutput) {
		t.Fatalf("expected ErrMultiFileOutput, got: %v", err)
	}
}
