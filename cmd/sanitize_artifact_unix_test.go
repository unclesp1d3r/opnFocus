//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// writeFailureLimit is small enough that the artifact below cannot be written
// within it, and large enough that creating the file itself succeeds.
const writeFailureLimit = 64

// TestWriteSanitizeArtifactSurvivesWriteFailure forces a real failure part-way
// through the write, which is the case the atomic replacement exists for.
//
// The other tests in this package cover the failure reaching the writer late
// (a directory destination, which fails at the rename) and the structural
// property that the destination is replaced rather than rewritten. Neither
// reproduces the original defect, because opening a directory with O_TRUNC
// fails before truncating anything.
//
// RLIMIT_FSIZE does reproduce it. With the destination opened O_TRUNC the
// previous artifact is truncated at open and then partially overwritten before
// the limit is hit, so the operator is left with neither the old result nor the
// new one. Measured against the pre-fix implementation, the destination came
// back as 64 bytes of payload with the previous content gone.
//
// Unix only: the limit has no Windows equivalent. This test does not call
// t.Parallel, because the limit is process-wide. Tests in this package are
// already serial (see GOTCHAS 1.1, cmd uses package-level flag globals).
func TestWriteSanitizeArtifactSurvivesWriteFailure(t *testing.T) {
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		t.Skipf("cannot read RLIMIT_FSIZE: %v", err)
	}

	limited := original
	limited.Cur = writeFailureLimit

	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Skipf("cannot lower RLIMIT_FSIZE: %v", err)
	}

	t.Cleanup(func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Errorf("failed to restore RLIMIT_FSIZE: %v", err)
		}
	})

	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "sanitized.xml")

	const previous = "PREVIOUS SANITIZED OUTPUT"
	if err := os.WriteFile(dest, []byte(previous), 0o600); err != nil {
		t.Fatalf("failed to seed destination: %v", err)
	}

	oversized := []byte(strings.Repeat("x", writeFailureLimit*64))

	if err := writeSanitizeArtifact(dest, oversized); err == nil {
		t.Fatal("expected the write to fail against the file size limit, got nil")
	}

	//nolint:gosec // path is built by the test
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("destination was removed by the failed write: %v", err)
	}

	if string(got) != previous {
		t.Errorf("destination content = %q, want %q; the failed write destroyed the previous artifact",
			got, previous)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read working directory: %v", err)
	}

	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp_") {
			t.Errorf("temporary file %q left behind after a failed write", entry.Name())
		}
	}
}

// TestWriteSanitizeArtifactWritesThroughNonRegularDestination covers the
// destinations the temp-file-and-rename path would otherwise break.
//
// Renaming onto a device node substitutes a regular file for it, which is not
// what -o /dev/null or -o /dev/stdout asks for, and os.CreateTemp cannot create
// a sibling in /dev for an ordinary user at all. Writing to /dev/null regressed
// to "create temporary file: permission denied" until the non-regular case was
// split out.
//
// The node must also survive as a node. A FIFO would exercise the same path but
// is not safe to assert on here: opening one O_WRONLY blocks until a reader
// attaches, so a reader that fails to start leaves the test hung rather than
// failed. /dev/null is a character device and needs no peer.
//
// Unix only: there is no Windows equivalent of these destinations.
func TestWriteSanitizeArtifactWritesThroughNonRegularDestination(t *testing.T) {
	before, err := os.Stat(os.DevNull)
	if err != nil {
		t.Skipf("%s unavailable: %v", os.DevNull, err)
	}

	if before.Mode()&os.ModeCharDevice == 0 {
		t.Skipf("%s is not a character device on this system", os.DevNull)
	}

	if err := writeSanitizeArtifact(os.DevNull, []byte("<opnsense/>")); err != nil {
		t.Fatalf("writing to %s failed: %v", os.DevNull, err)
	}

	after, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatalf("%s disappeared after the write: %v", os.DevNull, err)
	}

	if after.Mode()&os.ModeCharDevice == 0 {
		t.Errorf("%s mode = %v, want a character device; the write replaced the node",
			os.DevNull, after.Mode())
	}
}
