package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWriteSanitizeArtifactLeavesDestinationIntactOnFailure covers the write
// half of the "a failed run does not destroy the previous artifact" guarantee.
//
// The sanitizer-failure half is covered by
// TestSanitizeCommand_FailedRunLeavesDestinationIntact, which never reaches the
// writer. This one exercises a failure inside the writer itself. Opening the
// destination directly with O_TRUNC truncated it before the first byte was
// written, so any later failure returned an error having already lost the
// previous result.
//
// A directory makes a reliable cross-platform failure: the content and
// permissions steps succeed, and the final rename cannot replace it.
func TestWriteSanitizeArtifactLeavesDestinationIntactOnFailure(t *testing.T) {
	tmpDir := t.TempDir()

	dest := filepath.Join(tmpDir, "destination")
	if err := os.Mkdir(dest, 0o750); err != nil {
		t.Fatalf("failed to create destination directory: %v", err)
	}

	marker := filepath.Join(dest, "keep.txt")
	if err := os.WriteFile(marker, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("failed to seed destination: %v", err)
	}

	if err := writeSanitizeArtifact(dest, []byte("replacement")); err == nil {
		t.Fatal("expected an error writing over a directory, got nil")
	}

	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("destination was damaged by the failed write: %v", err)
	}

	if string(got) != "untouched" {
		t.Errorf("destination content = %q, want %q", got, "untouched")
	}

	// The temporary file is a sibling of the destination, so a leak would show
	// up in the same directory the operator is working in.
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

// TestWriteSanitizeArtifactReplacesExistingFile is the success path: the
// destination ends up with the new content at owner-only permissions, and no
// temporary file survives.
func TestWriteSanitizeArtifactReplacesExistingFile(t *testing.T) {
	tmpDir := t.TempDir()

	dest := filepath.Join(tmpDir, "artifact.xml")
	if err := os.WriteFile(dest, []byte("stale"), 0o644); err != nil { //nolint:gosec // deliberately permissive
		t.Fatalf("failed to seed destination: %v", err)
	}

	before, statErr := os.Stat(dest)
	if statErr != nil {
		t.Fatalf("failed to stat seeded destination: %v", statErr)
	}

	if err := writeSanitizeArtifact(dest, []byte("fresh")); err != nil {
		t.Fatalf("writeSanitizeArtifact: %v", err)
	}

	// The destination must be a different file, not the same one truncated and
	// rewritten. That is the property that makes a mid-write failure survivable:
	// the original is only unlinked by the final rename, once the new content is
	// already on disk.
	//
	// TestWriteSanitizeArtifactSurvivesWriteFailure exercises the failure itself
	// under RLIMIT_FSIZE. This is the cheaper structural check that runs
	// alongside it.
	//
	// POSIX only. os.SameFile compares the volume and file index on Windows, and
	// a path-based Stat there does not populate them, so it reports true for
	// both shapes and would assert nothing.
	if runtime.GOOS != "windows" {
		after, err := os.Stat(dest)
		if err != nil {
			t.Fatalf("failed to stat written destination: %v", err)
		}

		if os.SameFile(before, after) {
			t.Error("destination was rewritten in place; a failure mid-write would have destroyed it")
		}
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("failed to read destination: %v", err)
	}

	if string(got) != "fresh" {
		t.Errorf("destination content = %q, want %q", got, "fresh")
	}

	// A pre-existing 0644 file must come back owner-only, which is the case the
	// permission handling exists for. The mode bits are POSIX-only; NTFS does
	// not map onto FileMode.Perm(), so this is skipped on Windows rather than
	// asserted and quietly wrong, matching TestSanitizeArtifactsAreOwnerOnly.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dest)
		if err != nil {
			t.Fatalf("failed to stat destination: %v", err)
		}

		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("destination permissions = %04o, want no group or world access", perm)
		}
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read working directory: %v", err)
	}

	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp_") {
			t.Errorf("temporary file %q left behind after a successful write", entry.Name())
		}
	}
}
