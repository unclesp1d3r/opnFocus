//go:build unix

package cmd

import (
	"os"
	"testing"
)

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
