package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// sanitizeTestXML is a minimal but non-empty configuration used by the
// regression tests below. It has to contain at least one redactable value so a
// successful run reports a non-zero redaction count, which is what makes the
// "0 fields redacted" success report on a destroyed input recognisable.
const sanitizeTestXML = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>firewall.example.com</hostname>
    <user>
      <name>admin</name>
      <password>supersecret123</password>
    </user>
  </system>
</opnsense>`

func writeSanitizeFixture(t *testing.T, path string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(sanitizeTestXML), 0o600); err != nil {
		t.Fatalf("failed to write fixture %s: %v", path, err)
	}
}

func TestPathsResolveToSameFile(t *testing.T) {
	tmpDir := t.TempDir()

	existing := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, existing)

	other := filepath.Join(tmpDir, "other.xml")
	writeSanitizeFixture(t, other)

	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "identical absolute paths",
			a:    existing,
			b:    existing,
			want: true,
		},
		{
			name: "distinct existing files",
			a:    existing,
			b:    other,
			want: false,
		},
		{
			name: "same file reached through a dot segment",
			a:    existing,
			b:    filepath.Join(tmpDir, ".", "config.xml"),
			want: true,
		},
		{
			name: "same file reached through a parent segment",
			a:    existing,
			b:    filepath.Join(tmpDir, "sub", "..", "config.xml"),
			want: true,
		},
		{
			name: "destination that does not exist yet",
			a:    existing,
			b:    filepath.Join(tmpDir, "sanitized.xml"),
			want: false,
		},
		{
			name: "two destinations that do not exist yet but share a path",
			a:    filepath.Join(tmpDir, "out.xml"),
			b:    filepath.Join(tmpDir, "out.xml"),
			want: true,
		},
		{
			name: "two destinations that do not exist yet with distinct paths",
			a:    filepath.Join(tmpDir, "out.xml"),
			b:    filepath.Join(tmpDir, "map.json"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pathsResolveToSameFile(tt.a, tt.b)
			if err != nil {
				t.Fatalf("pathsResolveToSameFile(%q, %q) returned error: %v", tt.a, tt.b, err)
			}

			if got != tt.want {
				t.Errorf("pathsResolveToSameFile(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestPathsResolveToSameFile_Symlink covers the case a purely lexical path
// comparison cannot see: a destination that is a different path but resolves to
// the input through a symlink. Creating symlinks needs elevation on Windows, so
// the test skips rather than fails when the link cannot be created.
func TestPathsResolveToSameFile_Symlink(t *testing.T) {
	tmpDir := t.TempDir()

	target := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, target)

	link := filepath.Join(tmpDir, "config-link.xml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform or account: %v", err)
	}

	same, err := pathsResolveToSameFile(target, link)
	if err != nil {
		t.Fatalf("pathsResolveToSameFile returned error: %v", err)
	}

	if !same {
		t.Error("a symlink pointing at the input should be reported as the same file")
	}
}

func TestValidateSanitizePaths(t *testing.T) {
	tmpDir := t.TempDir()

	input := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, input)

	output := filepath.Join(tmpDir, "sanitized.xml")
	mapping := filepath.Join(tmpDir, "mapping.json")

	tests := []struct {
		name        string
		input       string
		output      string
		mapping     string
		wantErr     bool
		wantMessage string
	}{
		{
			name:    "all three distinct",
			input:   input,
			output:  output,
			mapping: mapping,
		},
		{
			name:  "output omitted",
			input: input,
		},
		{
			name:    "mapping omitted",
			input:   input,
			output:  output,
			mapping: "",
		},
		{
			name:        "output is the input",
			input:       input,
			output:      input,
			wantErr:     true,
			wantMessage: "refers to the input file",
		},
		{
			name:        "mapping is the input",
			input:       input,
			output:      output,
			mapping:     input,
			wantErr:     true,
			wantMessage: "refers to the input file",
		},
		{
			name:        "output and mapping share a path",
			input:       input,
			output:      output,
			mapping:     output,
			wantErr:     true,
			wantMessage: "both refer to",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSanitizePaths(tt.input, tt.output, tt.mapping)

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("validateSanitizePaths returned unexpected error: %v", err)
				}

				return
			}

			if err == nil {
				t.Fatal("expected a collision error, got nil")
			}

			if !errors.Is(err, ErrSanitizePathCollision) {
				t.Errorf("error does not wrap ErrSanitizePathCollision: %v", err)
			}

			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("error message %q does not contain %q", err.Error(), tt.wantMessage)
			}
		})
	}
}

// resetFlagSet returns every flag in fs to its declared default and clears the
// Changed bit.
//
// Cobra keeps Changed set for the lifetime of the command tree, and rootCmd is
// a package-level singleton shared by the whole test binary. A --quiet from an
// earlier test therefore still counts as "set" on the next Execute and trips
// the verbose/quiet/debug mutual-exclusion group, which fails the run before it
// reaches the command under test. None of these flags are slice-valued, so
// Set(DefValue) round-trips cleanly.
func resetFlagSet(t *testing.T, fs *pflag.FlagSet) {
	t.Helper()

	fs.VisitAll(func(f *pflag.Flag) {
		if err := f.Value.Set(f.DefValue); err != nil {
			t.Fatalf("failed to reset flag --%s to %q: %v", f.Name, f.DefValue, err)
		}

		f.Changed = false
	})
}

// isolateCommandGlobals neutralises the package-level state Cobra binds its
// flags to, both before the test runs and again when it ends.
//
// cfgFile matters as much as the flag state: other tests in this package leave
// it pointing at a temp config that no longer exists, which makes
// PersistentPreRunE fail during config load before the sanitize command is ever
// reached. Clearing all of it keeps these tests independent of execution order.
func isolateCommandGlobals(t *testing.T) {
	t.Helper()

	priorCfgFile := cfgFile

	reset := func() {
		sanitizeMode = SanitizeModeModerate
		sanitizeOutputFile = ""
		sanitizeMappingFile = ""
		sanitizeForce = false

		resetFlagSet(t, rootCmd.PersistentFlags())
		resetFlagSet(t, sanitizeCmd.Flags())
	}

	t.Cleanup(func() {
		reset()

		cfgFile = priorCfgFile

		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	reset()

	cfgFile = ""
}

// runSanitize executes the sanitize command through the root command, the same
// path a real invocation takes, and returns its error.
func runSanitize(t *testing.T, args ...string) error {
	t.Helper()

	isolateCommandGlobals(t)

	var out bytes.Buffer

	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append([]string{"sanitize"}, args...))

	return rootCmd.Execute()
}

// TestSanitizeCommand_RefusesToDestroyInput is the regression test for the
// in-place truncation bug. Before the fix, each of these invocations opened the
// destination with os.Create, which truncated the file the sanitizer was about
// to read; the command then sanitized an empty document and exited 0 reporting
// "0 fields redacted", leaving the operator with a zero-byte configuration.
//
// The assertion that matters is not just that the command fails, but that the
// input file is byte-for-byte unchanged afterwards.
func TestSanitizeCommand_RefusesToDestroyInput(t *testing.T) {
	tests := []struct {
		name string
		args func(input string) []string
	}{
		{
			name: "output aimed at the input",
			args: func(input string) []string {
				return []string{input, "-o", input, "--force"}
			},
		},
		{
			name: "mapping aimed at the input",
			args: func(input string) []string {
				return []string{input, "--mapping", input, "--force"}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			input := filepath.Join(tmpDir, "config.xml")
			writeSanitizeFixture(t, input)

			err := runSanitize(t, tt.args(input)...)
			if err == nil {
				t.Fatal("expected the command to fail, got nil error")
			}

			if !errors.Is(err, ErrSanitizePathCollision) {
				t.Errorf("error does not wrap ErrSanitizePathCollision: %v", err)
			}

			after, readErr := os.ReadFile(input)
			if readErr != nil {
				t.Fatalf("failed to read input file after the run: %v", readErr)
			}

			if !bytes.Equal(after, []byte(sanitizeTestXML)) {
				t.Errorf("input file was modified; got %d bytes, want %d bytes",
					len(after), len(sanitizeTestXML))
			}
		})
	}
}

// TestSanitizeCommand_RefusesRelativeAliasOfInput checks the same guard when the
// operator spells the destination differently from the input. A lexical
// comparison of the raw strings would miss this.
func TestSanitizeCommand_RefusesRelativeAliasOfInput(t *testing.T) {
	tmpDir := t.TempDir()
	input := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, input)

	alias := filepath.Join(tmpDir, "sub", "..", "config.xml")

	err := runSanitize(t, input, "-o", alias, "--force")
	if err == nil {
		t.Fatal("expected the command to fail, got nil error")
	}

	if !errors.Is(err, ErrSanitizePathCollision) {
		t.Errorf("error does not wrap ErrSanitizePathCollision: %v", err)
	}

	after, readErr := os.ReadFile(input)
	if readErr != nil {
		t.Fatalf("failed to read input file after the run: %v", readErr)
	}

	if !bytes.Equal(after, []byte(sanitizeTestXML)) {
		t.Error("input file was modified by a run that should have been rejected")
	}
}

// TestSanitizeCommand_WritesDistinctDestinations is the counterpart to the
// rejection tests: the guard must not get in the way of an ordinary run.
func TestSanitizeCommand_WritesDistinctDestinations(t *testing.T) {
	tmpDir := t.TempDir()
	input := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, input)

	output := filepath.Join(tmpDir, "sanitized.xml")
	mapping := filepath.Join(tmpDir, "mapping.json")

	if err := runSanitize(t, input, "-o", output, "--mapping", mapping, "--force"); err != nil {
		t.Fatalf("sanitize with distinct destinations failed: %v", err)
	}

	sanitized, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed to read sanitized output: %v", err)
	}

	if len(sanitized) == 0 {
		t.Error("sanitized output is empty")
	}

	if bytes.Contains(sanitized, []byte("supersecret123")) {
		t.Error("password was not redacted in the sanitized output")
	}

	if _, err := os.Stat(mapping); err != nil {
		t.Errorf("mapping file was not written: %v", err)
	}

	unchanged, err := os.ReadFile(input)
	if err != nil {
		t.Fatalf("failed to read input file after the run: %v", err)
	}

	if !bytes.Equal(unchanged, []byte(sanitizeTestXML)) {
		t.Error("input file was modified by a successful run")
	}
}

// TestSanitizeCommand_FailedRunLeavesDestinationIntact covers the second half of
// the fix: the destination is created only after sanitization succeeds, so a
// failure part-way through cannot leave a truncated file where a previous
// result used to be.
func TestSanitizeCommand_FailedRunLeavesDestinationIntact(t *testing.T) {
	tmpDir := t.TempDir()

	input := filepath.Join(tmpDir, "config.xml")
	if err := os.WriteFile(input, []byte("<opnsense><system>"), 0o600); err != nil {
		t.Fatalf("failed to write malformed fixture: %v", err)
	}

	const previous = "previous sanitized output"

	output := filepath.Join(tmpDir, "sanitized.xml")
	if err := os.WriteFile(output, []byte(previous), 0o600); err != nil {
		t.Fatalf("failed to seed destination: %v", err)
	}

	if err := runSanitize(t, input, "-o", output, "--force"); err == nil {
		t.Fatal("expected sanitizing a malformed document to fail, got nil error")
	}

	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed to read destination after the failed run: %v", err)
	}

	if string(after) != previous {
		t.Errorf("destination was clobbered by a failed run; got %q, want %q", string(after), previous)
	}
}

// TestPathsResolveToSameFile_CaseInsensitive exercises the os.SameFile arm of
// the check on filesystems where two spellings of one path differ only in case.
// Linux filesystems are case-sensitive, so the two names are genuinely
// different files there and the test only runs on Windows and macOS.
func TestPathsResolveToSameFile_CaseInsensitive(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("filesystem is case-sensitive on this platform")
	}

	tmpDir := t.TempDir()

	lower := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, lower)

	upper := filepath.Join(tmpDir, "CONFIG.XML")

	same, err := pathsResolveToSameFile(lower, upper)
	if err != nil {
		t.Fatalf("pathsResolveToSameFile returned error: %v", err)
	}

	if !same {
		t.Error("paths differing only in case should resolve to the same file on this platform")
	}
}

// TestSanitizeArtifactsAreOwnerOnly checks the permissions of both files the
// command creates. The mapping file is the sensitive one: it holds every
// original hostname, address, username, and email in cleartext next to its
// pseudonym, so a 0644 default in a shared working directory would undo much of
// the point of sanitizing.
//
// The mode bits are POSIX-only; NTFS does not map onto FileMode.Perm(), so the
// assertion is skipped on Windows rather than asserted and quietly wrong.
func TestSanitizeArtifactsAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not map onto NTFS ACLs")
	}

	tmpDir := t.TempDir()
	input := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, input)

	output := filepath.Join(tmpDir, "sanitized.xml")
	mapping := filepath.Join(tmpDir, "mapping.json")

	if err := runSanitize(t, input, "-o", output, "--mapping", mapping, "--force"); err != nil {
		t.Fatalf("sanitize failed: %v", err)
	}

	for _, path := range []string{output, mapping} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("failed to stat %s: %v", path, err)
		}

		if got := info.Mode().Perm(); got != sanitizeArtifactPermissions {
			t.Errorf("%s has mode %#o, want %#o", filepath.Base(path), got, sanitizeArtifactPermissions)
		}
	}
}

// TestSanitizeTightensExistingArtifactPermissions covers the case the OpenFile
// mode argument alone does not: the target already exists, so O_CREATE does not
// apply a mode to it. Re-running sanitize over a mapping file that an earlier
// version left world-readable has to end with it owner-only.
func TestSanitizeTightensExistingArtifactPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not map onto NTFS ACLs")
	}

	tmpDir := t.TempDir()
	input := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, input)

	output := filepath.Join(tmpDir, "sanitized.xml")
	mapping := filepath.Join(tmpDir, "mapping.json")

	// Seed both destinations world-readable, as an earlier release would have
	// left them. Written owner-only first and widened with Chmod so the fixture
	// setup does not itself trip the write-permission linter.
	const worldReadable = 0o644

	for _, path := range []string{output, mapping} {
		if err := os.WriteFile(path, []byte("stale"), sanitizeArtifactPermissions); err != nil {
			t.Fatalf("failed to seed %s: %v", path, err)
		}

		if err := os.Chmod(path, worldReadable); err != nil {
			t.Fatalf("failed to widen permissions on %s: %v", path, err)
		}
	}

	if err := runSanitize(t, input, "-o", output, "--mapping", mapping, "--force"); err != nil {
		t.Fatalf("sanitize failed: %v", err)
	}

	for _, path := range []string{output, mapping} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("failed to stat %s: %v", path, err)
		}

		if got := info.Mode().Perm(); got != sanitizeArtifactPermissions {
			t.Errorf("%s kept mode %#o, want %#o", filepath.Base(path), got, sanitizeArtifactPermissions)
		}
	}
}

// TestSanitizeCommand_MappingCollisionViaSymlinkIsRefused pins the hole that the
// up-front collision check cannot see.
//
// validateSanitizePaths compares --output and --mapping before either exists, so
// all it has is a lexical path comparison. A dangling symlink from the mapping
// path to the output path defeats that: the two spellings differ, os.Stat finds
// neither, and the preflight passes. The run then wrote the sanitized
// configuration to --output and, moments later, overwrote it with the mapping
// JSON — exiting 0 while reporting success for a file it had just destroyed.
//
// No attacker is required; a symlink left over from a previous run is enough.
func TestSanitizeCommand_MappingCollisionViaSymlinkIsRefused(t *testing.T) {
	tmpDir := t.TempDir()

	input := filepath.Join(tmpDir, "config.xml")
	writeSanitizeFixture(t, input)

	output := filepath.Join(tmpDir, "sanitized.xml")
	mapping := filepath.Join(tmpDir, "mapping.json")

	// Dangling on purpose: neither file exists yet, which is the normal state
	// when the preflight runs.
	if err := os.Symlink(output, mapping); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	err := runSanitize(t, input, "-o", output, "--mapping", mapping, "--force")
	if err == nil {
		t.Fatal("expected a mapping path resolving to the output to be refused, got nil error")
	}

	if !errors.Is(err, ErrSanitizePathCollision) {
		t.Fatalf("expected ErrSanitizePathCollision, got %v", err)
	}

	// The sanitized configuration must survive: refusing late is only useful if
	// the artifact already written is still the sanitized XML.
	written, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatalf("failed to read output after the refused run: %v", readErr)
	}

	if bytes.Contains(written, []byte(`"mappings"`)) {
		t.Error("output file holds the mapping JSON; the sanitized configuration was destroyed")
	}

	if !bytes.Contains(written, []byte("<opnsense>")) {
		t.Errorf("output file is not the sanitized configuration; got %q", string(written))
	}
}
