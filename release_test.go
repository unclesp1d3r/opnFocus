package main

import (
	"bytes"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// latestChangelogVersion returns the version of the topmost released entry in
// CHANGELOG.md, formatted as a tag ("v1.7.2"). Unreleased sections are skipped.
func latestChangelogVersion(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile("CHANGELOG.md")
	require.NoError(t, err)

	entry := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`)
	m := entry.FindSubmatch(data)
	require.NotNil(t, m, "CHANGELOG.md has no released ## [X.Y.Z] entry")

	return "v" + string(m[1])
}

// TestActionDefaultVersionMatchesLatestRelease guards a release-checklist step
// that is easy to skip and silent when skipped.
//
// RELEASING.md requires bumping the action.yml default `version:` input and
// sweeping the README `uses:` lines to each new tag. Both were missed for
// v1.7.2: the composite action kept pulling the v1.7.1 image by default, and
// the README told users the default was the current release when it was the
// previous one. Nothing failed, because nothing checked.
func TestActionDefaultVersionMatchesLatestRelease(t *testing.T) {
	t.Parallel()

	want := latestChangelogVersion(t)

	data, err := os.ReadFile("action.yml")
	require.NoError(t, err)

	// The `version` input is the last one declared, so its default is the last
	// `default:` line before the `runs:` block.
	runsIdx := bytes.Index(data, []byte("\nruns:"))
	require.Positive(t, runsIdx, "action.yml has no runs: block")

	defaults := regexp.MustCompile(`(?m)^\s+default: "([^"]*)"`).
		FindAllSubmatch(data[:runsIdx], -1)
	require.NotEmpty(t, defaults, "action.yml declares no input defaults")

	got := string(defaults[len(defaults)-1][1])
	assert.Equal(t, want, got,
		"action.yml version input default is %q but the latest release in CHANGELOG.md is %q; "+
			"bump it per the RELEASING.md checklist", got, want)
}

// TestReadmeActionExamplesUseLatestRelease keeps the documented `uses:` lines
// on the current tag. See TestActionDefaultVersionMatchesLatestRelease.
func TestReadmeActionExamplesUseLatestRelease(t *testing.T) {
	t.Parallel()

	want := latestChangelogVersion(t)

	data, err := os.ReadFile("README.md")
	require.NoError(t, err)

	refs := regexp.MustCompile(`EvilBit-Labs/opnDossier@(v\d+\.\d+\.\d+)`).
		FindAllSubmatch(data, -1)
	require.NotEmpty(t, refs, "README.md has no pinned action examples")

	for _, ref := range refs {
		assert.Equal(t, want, string(ref[1]),
			"README.md pins the action at %s but the latest release is %s; "+
				"sweep the uses: lines per the RELEASING.md checklist", string(ref[1]), want)
	}
}
