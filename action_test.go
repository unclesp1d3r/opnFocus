package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestActionRunsAsWorkspaceOwner guards a defect that only end-to-end
// container testing surfaces.
//
// The published image sets USER 65532:65532, which is the right default for a
// bare `docker run`. A runner workspace, however, is owned by the runner user
// (uid 1001 on GitHub-hosted runners), so the container could not write into
// the bind mount. Every invocation using the documented `output` input failed
// with "permission denied", while stdout-only runs looked fine -- so the
// breakage was invisible to any test that did not ask for an output file.
//
// Verified by building the release image and running it against a workspace
// chowned to 1001:1001: without --user, convert/audit/sanitize --output all
// fail; with it, all three succeed and the artefacts land owned by 1001.
func TestActionRunsAsWorkspaceOwner(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("action.yml")
	require.NoError(t, err)

	action := string(data)

	require.Contains(t, action, "docker run --rm",
		"action.yml no longer invokes docker run; this guard needs updating")
	assert.Contains(t, action, `--user "$(id -u):$(id -g)"`,
		"the container must run as the workspace owner, or the output input fails "+
			"with permission denied against the runner-owned bind mount")
}

// TestActionMountsWorkspace pins the two flags the --user fix depends on: the
// workspace bind mount and the working directory the relative output path is
// resolved against.
func TestActionMountsWorkspace(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("action.yml")
	require.NoError(t, err)

	action := string(data)

	assert.Contains(t, action, `--volume "${GITHUB_WORKSPACE}:/data"`)
	assert.Contains(t, action, "--workdir /data")
}
