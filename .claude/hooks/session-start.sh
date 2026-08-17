#!/bin/bash
# SessionStart hook — provisions the toolchain for Claude Code on the web.
#
# Mirrors `just install` (see CONTRIBUTING.md "Development Setup") with two
# deliberate differences, both to avoid mutating the working tree on every
# session start:
#
#   * `go mod download` instead of `go mod tidy` — tidy rewrites go.mod/go.sum,
#     which would surface as a spurious diff in every session.
#   * `pre-commit install` is skipped — it writes .git/hooks and would make
#     every commit in the session run the full pre-commit suite.
#
# Run `just install` by hand if you need either of those.
set -euo pipefail

# Local machines already have their own toolchain; only provision the remote.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.local/share/mise}"
MISE_BIN="$HOME/.local/bin/mise"

# 1. mise — owns every pinned tool in mise.toml (go, golangci-lint, just, ...).
if ! command -v mise >/dev/null 2>&1 && [ ! -x "$MISE_BIN" ]; then
  echo "==> installing mise"
  curl -fsSL https://mise.run | MISE_INSTALL_PATH="$MISE_BIN" sh
fi
command -v mise >/dev/null 2>&1 || export PATH="$HOME/.local/bin:$PATH"

# 2. Trust the config. The repo is cloned fresh each remote session, so mise
#    sees an unfamiliar mise.toml and refuses to parse it until trusted.
echo "==> mise trust"
mise trust "$PWD/mise.toml"

# 3. Pinned tools. Idempotent: already-installed versions are a no-op.
#
# Deliberately narrower than a bare `mise install`, which provisions all ~17
# tools in mise.toml. Only these three are needed to build, test, and lint;
# the rest are release/docs tooling (goreleaser, cosign, quill, bun, mkdocs,
# act, ...) that costs minutes to install and is unused in a dev session.
# `quill` in particular installs via the github: backend and, with
# github_attestations enabled, fails outright where the GitHub API is not
# reachable. Run `just install` by hand if you need the full set.
echo "==> mise install (go, golangci-lint, just)"
mise install go golangci-lint just

# 4. Warm the Go module cache so the first test run is not a download.
#
# Uses the shims rather than `mise exec`: mise.toml sets exec_auto_install,
# so `mise exec` provisions every tool in the config before running the
# command — reintroducing the full install this script just avoided.
export PATH="$MISE_DATA_DIR/shims:$PATH"
echo "==> go mod download"
go mod download

# 5. Put the mise shims on PATH for the rest of the session, so `just`,
#    `golangci-lint`, and the pinned `go` resolve without a `mise exec` prefix.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export PATH=\"\$HOME/.local/bin:$MISE_DATA_DIR/shims:\$PATH\""
    echo "export MISE_DATA_DIR=\"$MISE_DATA_DIR\""
  } >> "$CLAUDE_ENV_FILE"
fi

echo "==> session-start hook complete"
