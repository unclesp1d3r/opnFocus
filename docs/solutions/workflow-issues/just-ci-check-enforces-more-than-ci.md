---
title: '`just ci-check` enforces more than CI, and can be red on a clean tree'
category: workflow-issues
date: '2026-08-29'
module: justfile, .golangci.yml, mise.toml
problem_type: workflow_issue
component: development-workflow
severity: medium
tags:
  - just-ci-check
  - golangci-lint
  - modernize
  - mise
  - lockfile
  - staticcheck
  - local-vs-ci
applies_when:
  - '`just ci-check` fails on files the current change never touched'
  - Weighing whether a lint failure is "pre-existing" and can be deferred to a later PR
  - Adding a Go tool to a justfile recipe and assuming mise pins it
  - Reconciling a green CI run against a red local gate on the same tree
related_issues: []
related_docs:
  - docs/solutions/workflow-issues/ci-runs-on-pull-request-not-feature-branch-push.md
---

## Context

`AGENTS.md` requires `just ci-check` to pass **before** committing. During a documentation-only change (one file, `GOTCHAS.md`), that gate failed twice on code the change never touched. Neither failure was noise, and neither was visible in CI — the same tree was green on GitHub both times.

The two failures had different causes, and together they explain how the mandated gate drifts into a state where it is always red and therefore always excused.

## Guidance

### 1. `just ci-check` is a superset of CI, not a mirror of it

CI's `Lint` job (`.github/workflows/ci.yml:16`) runs exactly one thing:

```yaml
  - uses: golangci/golangci-lint-action@... # v9
    with:
      version: v2.12.2
```

It never invokes `just lint`. So everything `just lint` adds past `golangci-lint` — `modernize-check` (`justfile:150`) among it — is enforced **only** on developer machines. A finding there is real; it is simply unenforced upstream, which is not the same as untrue.

The reverse also holds, and it is the trap that cost the most time here. `mise.toml` and `ci.yml` **both** pin golangci-lint, independently:

```toml
# mise.toml — what `just lint` uses
golangci-lint = "2.13.2"
```

```yaml
# .github/workflows/ci.yml:29 — what CI uses
version: v2.12.2   # comment says "should be handled by mise ... specified here to ensure consistency"
```

A routine tool bump moved mise to 2.13.2 and left `ci.yml` at 2.12.2. From then on the two ran **different linters**, and 2.13.2's staticcheck reports SA1019 deprecation hits that 2.12.2 does not:

```
golangci-lint 2.13.2 run ./...   ->  13 issues   exit 1     # just lint
golangci-lint 2.12.2 run ./...   ->   0 issues   exit 0     # CI, same tree, same config
```

The second pin defeats its own stated purpose: hardcoding the version to "ensure consistency" is exactly what makes it drift, because now two files must be updated in lockstep and only one of them is what developers run. A single source of truth — let the action take the version from mise — cannot skew.

**Do not diagnose this by reasoning about invocation differences.** The obvious suspect was the `./...` argument that `just lint` passes and `golangci-lint-action` does not. That theory was wrong, and only running CI's exact version locally disproved it:

```bash
mise exec golangci-lint@2.12.2 -- golangci-lint run ./...   # 0 issues — argument was never the cause
```

Pin the version you are comparing against before you theorise about anything else.

### 2. `go run <tool>@latest` inside a `mise_exec` recipe is not pinned

This *looks* locked — it runs under mise, in a repo with a committed `mise.lock`:

```make
modernize-check:
    @{{ mise_exec }} go run golang.org/x/tools/.../modernize@latest -test ./...
```

It is not. `mise_exec` supplies only the pinned `go`; `@latest` is then resolved by the Go module proxy, entirely outside `mise.lock`. The tool was absent from `mise.toml` altogether, so the lockfile had nothing to pin.

Every other Go tool in this repo is done correctly and *is* locked — `gosec`, `go-licenses`, `benchstat` all appear under `[tools]` with `go:` backends and concrete versions in `mise.lock`, and their recipes call them by name. The fix follows that precedent:

```toml
# mise.toml
"go:golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize" = "latest"
```

```make
# justfile:151
modernize-check:
    @{{ mise_exec }} modernize -test ./...
```

`mise.lock` then records a concrete version (`0.23.0`), and the check becomes reproducible across machines.

### 3. Pinning makes a gate deterministic — it does not make findings disappear

This is the part worth internalizing. The natural reading of "local fails, CI passes" is *version drift: my machine has a newer tool*. That reading was wrong here. After pinning to `0.23.0`, `modernize-check` reported the **same** finding. It was never drift. CI simply never ran that check, so a real finding had been accumulating unseen.

Pin first to make the signal trustworthy; then treat what it reports as true.

## Why This Matters

A gate that is red on a clean tree stops being a gate. Once `just ci-check` fails for reasons unrelated to the change in front of you, every future failure gets triaged as "probably pre-existing too," and the one that actually matters is waved through with the rest. The failure mode is not a missed lint warning — it is the erosion of the check that was supposed to catch everything else.

This is why `AGENTS.md` states the rule without an exception: *"Never dismiss warnings, lint failures, or CI errors as 'pre-existing' or 'not from our changes.'"* The rule is not about attribution. A failure surfaced by your run is yours to resolve, whoever introduced it, because the alternative is a gate nobody trusts.

## When to Apply

- `just ci-check` fails in a package your diff does not touch — resolve it, do not defer it or ask whether it counts.
- You are adding a Go tool to a justfile recipe — put it in `mise.toml` under `[tools]` with a `go:` backend and call it by name. Never `go run …@latest`, which silently escapes the lockfile. (`security-tools` at `justfile:94` still has this shape and remains unfixed.)
- CI is green but local is red, or the reverse — compare the actual invocations before assuming environment drift. The arguments differ.

## Examples

**Suppressing a deliberate deprecation, per site.** The 13 `staticcheck` SA1019 hits were real: `cmd/` reads and writes deprecated `config.Config` flat fields (`Format`, `Verbose`, `Quiet`, `Theme`) on purpose, for v1.x config compatibility, and the deprecation notes name those readers explicitly. Removing them would break the compatibility path, so the fix is suppression — but *where* you suppress matters.

An earlier attempt added a file-list exclusion to `.golangci.yml`, extending the existing `internal/config` rule to name the `cmd/` test files. It worked, and it was wrong twice over. It made in-flight inline directives redundant, so `nolintlint --fix` silently deleted them; and a file list is a second place to maintain, drifting the moment a test file is renamed.

The approach that shipped puts the directive at the site, on its own line (gofumpt strips inline ones — `AGENTS.md`):

```go
expectedCfg := &config.Config{
    //nolint:staticcheck // SA1019: exercising deprecated flat field for backward-compat coverage.
    Verbose: true,
}
```

Each suppression states its own reason, greps cleanly, dies with the line it guards, and needs no config edit. A config-level path rule is for a whole category of file; a deliberate deprecated call is a per-line decision.

**An untidy `go.mod` breaks the API snapshot tests, and the error does not mention go.mod.** `TestPublicAPISnapshot_*` diffs `go doc` output against a golden fixture. When `go.mod` needs tidying, `go doc` prefixes its output with a warning:

```
go: updates to go.mod needed; to update it:
	go mod tidy
```

That warning lands inside the captured output, so all four snapshot tests fail with a diff whose first line is about go.mod and whose remaining hundreds of lines are the unchanged API surface. The signal is the top of the diff, not its size. A dependency-update commit that leaves `go 1.26` where `go mod tidy` wants `go 1.26.0` is enough to trigger it. Run `go mod tidy` and re-read the first line of the diff before assuming the public API actually changed.

**A cold cache before you conclude anything.** golangci-lint caches per package. Its first run in this session reported `0 issues`; after an unrelated edit invalidated part of the cache, the same tree reported 13. Run `golangci-lint cache clean` before deciding a finding is spurious — or that a clean run means clean.

## Related

- [CI runs on pull_request, not on feature-branch pushes](ci-runs-on-pull-request-not-feature-branch-push.md) — the same local/CI expectation gap seen from the trigger side.
- Adjacent, still open: the `Main` ruleset's `code_scanning` rule requires CodeQL results, but CodeQL default setup is schedule-only (`"schedule":"weekly"`, no `pull_request` trigger), so no PR ever produces them and every PR sits at `BLOCKED` pending a manual maintainer merge — fork or not.
