---
title: A markdown-library dependency bump is an output change, not just a dependency change
category: workflow-issues
date: '2026-08-21'
module: internal/converter
problem_type: workflow_issue
component: converter/builder
severity: medium
tags:
  - dependency-update
  - dependabot
  - markdown
  - golden-tests
  - output-drift
  - line-endings
  - changelog-verification
  - third-party-notices
applies_when:
  - Reviewing a dependency-bump PR for a library that renders or formats generated output rather than providing internal logic
  - Deciding whether a go.mod/go.sum-only diff needs more than `go build` and `go vet` before merging
  - Trusting an upstream changelog's fixed-in-this-version claim without re-verifying it against this repo's actual call pattern
  - Auditing whether every independent markdown-construction path has equivalent golden-fixture coverage
related_issues:
  - '#770'
  - '#754'
related_docs:
  - GOTCHAS.md
---

# A markdown-library dependency bump is an output change, not just a dependency change

## Context

`github.com/nao1215/markdown` (v0.13.0 to v1.0.0, dependabot PR #770) is the library `internal/converter/builder` (and, at the time, `internal/processor/report_markdown.go`) uses to construct every markdown-format report opnDossier generates. 21 Go files referenced the package (12 non-test import sites, plus test files); it is not an incidental dependency — it owns the literal bytes of a primary output format.

The bump touched only `go.mod` and `go.sum`. `go build`, `go vet`, and every package except one passed unchanged. `TestGolden_ProgrammaticReportGeneration` (`internal/converter/golden_test.go`) failed all six subtests — the only failure in the repo.

The actual diff, read from the golden fixtures under `internal/converter/testdata/golden/`, was 16 pure line insertions across the six markdown fixtures, zero deletions: a blank line inserted before every heading that had previously followed a bullet list or a GitHub-alert block directly. That is exactly what markdownlint's MD022 rule (headings must be surrounded by blank lines) checks for. No content, escaping, table-alignment, or line-ending byte changed. The fix was `go test ./internal/converter -run TestGolden -update`, followed by reading the diff before committing.

Two upstream changelog claims looked, at a skim, like they might affect this repo's own line-ending and trailing-newline invariants. Neither held once checked against the actual v1.0.0 module code and this repo's own golden coverage:

- The v1.0.0 CHANGELOG lists "line endings on Windows" among its fixes. Reading the library's own `lf.go` in the module cache (`$(go env GOMODCACHE)/github.com/nao1215/markdown@v1.0.0/internal/lf.go` — a dependency path, not a repo path) shows the fix was a testability refactor — `LineFeed()` now delegates to an unexported `lineFeed(goos string)` so both branches can be tested regardless of the host OS — not a behavior change. `lineFeed` still returns `"\r\n"` when `goos == "windows"` and `"\n"` otherwise, identical to v0.13.0. `internal/converter/builder/lineendings.go`'s `renderMarkdown` (`formatters.NormalizeToLF(md.String())`) and the invariant documented in `GOTCHAS.md` section 10.4 are therefore still load-bearing and unaffected.
- The v1.0.0 CHANGELOG's "Upgrading from v0.13.0" section states every regenerated document now ends with a trailing line ending (MD047 compliance), achieved via the writer-flush path. opnDossier extracts output via `md.String()` directly rather than through that writer-flush path, so this repo's generated reports were verified byte-identical at the tail before and after the bump — still no trailing LF.

A gap surfaced by tracing every call site: `internal/processor/report_markdown.go` built markdown independently of `internal/converter/builder` (the divergence `GOTCHAS.md` section 10.4 already names — both had to be given the `NormalizeToLF` treatment separately for the same reason). It had no golden fixture at all under `internal/processor`, so its output shifted with this same bump and nothing in the test suite would have caught it either way.

> **Since resolved:** `internal/processor` was deleted in #777 (packages outside the binary dependency closure), which removed the second construction path and with it this specific coverage gap. Every remaining `nao1215/markdown` call site is under `internal/converter/`. The general risk stands — the finding here is that the call-site grep is what surfaces an unfixtured path, not that this one path was special.

Separately, `THIRD_PARTY_NOTICES` pins each dependency's license URL to a specific tag via `packaging/notices.tpl` (the `just notices` recipe). Nothing in CI enforces that this file tracks `go.mod`/`go.sum`. Regenerating it after this bump rewrote 26 package URLs and added one new package entry (a font license) — only one of the 26 rewrites was the bumped package — because the file had already drifted from the dependency tree independent of this PR.

## Guidance

When a dependency bump touches a library that constructs literal output bytes — a markdown/HTML/template renderer, a serializer, a formatter — treat it as a potential output-format change, not a routine version-pin update, even when `go.mod`/`go.sum` are the only files in the diff:

1. **Run the full test suite before reading the changelog.** Let golden/fixture tests tell you empirically what changed. `just ci-check` (or the package-specific `go test ./internal/converter -run TestGolden`) surfaces the actual diff; the changelog tells you the intended diff, which is not always the same thing and is not always complete.
2. **Read the actual byte diff on the fixtures, not just the pass/fail.** `go test <pkg> -run <Test> -update` regenerates fixtures; `git diff` on the fixture files afterward is the ground truth for what to describe in the commit message. Pure additive whitespace is the benign case; a change to escaping, table alignment, or content is a real behavior change needing review against the upstream CHANGELOG.
3. **Verify every "this doesn't affect us" claim against the module source in `$(go env GOMODCACHE)`, not the changelog prose alone.** Changelog entries can be incomplete (this one never mentioned the blank-line-before-heading change that was the actual failure, even under its own "Upgrading" section) or describe behavior that doesn't apply to how this codebase calls the library.
4. **Grep every call site of the bumped package, not just the ones the failing test touches.** `report_markdown.go`'s independent markdown construction was found this way — it shares the exposure but not the test coverage.
5. **Regenerate any tag-pinned metadata file (license notices, SBOM, attribution list) when the project has one.** A stale license URL pointing at a superseded tag is real, if low-severity, compliance drift. Expect the regeneration to be noisy if the file has already drifted; that noise is a separate pre-existing problem, and bundling it into a dependabot PR obscures the actual change.

## Why This Matters

A dependency bump that "only touches go.mod" can still be a silent output-format change for any library that constructs bytes rather than just providing logic. `go build` and `go vet` passing is not evidence the output is unchanged; only fixture/golden tests catch that class of regression, and only if every call site of the library has one. This bump's coverage gap (`report_markdown.go` has none) means the same failure mode can recur invisibly the next time this library — or any renderer like it — is bumped, in the one code path nothing would flag.

This is also the second formatting surprise from this same library: PR #754 established the LF-normalization layer (`GOTCHAS.md` section 10.4) after the host-native line-ending behavior reached generated reports. A library that owns output bytes produces this class of problem repeatedly, which is what makes the fixture coverage worth auditing rather than assuming.

Upstream changelogs describe *intended* changes from the maintainer's perspective; they are not a substitute for reading the actual diff against your own fixtures, and they can both omit real changes (the MD022 blank-line insertion) and describe fixes that don't reach your call pattern (MD047 trailing newline, gated behind a writer-flush path this repo doesn't use). Treat changelog claims as hypotheses to verify against `$(go env GOMODCACHE)/<module>@<version>/`, not as facts to cite.

## When to Apply

- Any dependency bump — dependabot-authored or manual — where the bumped package is imported by more than a trivial number of files, or is known to construct output bytes (markdown, HTML, XML/YAML serialization, templating, string-formatting libraries).
- Any time `go build`/`go vet`/lint pass but a golden or snapshot test fails after a dependency bump: read the fixture diff before assuming it is noise, and before running `-update` and moving on.
- Before citing an upstream changelog claim ("fixes X", "Y now behaves correctly") as justification for skipping verification of a repo invariant such as a `GOTCHAS.md` entry — confirm the claim against the vendored module source first.
- When a repo has more than one code path constructing the same output format — a fixture gap on one of them is a standing risk for every future bump of that shared library, not just this one. That was the case here until `internal/processor` was removed in #777; re-run the call-site grep rather than assuming the single-path state still holds.

## Examples

### Verifying a changelog claim against module source instead of trusting it

```bash
# Claim: "v1.0.0 fixes line endings on Windows" (upstream CHANGELOG.md)
GOMODCACHE=$(go env GOMODCACHE)
diff "$GOMODCACHE/github.com/nao1215/markdown@v0.13.0/internal/lf.go" \
     "$GOMODCACHE/github.com/nao1215/markdown@v1.0.0/internal/lf.go"
# Result: behavior unchanged (\r\n on windows, \n otherwise) — only a
# refactor making the OS a parameter for testability. The repo's own
# GOTCHAS.md section 10.4 NormalizeToLF guarantee is still necessary.
```

### Letting the golden fixture diff drive the commit message, not the changelog

```bash
go test ./internal/converter -run TestGolden -update
git diff internal/converter/testdata/golden/
# 16 insertions, 0 deletions, across the 6 markdown fixtures — a blank line before every
# heading that follows a bullet list or GitHub-alert block (MD022).
# That fact, not the changelog's summary, is what the commit message
# and this doc describe.
```

### Finding the untested call site

```bash
grep -rl 'nao1215/markdown' --include='*.go' . | grep -v _test.go
# At the time of this bump:
# internal/converter/builder/*.go        <- has golden fixtures
# internal/processor/report_markdown.go  <- built markdown independently,
#                                           no golden fixture, silent exposure
# (that second path was removed in #777; run the grep again rather than
#  trusting this list)
```

## Related

- `GOTCHAS.md` section 10.4 ("Never Return `md.String()` or `buf.String()` Raw") — the line-ending invariant this bump could have broken but did not, and the reason `report_markdown.go` and `internal/converter/builder` each needed independent `NormalizeToLF` treatment while both existed.
- `GOTCHAS.md` section 22.2 — the `\.golden\.md$` exclude in `.pre-commit-config.yaml` keeps mdformat off these fixtures, which is why golden-file diffing is the sole detection mechanism for this class of upstream formatting change.
- `internal/converter/golden_test.go` — the fixture harness that caught this bump; the `-update` flag is documented at the top of the file.
- `internal/converter/builder/lineendings.go` — the `renderMarkdown` helper that is the sanctioned exit point for markdown output in the builder package.
- PR #770 — the v0.13.0 to v1.0.0 bump this learning documents, merged with the golden-fixture regeneration. The `THIRD_PARTY_NOTICES` refresh is tracked separately, since the notices file had drifted repo-wide and folding that churn into the bump PR would have obscured the actual change.
- PR #754 — the earlier LF-normalization fix from the same library, and the origin of `GOTCHAS.md` section 10.4.
