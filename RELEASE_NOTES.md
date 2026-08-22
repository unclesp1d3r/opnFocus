# opnDossier v1.7.1 — Data-loss and output-integrity fixes

v1.7.1 is a patch release. It fixes two ways the tool could silently destroy or discard a user's data, closes an HTML injection path through untrusted config values, and makes generated Markdown byte-identical across platforms. It is a drop-in upgrade from v1.7.0 — no config changes, no CLI changes, and no public Go API changes.

## Fixed

**`sanitize` could destroy the config it was reading.** `opnDossier sanitize config.xml -o config.xml --force` opened the input for reading and then truncated the same path with `os.Create`, emptying the configuration before the sanitizer ever read it — and exited 0 reporting "0 fields redacted". `--mapping` had the same failure mode, and `--output` pointed at `--mapping` silently replaced the sanitized config with the mapping JSON. This contradicted `sanitize --help`, which states the input is never modified in place. Runs where the input, `--output`, and `--mapping` do not all resolve to distinct files are now rejected before anything is opened for writing; detection compares cleaned absolute paths and then `os.SameFile`, so symlinks, hard links, relative aliases, and case variants are all caught. The document is sanitized into a buffer and the destination is created only after that succeeds. Both artifacts are now written `0600` — the `--mapping` file holds every original hostname, address, username, and email in cleartext beside its pseudonym, and previously got `0666` masked by umask. ([#749](https://github.com/EvilBit-Labs/opnDossier/pull/749))

**Config values rendered as live markup in HTML reports.** A hostname of `<img src=x onerror=alert(1)>` was emitted unescaped into `convert --format html` output, and the same path existed in `audit --format html` and `diff --format html`. Config values are now escaped. ([#749](https://github.com/EvilBit-Labs/opnDossier/pull/749))

**Multi-file `convert` runs discarded all but one report.** `opnDossier convert a.xml b.xml -o out.md --force` produced a single file and exited 0 — every worker resolved the same `--output` path and wrote it concurrently, so on POSIX the last writer won and the other reports vanished; on Windows the second rename failed against the open handle. `convert` now derives a unique per-input output path, the same way `audit` already did, and does not fall back to stdout for multi-file runs. That fallback is not viable for the structured formats: two JSON documents produce `}{` and fail to parse, two HTML documents give two doctypes, and two YAML documents parse as one mapping where the second config's keys silently replace the first. ([#750](https://github.com/EvilBit-Labs/opnDossier/pull/750))

**Aggressive-mode sanitize produced invalid addresses and collided with real ones.** `MapPrivateIP` numbered its replacements into `10.0.0.0/24` with `fmt.Sprintf("10.0.0.%d", counter)`. Past 255 distinct private addresses that produced invalid octets — a config with 300 of them yielded 45 addresses from `10.0.0.256` upward, and the sanitized file no longer passed `opnDossier validate`. The replacement space also overlapped the input space, which is RFC1918 by definition, so a pseudonym could be indistinguishable from a real address elsewhere in the same file. Private IPs are now replaced with markers instead of synthesized addresses. ([#752](https://github.com/EvilBit-Labs/opnDossier/pull/752))

**Generated Markdown is now LF on every platform.** `github.com/nao1215/markdown` emits the host's line ending, so every report generated on a Windows checkout contained CRLF — despite `internal/export` documenting that exports use LF for deterministic cross-platform builds. The same configuration produced byte-different reports depending on where it ran. CRLF on disk is still available via `OPNDOSSIER_PLATFORM_LINE_ENDINGS=1`. ([#754](https://github.com/EvilBit-Labs/opnDossier/pull/754))

## Also in this release

- **Go toolchain** bumped to 1.26.6. ([#755](https://github.com/EvilBit-Labs/opnDossier/pull/755))
- **The race detector now runs in CI**, and the wall-clock tests that previously made it unusable are skipped or scaled under `-race`. The Windows job also runs the full test suite now rather than the `ci-smoke` subset, which the LF fix unblocked. ([#753](https://github.com/EvilBit-Labs/opnDossier/pull/753), [#754](https://github.com/EvilBit-Labs/opnDossier/pull/754))
- **Audit finding-type literals** consolidated into shared constants. ([#738](https://github.com/EvilBit-Labs/opnDossier/pull/738))
- Two factually wrong code comments corrected, user-guide version examples swept, and routine dependency and GitHub Actions bumps. ([#756](https://github.com/EvilBit-Labs/opnDossier/pull/756), [#761](https://github.com/EvilBit-Labs/opnDossier/pull/761))

## Upgrade notes

Drop-in upgrade from v1.7.0. No breaking changes; the public Go API is unchanged (the API snapshot goldens are byte-identical to v1.7.0).

- **Sanitized output differs.** Aggressive mode now emits markers for private IPs where it previously emitted synthesized `10.0.0.x` addresses. Tooling that consumed the old pseudonyms will need updating.
- **Multi-file `convert` writes one file per input** instead of one clobbered file. Scripts that passed several inputs with a single `-o` were previously losing data; they now produce a file per input.
- **HTML reports escape config values.** Output that previously contained raw markup from the config is now escaped.

## Full changelog

See [CHANGELOG.md](./CHANGELOG.md#171---2026-08-22) for the complete list.
