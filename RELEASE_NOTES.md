# opnDossier v1.7.0 — Real blue/red audit analysis, rule shadowing, and unused-alias detection

v1.7.0 turns the `audit` command's blue and red modes into real analysis over a shared detection engine, adds firewall rule shadowing and unused-alias detection, and closes a cleartext NetBird enrollment-token leak in `sanitize`. It is a drop-in upgrade from v1.6.0 — no breaking changes; the public Go API gains additive fields only.

## Highlights

**Blue and red audit modes now perform real analysis.** Both modes are built on one shared detection engine (`ScanObservations`) so they read as two lenses over the same set of facts. Blue mode appends real hygiene findings (insecure SNMP, weak TLS floor, any-to-any rules, disabled logging), de-duplicates them against fired compliance-plugin findings, derives the compliance-frameworks list from the plugins actually executed instead of a hardcoded `["STIG","NIST","SANS"]`, and builds configuration summary tables from real counts. Red mode's five `add*` methods were placeholder stubs emitting fabricated metadata — a red run against a WAN-exposed-SSH config reported nothing. They now emit reachability-filtered exposure findings: WAN-reachable management services (WebGUI, SSH, SNMP) correlated against WAN pass rules by port, WAN-reachable inbound NAT port-forwards, and WAN-reachable hygiene observations reframed as attack surfaces. The "experimental / not implemented" red-mode warning is gone. (#694, #695)

The engine also consolidated four divergent WAN-detection sites into one canonical reachability helper. The two narrower exact-match checks silently missed multi-WAN interfaces such as `wan2`, so this is a correctness fix as much as a refactor — it now also covers interface-scoped floating rules, IPv6 WAN interfaces, and inbound NAT rules gated on a matching enabled pass rule.

```bash
# Red lens with adversarial tone (opt-in, red mode only)
opndossier audit config.xml --mode red --audit-blackhat
```

Red `ExploitNotes` carry impact and context only — never weaponized or step-by-step guidance. That is enforced by a denylist run over the actual generated notes plus a golden-file gate, not by authoring discipline.

**Firewall rule shadowing detection.** A new `shadowedRules` analysis reports any rule — or a subset of its traffic — that never takes effect because an earlier higher-precedence rule already covers it, classified by operator impact (security / troubleshooting / hygiene). It is backed by a set-relation containment engine over address, port, protocol, and IP family, and a pf precedence resolver that groups rules by `(interface, direction)`, evaluates floating rules device-wide-first, and resolves quick (first-match) against non-quick (last-match) semantics. Firewall aliases are resolved so the overlap analysis is accurate; an unresolvable or dynamic alias surfaces a distinct signal rather than collapsing into "no overlap". (#696)

This lands the additive `NamedObjects` registry on `CommonDevice` with cycle-guarded, depth-capped, memoized resolution. OPNsense's opaque alias blob is retyped to a structured `AliasList`, and pfSense gains a net-new `<aliases>` schema type; both populate `NamedObjects` while preserving resolved inline values.

**Unused named-object (alias) detection.** Aliases that are defined but never referenced by any policy are now surfaced in `audit` output and in the JSON/YAML export as `Analysis.UnusedObjects`. It is modeled as graph reachability from policy roots — nodes are aliases, edges are member-to-object references, roots are every live alias reference on a policy surface — so nested and transitive cases fall out of the traversal. Typed `ObjectRef` fields were added to every alias-capable surface (firewall redirect target; NAT match endpoints, translation targets and ports; static-route network; pfSense OpenVPN local/remote networks) and populated by both vendor converters. Disabled rules deliberately count as references — a staged alias is not a dead one — and the remediation copy hedges rather than instructing deletion. (#710)

**NetBird `setupKey` enrollment tokens are now redacted.** `opnDossier sanitize` was leaking the os-netbird `<setupKey>` enrollment token in cleartext — the same class of bug as the SNMPv3 `<enckey>` leak closed in v1.6.0, caused by the bare `key` field pattern being exact-match only. All sanitize modes now redact it, and the token often persists in configs even when NetBird is disabled or after the plugin is removed. (#728)

## Also in this release

- **Sanitizer hardening:** aggressive-mode redaction now dispatches per whitespace token at the CharData leaf, so IPs and hostnames embedded in multi-value alias members are redacted — previously only single-value fields were. (#696)
- **Custom web-configurator port** is exposed through the unified model as `common.WebGUI.Port`, populated from both vendor schemas, so red analysis reads the real port instead of assuming 443/80. (#695)
- **`deadRules` is deprecated** in favor of `shadowedRules`. It is now derived from the shadow core as its unreachable-plus-duplicate subset with byte-identical output, and carries a `RuleIndex` correlation key and a definite next-major removal criterion. (#696)
- **Architecture decision records:** ADR-0002 (named-object reference layer), ADR-0003 (FortiGate-first parser), ADR-0004 (`deadRules` compatibility view), and ADR-0005 (pf precedence resolution). `CONCEPTS.md` seeded with the audit-analysis domain vocabulary. (#694, #695, #696)
- **CI:** the benchmark workflow was removed and benchmarks kept as on-demand local `just bench*` recipes. Shared-runner CPU contention made wall-clock results non-deterministic, the workflow's package list had gone stale and was failing silently behind `continue-on-error`, and its startup budget enforced 100ms/op against a ~5µs/op actual. (#697)
- **Documentation** on memoizing recursive graph resolution to prevent exponential output size, plus routine dependency and GitHub Actions bumps.

## Upgrade notes

Drop-in upgrade from v1.6.0. No config changes and no breaking changes.

- **Public Go API:** additive fields only — `NamedObjects` on `CommonDevice`, `ObjectRef` on `RuleEndpoint` and the other alias-capable surfaces, `WebGUI.Port`, and `Analysis.UnusedObjects`. All are `omitempty`, so alias-free devices serialize unchanged. The API snapshot goldens were regenerated for these fields.
- **New CLI surface:** `--audit-blackhat`, an opt-in flag guarded to red mode.
- **Audit output changes:** blue and red mode now emit real findings where they previously emitted stubs or fabricated metadata. Any tooling that asserted on the placeholder output will need updating.
- **`deadRules` consumers** are unaffected today (output is byte-identical) but should migrate to `shadowedRules` before the next major.

## Full changelog

See [CHANGELOG.md](./CHANGELOG.md#170---2026-08-10) for the complete list.
