# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-04

Full code + architecture review pass — see [`docs/CODE_REVIEW.md`](docs/CODE_REVIEW.md).

### Fixed

- **EMAIL ReDoS (blocker):** the email pattern was O(n²) and could hang the hook
  on a pasted document with a long dotted run. Rewritten with RFC-bounded
  quantifiers → linear time (156 KB now scans in ~75 ms; valid/subdomain emails
  still match).
- **gitleaks occurrence-mismatch leak (blocker):** a flagged secret is now
  redacted at **every** occurrence (was: only the first literal match, so a real
  secret could survive if a benign copy appeared earlier). Prefers the `Secret`
  field over context-laden `Match`.
- **Plugin `hook-wrapper.sh` path bug:** the `core/` fallback discovery looked two
  directories above the plugin root and could never fire; now uses
  `$CLAUDE_PLUGIN_ROOT` directly.
- **`scan --json` no-op:** it only redacted top-level strings, so a dict
  `tool_input` (the real hook shape) passed through un-redacted. Now shares the
  hook's recursive `redact_nested`.
- **DOWOD_OSOBISTY false positives:** dropped `(?i)` — it matched ordinary
  lowercase SKUs/part codes and has no checksum to gate it.
- REGON now rejects all-zeros; checksum inputs are stripped to ASCII digits only
  (Unicode digits no longer sneak through `int()`).

### Added / changed

- **Expanded cloud-key coverage:** AWS `ASIA` (STS temp creds) + `AROA/AIDA/…`,
  GitHub fine-grained `github_pat_`, Slack app-level `xapp-`, OpenAI
  `sk-svcacct-`, and **lowercase IBANs**.
- **Detection is now sequential** (regex → gitleaks) instead of a 2-thread pool:
  the parallelism bought nothing (gitleaks subprocess dominates) and made
  placeholder numbering nondeterministic. Numbering is now stable run-to-run.
- `redact_nested` extracted to `core/redactor.py` (shared by hook + CLI) with a
  depth cap against pathological nesting.
- Version single-sourced to `1.2.0` across all four manifests, with a CI test
  that fails on drift.
- Test suite grew 109 → 136 (hook decision-logic now unit-tested; `hook_handler`
  coverage 0% → 60%).

## [1.1.0] - 2026-08-04

First public release.

### Fixed

- **Gitleaks duplicate matches** now get distinct offsets — the same secret
  appearing twice is redacted at both positions instead of once.
- **Nested tool inputs** (dicts and lists, e.g. `env` maps or `args` arrays) are
  now recursively redacted in the `PreToolUse` hook, not just top-level strings.
- **Dowód osobisty** detection is now case-insensitive.
- **Luhn validation** correctly rejects checksum-valid numbers that are shorter
  than a real card (13–19 digits).
- **Findings log** records match offsets/lengths and categories only — never the
  secret values themselves.
- **`install.sh`** hook registration no longer interpolates shell variables into
  a Python heredoc (values are passed via the environment instead).
- Bad-catalog-pattern warnings now go to **stderr**, so they can't corrupt the
  hook's JSON protocol on stdout.
- A gitleaks timeout can no longer abort a redaction — detection falls back to
  regex/validated findings only.

### Added

- **Claude Code plugin distribution** now works end to end: added
  `.claude-plugin/marketplace.json`, wired the hooks via an explicit `hooks` path
  in `plugin.json`, and corrected `hooks.json` to the object-keyed-by-event
  schema Claude Code expects.
- `SECURITY.md` (vulnerability-disclosure policy, threat model, data handling)
  and `CONTRIBUTING.md`.
- Threat-model note documenting in-place tool-input redaction trade-offs.

### Changed

- The entropy-based fallback detector is documented as **planned / not yet
  implemented** and disabled by default (it was previously advertised as active).

### Known limitations / follow-ups

- `PreToolUse` uses an empty matcher (all tools); scoping it to egress-style
  tools is tracked as a follow-up.
- The entropy detector for unknown-format secrets is not yet implemented.
