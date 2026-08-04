# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
