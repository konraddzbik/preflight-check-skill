# Full code & architecture review — 2026-08

Scope: the entire detection engine, hook/CLI layers, plugin distribution, and
packaging of `preflight-check-skill`, at the `v1.1.0` baseline. Reviewed for
correctness bugs, security/privacy, catalog quality (false positives/negatives +
ReDoS), concurrency, and engineering best practices.

**Method:** three independent review lenses (correctness bug-hunt, regex/ReDoS
empirical audit, architecture/best-practices) plus a manual validator pass,
cross-checked and each finding reproduced before fixing. Everything below marked
*Fixed* ships in `v1.2.0`.

## Findings & resolutions

### Blockers

| # | Finding | Reproduction | Resolution |
|---|---------|--------------|------------|
| B1 | **EMAIL regex ReDoS (O(n²)).** The unbounded local part `[…]+` rescanned the whole tail from every start position; a pasted document with a long dotted run (`a@a.a.a…`) hung the hook indefinitely (32 KB ≈ 1.1 s, quadratic). The regex path had no timeout. | `redact("a@" + "a."*20000)` → **1.7 s** before | **Fixed** — bounded quantifiers to RFC-5321 limits (local ≤64, label ≤63, ≤10 sub-labels, TLD 2–24) and removed the class/`\.` ambiguity. Now linear: 156 KB → ~75 ms. Valid + subdomain emails still match. |
| B2 | **gitleaks redacted the wrong occurrence (leak).** `text.find(match)` redacted the *first* literal occurrence; if a benign copy appeared earlier, the real secret survived — worst for gitleaks-only secrets nothing else catches. | `"sample AKIA…KEY0 … real: AKIA…KEY0"` left the second copy | **Fixed** — redact **every** occurrence of each flagged secret (over-redaction is the safe failure mode), prefer the `Secret` field over context-laden `Match`, dedup spans, normalize rule ids to underscores. |
| B3 | **`hook-wrapper.sh` fallback path off by two dirs.** With `marketplace.json` `source: "./"`, `$CLAUDE_PLUGIN_ROOT` *is* the repo root, but the wrapper looked in `$CLAUDE_PLUGIN_ROOT/../..` — so the `core/` discovery could never fire. | plugin-only install → wrapper can't find the engine | **Fixed** — use `$CLAUDE_PLUGIN_ROOT` directly for the venv and direct-module fallbacks. |

### Should-fix

| # | Finding | Resolution |
|---|---------|------------|
| S1 | **`scan --json` was a no-op on the primary shape.** It only redacted `prompt`/`tool_input` when they were strings; the real hook `tool_input` is a dict, so it passed through un-redacted — divergent from the hook. | **Fixed** — both paths now share one `redact_nested()` (extracted to `core/redactor.py`). |
| S2 | **DOWOD_OSOBISTY false positives.** `(?i)\b[A-Z]{3}\d{6}\b` (ungated, case-insensitive) flagged ordinary SKUs/part codes (`abc123456`). | **Fixed** — uppercase-only (`\b[A-Z]{3}\d{6}\b`); real dowód numbers are uppercase. |
| S3 | **Cloud-key coverage gaps** — missed AWS `ASIA` (live STS temp creds) and `AROA/AIDA/…`, GitHub fine-grained `github_pat_`, Slack app-level `xapp-`, OpenAI `sk-svcacct-`, and **lowercase IBANs**. | **Fixed** — catalog patterns extended; IBAN patterns made case-insensitive (the validator already upper-cases). |

### Cleanups (best practices)

| # | Finding | Resolution |
|---|---------|------------|
| C1 | **Pointless `ThreadPoolExecutor`** (never shut down, made placeholder numbering nondeterministic). Parallelism bought nothing — gitleaks is a subprocess on the critical path; regex is microseconds. | **Fixed** — detection is now sequential (regex→gitleaks); numbering is deterministic and the pool lifecycle question is gone. |
| C2 | `validate_regon` had no all-zeros guard (unlike NIP). | **Fixed** — reject all-zeros. |
| C3 | `_digits_only` used `\D`, keeping Unicode digits that `int()` accepts → Arabic-Indic digits could pass a checksum. | **Fixed** — `[^0-9]` (ASCII only). |
| C4 | `redact_nested` was depth-unbounded (theoretical `RecursionError` on hostile input). | **Fixed** — depth cap (`_MAX_NEST_DEPTH = 50`), fails safe. |
| C5 | **Version drift** — `marketplace.json` `metadata.version` was stale (`1.0.0`) vs everything else. | **Fixed** — all four version fields = `1.2.0`, plus a `test_packaging.py` test that fails CI on any future drift. |
| C6 | `bad-pattern` warning went to stdout (corrupts hook JSON); gitleaks future could raise a timeout into `redact()`. | Already fixed in `v1.1.0`. |

## Verified correct (no change)

- **All four checksum validators** — PESEL (weights + month-range), NIP (mod-11, reject 10), REGON (9 & 14-digit), IBAN (mod-97, A=10…Z=35), Luhn (13–19 digits). Algorithms and weights confirmed against references; all length-guard before slicing (no `IndexError`).
- **Overlap resolution** — severity-then-span priority, greedy disjoint acceptance, reverse-order splicing. Identical spans dedupe; adjacent spans (`f.end == a.start`) correctly non-overlapping.
- **`PlaceholderRegistry`** — lock around counter/mapping/save; `chmod 0o600` on the secret-bearing state file; `reverse_map` cannot collide (category embedded in placeholder).
- **Privacy** — the findings log records offsets/lengths and categories only; the secret value never reaches disk, stdout, or stderr (re-verified after all changes).
- **Fail-safe posture** — invalid JSON / exceptions pass through in `default`, block in `strict`; `updatedInput` is emitted only on full success, so Claude never sees a half-redacted payload.

## Testing

- 136 tests pass (was 109). New coverage: EMAIL ReDoS linearity, expanded cloud-key
  formats, gitleaks all-occurrence redaction, `scan --json` nested, validator
  hardening, `redact_nested` depth cap, **hook decision-logic unit tests**
  (strict/warn/default/pass-through — previously 0% on `hook_handler`, now 60%),
  and version-consistency. `ruff` clean, `gitleaks` clean.

## Deferred (tracked, intentional — not bugs)

- **#2** `PreToolUse` empty matcher rewrites `Write`/`Edit`/`Bash` input in place —
  a deliberate design decision (scope to egress tools vs. warn-only), out of scope
  for a bug-fix release.
- **#3** entropy detector for unknown-format secrets — not yet implemented.
- **Distribution model** (plugin vs. pip runtime): the wrapper path bug is fixed;
  the documented model is "install the CLI first, then the plugin finds it." A
  single-runtime story (vendored core, or pip-on-install) is a larger design call
  left for a follow-up.
