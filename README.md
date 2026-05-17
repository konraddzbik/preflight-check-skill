# preflight-check-skill

> Defensive toolkit for Claude Code: stop secrets, API keys, and personal data
> from leaving your machine — and clean transcripts before you publish.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/konraddzbik/preflight-check-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/konraddzbik/preflight-check-skill/actions)

---

## What this does

Two layers, one detection engine:

1. **Hook layer (prevention)** — runs inside Claude Code as a `UserPromptSubmit`
   and `PreToolUse` hook. For prompts: warns or blocks when secrets are detected.
   For tool inputs (Bash, Edit, Write): redacts secrets in place before execution.
2. **Skill layer (cleanup)** — a Claude skill you invoke manually when you
   want to scrub a transcript, code snippet, or document before publishing
   to a blog, LinkedIn post, or workshop material.

Both layers share the same detection core: gitleaks for cloud secrets +
custom validated patterns for PII (Polish, EU, US).

---

## What it detects

| Category | Examples | Validation |
|---|---|---|
| **Cloud keys** | AWS, GCP, Azure, OpenAI, Anthropic, GitHub, Slack, JWT | prefix + format |
| **Polish PII** | PESEL, NIP, REGON, IBAN PL, dowod osobisty | mod-11, mod-97 checksums |
| **EU PII** | Email, phone (E.164 + PL), generic IBAN | mod-97 for IBAN |
| **US PII** | SSN, credit cards | Luhn algorithm |
| **Unknown secrets** | High-entropy strings (>=4.5 bits, >=32 chars) | configurable |

Checksum validation is the difference between useful detection and noise.
A random 11-digit order number won't be flagged as a PESEL.

---

## Quick start

```bash
git clone https://github.com/konraddzbik/preflight-check-skill.git
cd preflight-check-skill
./install.sh
```

The installer will:
1. Install Python dependencies (`pyyaml`)
2. Check for `gitleaks` (and offer to install it)
3. Register the hook in `~/.claude/settings.json`
4. Copy the skill to `~/.claude/skills/preflight-check/`

Test it:

```bash
echo "My AWS key is AKIAIOSFODNN7EXAMPLE" | preflight-check
# Output: My AWS key is [REDACTED_AWS_ACCESS_KEY_001]
```

---

## Demo

```
$ echo "PESEL 99123175313, email user@corp.com, key AKIAIOSFODNN7EXAMPLE" | preflight-check scan
PESEL [REDACTED_PESEL_001], email [REDACTED_EMAIL_001], key [REDACTED_AWS_ACCESS_KEY_001]

$ # Hook on PreToolUse — redacts tool input in place:
$ echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo AKIAIOSFODNN7EXAMPLE"}}' \
  | preflight-check hook
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"echo [REDACTED_AWS_ACCESS_KEY_001]"}}}

$ preflight-check status
preflight-check-skill status
========================================
[ok] Config: ~/.claude/preflight.yaml
[ok] Hook: registered in ~/.claude/settings.json
[ok] Gitleaks: available
[ok] Skill: installed at ~/.claude/skills/preflight-check
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User in Claude Code                   │
└──────────────────┬──────────────────────────────────────┘
                   │ prompt / tool input
                   v
┌─────────────────────────────────────────────────────────┐
│ HOOK LAYER (UserPromptSubmit, PreToolUse)               │
│   hook/claude_redact_hook.py                            │
└──────────────────┬──────────────────────────────────────┘
                   │ uses
                   v
┌─────────────────────────────────────────────────────────┐
│                  DETECTION CORE                          │
│   core/redactor.py  (orchestrator)                       │
│   core/catalog.yaml  (all patterns)                      │
│   core/detectors/                                        │
│     ├── validators.py  (PESEL, NIP, IBAN, Luhn)          │
│     └── gitleaks_wrapper.py  (cloud keys, parallel)      │
│   core/placeholders.py  (stable [REDACTED_X_NNN])        │
└──────────────────┬──────────────────────────────────────┘
                   │ also used by
                   v
┌─────────────────────────────────────────────────────────┐
│ SKILL LAYER (manual invocation)                         │
│   skill/SKILL.md                                        │
│   skill/scripts/redact_file.py                          │
│   skill/scripts/redact_clipboard.py                     │
└─────────────────────────────────────────────────────────┘
```

---

## Configuration

Edit `core/catalog.yaml` to enable/disable categories or add custom patterns.
No code changes required.

```yaml
polish_pii:
  - id: PESEL
    pattern: '\b\d{11}\b'
    validator: validate_pesel
    severity: critical
    enabled: true   # flip to false if you don't need this
```

Per-environment overrides go in `~/.claude/preflight.yaml`:

```yaml
mode: strict        # strict | default | warn-only
log_path: ~/.claude/preflight.log
```

**Modes:**

| Mode | UserPromptSubmit | PreToolUse |
|------|-----------------|------------|
| `default` | Warn (add context) | Redact tool input via `updatedInput` |
| `strict` | Block prompt (exit 2) if critical | Deny tool call if critical |
| `warn-only` | Warn (add context) | Warn only, no modification |

Note: Claude Code hooks cannot modify prompt text — only block or add context.
Tool inputs (Bash commands, file edits) *can* be redacted in place.

---

## Threat model — read this

This tool is **defense-in-depth, not a guarantee.**

What it catches: well-known cloud key formats, validated PII, high-entropy
strings above the threshold.

What it can miss:
- Novel API key formats not yet in the catalog
- Obfuscated secrets (split across variables, base64-wrapped, etc.)
- Secrets inside images, PDFs, or binary files
- Context where a non-secret string is sensitive (a username, a hostname)

**Important limitation:** Claude Code hooks cannot modify user prompts —
only block them or add warnings. Tool inputs (Bash commands, file writes)
*can* be redacted in place. Use `strict` mode if you need prompts with
secrets to be blocked entirely.

**Always combine with:**
- `.claudeignore` for files that should never be read
- `gitleaks` / `trufflehog` as pre-commit hooks
- Vault / secret manager for actual production secrets
- Code review

If you spot a missed category or a false positive, please open an issue.

---

## Polski (PL)

Narzedzie obronne dla Claude Code: zapobiega wyciekom kluczy API, sekretow
i danych osobowych z Twojego komputera, oraz czysci transkrypty przed
publikacja (blog, LinkedIn, materialy szkoleniowe).

**Polskie PII z walidacja sum kontrolnych:**
- PESEL (mod-11 + walidacja miesiaca urodzenia)
- NIP (suma wazona mod-11)
- REGON (9 i 14 cyfr)
- IBAN PL (mod-97)

**Szybki start:**
```bash
git clone https://github.com/konraddzbik/preflight-check-skill.git
cd preflight-check-skill
./install.sh
```

Konfiguracja w `core/catalog.yaml`. Mozna dodac wlasne wzorce bez zmiany kodu.

Tryby pracy (`~/.claude/preflight.yaml`):
- `strict` — blokuje zapytanie przy wykryciu krytycznego sekretu
- `default` — redaguje w miejscu, loguje, przepuszcza
- `warn-only` — loguje bez modyfikacji

---

## Uninstall

Remove the hooks from `~/.claude/settings.json` (delete the preflight entries),
then:

```bash
rm -rf ~/.claude/skills/preflight-check
rm -f ~/.claude/preflight.yaml ~/.claude/preflight.log
pip uninstall preflight-check-skill
```

---

## Development

```bash
pip install -e ".[dev]"
pytest --cov=core
ruff check .
```

## Contributing

PRs welcome. Please include test fixtures with synthetic-but-checksum-valid
values, never real secrets. CI runs `gitleaks` against the repo to enforce this.

## License

MIT — see [LICENSE](LICENSE).
