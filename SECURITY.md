# Security Policy

## Scope and threat model

`preflight-check-skill` is **defense-in-depth, not a guarantee.** It reduces the
chance that secrets or personal data leak through the Claude Code agent boundary
(prompts, tool inputs) or into published material (blogs, transcripts). It is not
a replacement for a secret manager, `.gitignore`/`.claudeignore` discipline, or
commit-time scanners like `gitleaks`/`trufflehog`.

What it can miss:

- Novel API-key formats not yet in the catalog
- Obfuscated secrets (split across variables, base64-wrapped, etc.)
- Secrets inside images, PDFs, or binary files
- Context where a non-secret string is sensitive (a username, a hostname)

A `UserPromptSubmit` hook **cannot rewrite prompt text** — it can only warn or
block. Only tool inputs (`PreToolUse`) can be redacted in place. Use `strict`
mode if you need prompts containing critical secrets to be blocked entirely.

## Reporting a vulnerability

If you find a way this tool leaks data it should have caught, mis-handles a
secret it detected, or has a vulnerability of its own:

- **Do not** open a public issue for anything that would expose a live secret.
- Report privately via GitHub's **"Report a vulnerability"** (Security → Advisories)
  on the repository, or email the maintainer listed in the repository profile.
- Please include: affected version, a minimal reproduction using **synthetic /
  checksum-valid-but-fake** values only (never a real secret), and the observed
  vs. expected behavior.

You can expect an initial acknowledgement within a few days. Fixes for confirmed
detection-bypass or data-leak issues are prioritized.

## Handling of your data

- Detection runs **entirely locally.** No text, findings, or placeholders are
  sent anywhere by this tool.
- The findings log (`~/.claude/preflight.log`) records match **offsets and
  categories only** — never the secret values themselves.
- The optional placeholder-state file contains original values to keep
  placeholders stable across a session; it is written `0600` (owner-only). Delete
  it (or use the in-memory registry) if you do not want originals persisted.
