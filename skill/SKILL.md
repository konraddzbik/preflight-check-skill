---
name: preflight-check
description: Anonymize and redact secrets, API keys, and personal data from text, code, or files before sharing externally. Use this skill whenever the user asks to scrub, anonymize, redact, or clean content for publication — including blog posts, LinkedIn posts, workshop materials, screenshots, or transcripts. Triggers include phrases like "anonymize", "redact", "scrub this", "remove secrets", "prepare for blog", "clean before sharing", "zanonimizuj", "usun sekrety", "wyczysc przed publikacja". Detects cloud API keys (AWS, GCP, Azure, OpenAI, Anthropic, GitHub, Slack), Polish PII (PESEL, NIP, REGON, IBAN PL — all checksum-validated), EU PII (emails, phones), and US PII (SSN, credit cards with Luhn validation).
---

# Preflight Check — Redaction Skill

Post-hoc cleanup of text, code snippets, and files before external publication.

## When to use

- Preparing a blog post that includes a real terminal transcript
- Cleaning a code snippet for a LinkedIn post
- Anonymizing client data before using it in a workshop
- Producing a public version of an internal report

## Usage

### Redact a file

```bash
preflight-check scan --file path/to/file.txt
```

Output goes to stdout with findings summary on stderr. Redirect to create a redacted copy:

```bash
preflight-check scan --file notes.txt > notes.redacted.txt
```

### Redact piped text

```bash
echo "my PESEL is 44051401359" | preflight-check scan
```

### Redact clipboard (macOS/Linux)

```bash
pbpaste | preflight-check scan | pbcopy
```

### Check installation status

```bash
preflight-check status
```

## What it detects

| Category | Examples | Validation |
|----------|----------|------------|
| Cloud keys | AWS, GCP, Azure, OpenAI, Anthropic, GitHub, Slack | prefix + format |
| Polish PII | PESEL, NIP, REGON, IBAN PL | mod-11, mod-97 checksums |
| EU PII | Email, phone (E.164 + PL), generic IBAN | mod-97 for IBAN |
| US PII | SSN, credit cards | Luhn algorithm |

See `core/catalog.yaml` for the complete catalog.

## What it does NOT replace

This skill is for the **publishing-side** workflow. For prevention while
working in Claude Code, install the hook layer instead — see repo README.
