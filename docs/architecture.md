# preflight-check — architecture

Interactive version: open [`architecture.html`](architecture.html) in a browser and
click through each flow. Static snapshot: [`architecture.png`](architecture.png).

**One detection core, three entry points.** Secrets and PII are caught at the
Claude Code *agent boundary* — the prompt and every tool call — and on demand when
you clean text for publishing.

## Components

| Node | Role | What it is |
|------|------|-----------|
| **User · Claude Code** | entry | Your prompt, a tool call, or pasted text. |
| **Hook Layer** | prevention | `UserPromptSubmit` + `PreToolUse` hooks. Reads the event JSON on stdin before the model/tool acts. |
| **Skill · CLI** | cleanup | `preflight-check` CLI + skill scripts. Manual, publishing-side scrubbing. |
| **Detection Core** | orchestrator | `redactor.py` compiles `catalog.yaml` and runs the two detectors in parallel, then resolves overlaps. |
| **Validated Regex** | detector | PESEL / NIP / REGON / IBAN (mod-11, mod-97), SSN, credit cards (Luhn). Checksums kill false positives. |
| **gitleaks** | detector | Subprocess scan for cloud keys (AWS, GCP, Azure, OpenAI, Anthropic, GitHub, Slack). Fails safe on timeout. |
| **Placeholder Registry** | mapping | Stable `[REDACTED_X_NNN]` tokens — the same secret always maps to the same placeholder. |
| **Findings Log** | audit | `~/.claude/preflight.log` — records offsets + categories only, **never** the secret values. |

## Flows

### 1 · Prompt scan (`UserPromptSubmit`)
Every prompt is scanned before it reaches the model.
1. **User → Hook** — prompt arrives as JSON on stdin, pre-model.
2. **Hook → Core** — `redactor.redact(prompt)`; regex + gitleaks run in parallel.
3. **Core → Validated Regex** — checksum-gated PII (a random 11-digit number is *not* a PESEL).
4. **Core → gitleaks** — cloud-key scan.
5. **Core → Placeholder Registry** — stable placeholders assigned.
6. **Core → Findings Log** — offsets logged, no values.
7. **Hook → User** — a prompt hook *cannot rewrite* text, only warn or block.

### 2 · Tool-input redaction (`PreToolUse`)
Tool inputs — unlike prompts — *can* be rewritten before execution.
1. **User → Hook** — the full `tool_input` (Bash/Write/Edit/…) as JSON.
2. **Hook → Core** — `_redact_nested()` walks strings, dicts (env maps), lists (arg arrays).
3–5. **Core → Regex / gitleaks / Registry** — same detection as the prompt path.
6. **Hook → User** — `updatedInput` with placeholders substituted in place.

### 3 · Manual cleanup (skill / CLI)
The same core, invoked by hand to scrub text before you publish.
1. **User → Skill** — `/preflight-check`, or `pbpaste | preflight-check scan | pbcopy`.
2. **Skill → Core** — shells out to the same CLI + detection core the hooks use.
3–5. **Core → Regex / gitleaks / Registry** — detection.
6. **Skill → User** — redacted text on stdout / clipboard, safe to publish.

## Modes (the toggle)

The mode changes only the **final decision**, not the detection:

| Mode | Prompt (`UserPromptSubmit`) | Tool input (`PreToolUse`) |
|------|------------------------------|----------------------------|
| **default** | Warn (add context) | Redact in place via `updatedInput` |
| **strict** | Block the prompt (exit 2) on a critical | Deny the tool call on a critical |
| **warn-only** | Warn, never block | Run unchanged, warn only |
