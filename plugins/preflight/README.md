# Preflight Check Plugin

This directory contains the Claude Code plugin hooks for preflight-check.

## Structure

```
plugins/preflight/
├── hooks/
│   └── hooks.json     # Hook definitions (auto-registered)
├── hook-wrapper.sh   # Wrapper script to find preflight-check installation
└── README.md
```

## How It Works

1. When the plugin is installed, hooks.json is automatically registered with Claude Code
2. The hooks intercept `UserPromptSubmit` and `PreToolUse` events
3. The wrapper script (`hook-wrapper.sh`) locates the preflight-check installation and delegates to it
4. The preflight-check CLI handles the actual redaction logic

## Installation

The plugin is installed via:

```bash
claude plugin marketplace add <repo-url>
claude plugin install preflight@preflight-check
```

## Hook Configuration

The hooks run the `preflight-check hook` command which:
- Reads JSON from stdin (Claude Code hook protocol)
- Processes the prompt/tool_input for secrets/PII
- Returns appropriate response (allow/block/warn based on config)