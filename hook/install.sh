#!/usr/bin/env bash
set -euo pipefail

# preflight-check-skill — Hook installer
# Idempotent: safe to run multiple times.
# Expects PREFLIGHT_BIN env var (absolute path to preflight-check CLI).

SETTINGS_FILE="$HOME/.claude/settings.json"
CONFIG_FILE="$HOME/.claude/preflight.yaml"

echo "=== preflight-check-skill hook installer ==="
echo ""

# 1. Resolve CLI path
if [ -n "${PREFLIGHT_BIN:-}" ]; then
    CLI_PATH="$PREFLIGHT_BIN"
elif command -v preflight-check &>/dev/null; then
    CLI_PATH="$(command -v preflight-check)"
else
    echo "ERROR: preflight-check not found on PATH."
    echo "  Set PREFLIGHT_BIN or run: pip install preflight-check-skill"
    exit 1
fi

# Resolve to absolute path
CLI_PATH="$(cd "$(dirname "$CLI_PATH")" && pwd)/$(basename "$CLI_PATH")"
echo "[ok] CLI: $CLI_PATH"

# 2. Ensure ~/.claude/ exists
mkdir -p "$HOME/.claude"

# 3. Back up existing settings.json
if [ -f "$SETTINGS_FILE" ]; then
    BACKUP="$SETTINGS_FILE.bak.$(date +%s)"
    cp "$SETTINGS_FILE" "$BACKUP"
    echo "[ok] Backed up settings to $BACKUP"
fi

# 4. Register hooks in settings.json (idempotent, uses absolute CLI path)
PREFLIGHT_SETTINGS_FILE="$SETTINGS_FILE" PREFLIGHT_CLI_PATH="$CLI_PATH" python3 << 'PYEOF'
import json
import os
import sys

settings_file = os.environ["PREFLIGHT_SETTINGS_FILE"]
hook_cmd = os.environ["PREFLIGHT_CLI_PATH"] + " hook"

try:
    if os.path.exists(settings_file):
        with open(settings_file, "r") as f:
            settings = json.load(f)
    else:
        settings = {}
except json.JSONDecodeError:
    print(f"ERROR: {settings_file} contains invalid JSON.", file=sys.stderr)
    print("  Fix it manually or delete it and re-run this installer.", file=sys.stderr)
    sys.exit(1)

if "hooks" not in settings:
    settings["hooks"] = {}

for event in ["UserPromptSubmit", "PreToolUse"]:
    matcher_groups = settings["hooks"].get(event, [])

    already_registered = False
    for group in matcher_groups:
        if isinstance(group, dict):
            for h in group.get("hooks", []):
                if isinstance(h, dict) and "preflight-check" in h.get("command", ""):
                    already_registered = True
                    break

    if not already_registered:
        matcher_groups.append({
            "matcher": "",
            "hooks": [{"type": "command", "command": hook_cmd}]
        })
        settings["hooks"][event] = matcher_groups

with open(settings_file, "w") as f:
    json.dump(settings, f, indent=2)

print("[ok] Hooks registered in " + settings_file)
PYEOF

# 5. Create default config if missing
if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" << 'YAML'
# preflight-check-skill configuration
# mode: strict | default | warn-only
mode: default
log_path: ~/.claude/preflight.log
YAML
    echo "[ok] Created default config at $CONFIG_FILE"
else
    echo "[ok] Config already exists at $CONFIG_FILE"
fi

echo ""
echo "=== Hook installation complete ==="
echo ""
echo "Hooks registered for: UserPromptSubmit, PreToolUse"
echo "Hook command: $CLI_PATH hook"
echo "Mode: $(grep 'mode:' "$CONFIG_FILE" | head -1 | awk '{print $2}')"
echo ""
echo "Next steps:"
echo "  - Edit $CONFIG_FILE to change mode (strict/default/warn-only)"
echo "  - Restart Claude Code for hooks to take effect"
echo "  - Check $HOME/.claude/preflight.log for detection results"
