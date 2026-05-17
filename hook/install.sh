#!/usr/bin/env bash
set -euo pipefail

# preflight-check-skill — Hook installer
# Idempotent: safe to run multiple times.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK_SCRIPT="$SCRIPT_DIR/claude_redact_hook.py"
SETTINGS_FILE="$HOME/.claude/settings.json"
CONFIG_FILE="$HOME/.claude/preflight.yaml"

echo "=== preflight-check-skill hook installer ==="
echo ""

# 1. Check Python 3.10+
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.10+ first."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "ERROR: Python 3.10+ required (found $PY_VERSION)"
    exit 1
fi
echo "[ok] Python $PY_VERSION"

# 2. Check hook script exists
if [ ! -f "$HOOK_SCRIPT" ]; then
    echo "ERROR: Hook script not found at $HOOK_SCRIPT"
    exit 1
fi
echo "[ok] Hook script: $HOOK_SCRIPT"

# 3. Ensure ~/.claude/ exists
mkdir -p "$HOME/.claude"

# 4. Back up existing settings.json
if [ -f "$SETTINGS_FILE" ]; then
    BACKUP="$SETTINGS_FILE.bak.$(date +%s)"
    cp "$SETTINGS_FILE" "$BACKUP"
    echo "[ok] Backed up settings to $BACKUP"
fi

# 5. Register hooks in settings.json (idempotent, matcher wrapper format)
python3 << PYEOF
import json
import os

settings_file = "$SETTINGS_FILE"
hook_cmd = "python3 $HOOK_SCRIPT"

if os.path.exists(settings_file):
    with open(settings_file, "r") as f:
        settings = json.load(f)
else:
    settings = {}

if "hooks" not in settings:
    settings["hooks"] = {}

for event in ["UserPromptSubmit", "PreToolUse"]:
    matcher_groups = settings["hooks"].get(event, [])

    # Check if already registered in any matcher group
    already_registered = False
    for group in matcher_groups:
        if isinstance(group, dict):
            for h in group.get("hooks", []):
                if isinstance(h, dict) and h.get("command") == hook_cmd:
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

# 6. Create default config if missing
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
echo "=== Installation complete ==="
echo ""
echo "Hooks registered for: UserPromptSubmit, PreToolUse"
echo "Mode: $(grep 'mode:' "$CONFIG_FILE" | head -1 | awk '{print $2}')"
echo ""
echo "Next steps:"
echo "  - Edit $CONFIG_FILE to change mode (strict/default/warn-only)"
echo "  - Restart Claude Code for hooks to take effect"
echo "  - Check $HOME/.claude/preflight.log for detection results"
