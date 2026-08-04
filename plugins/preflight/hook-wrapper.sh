#!/usr/bin/env bash
# Preflight-check hook wrapper for Claude Code plugin
# Finds the preflight-check installation and delegates to it
#
# This script runs from Claude Code's cached plugin directory:
#   ~/.claude/plugins/marketplaces/<author>/preflight-check-skill/<version>/plugins/preflight/
#
# We need to find the preflight-check CLI which may be:
# 1. On PATH (if user added venv to PATH)
# 2. In a common venv location
# 3. In the original repo location (during dev)

PREFLIGHT_BIN=""

# 1. Try PATH first
if command -v preflight-check &>/dev/null; then
    PREFLIGHT_BIN="$(command -v preflight-check)"
fi

# 2. Try common venv locations
if [ -z "$PREFLIGHT_BIN" ]; then
    for venv in \
        "$HOME/.local/share/preflight-check/venv/bin/preflight-check" \
        "$HOME/.local/preflight-check/venv/bin/preflight-check" \
        "/usr/local/bin/preflight-check" \
        "/usr/bin/preflight-check"; do
        if [ -x "$venv" ]; then
            PREFLIGHT_BIN="$venv"
            break
        fi
    done
fi

# 3. Try a venv inside the plugin root.
# With marketplace.json `source: "./"`, CLAUDE_PLUGIN_ROOT *is* the repo root,
# so core/ lives directly under it (not two levels up).
if [ -z "$PREFLIGHT_BIN" ] && [ -n "${CLAUDE_PLUGIN_ROOT:-}" ]; then
    REPO_ROOT="$CLAUDE_PLUGIN_ROOT"
    for venv in "$REPO_ROOT/venv/bin/preflight-check" "$REPO_ROOT/.venv/bin/preflight-check"; do
        if [ -x "$venv" ]; then
            PREFLIGHT_BIN="$venv"
            break
        fi
    done
fi

# 4. Fall back to running the module directly from the plugin root.
if [ -z "$PREFLIGHT_BIN" ] && [ -n "${CLAUDE_PLUGIN_ROOT:-}" ]; then
    REPO_ROOT="$CLAUDE_PLUGIN_ROOT"
    if [ -f "$REPO_ROOT/core/hook_handler.py" ]; then
        PYTHON_CMD="$REPO_ROOT/venv/bin/python3"
        if [ ! -x "$PYTHON_CMD" ]; then
            PYTHON_CMD="python3"
        fi
        if command -v "$PYTHON_CMD" &>/dev/null; then
            export PYTHONPATH="$REPO_ROOT:$PYTHONPATH"
            exec "$PYTHON_CMD" -c "from core.hook_handler import main; import sys; sys.exit(main())"
        fi
    fi
fi

# Execute the found binary
if [ -n "$PREFLIGHT_BIN" ] && [ -x "$PREFLIGHT_BIN" ]; then
    exec "$PREFLIGHT_BIN" hook
else
    echo "preflight-check not found. Install with: pip install preflight-check-skill" >&2
    echo "Or run: ./install.sh from the preflight-check-skill repo" >&2
    exit 1
fi