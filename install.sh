#!/usr/bin/env bash
set -euo pipefail

# preflight-check-skill — One-command installer
# Installs the detection core, hook layer, and skill layer.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== preflight-check-skill installer ==="
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

# 2. Install Python package
echo ""
echo "--- Installing Python package ---"
if [ "${1:-}" = "--dev" ]; then
    pip3 install -e "$SCRIPT_DIR[dev]" 2>/dev/null || python3 -m pip install -e "$SCRIPT_DIR[dev]"
    echo "[ok] preflight-check-skill installed (editable/dev mode)"
else
    pip3 install "$SCRIPT_DIR" 2>/dev/null || python3 -m pip install "$SCRIPT_DIR"
    echo "[ok] preflight-check-skill installed"
fi

# 3. Check gitleaks
echo ""
echo "--- Checking gitleaks ---"
if command -v gitleaks &>/dev/null; then
    GITLEAKS_VERSION=$(gitleaks version 2>/dev/null || echo "unknown")
    echo "[ok] gitleaks found ($GITLEAKS_VERSION)"
else
    echo "[warn] gitleaks not found — secret detection will use regex only"
    echo ""
    if command -v brew &>/dev/null; then
        echo "  Install with: brew install gitleaks"
    else
        echo "  Install with: go install github.com/gitleaks/gitleaks/v8@latest"
    fi
    echo "  Or download: https://github.com/gitleaks/gitleaks/releases"
    echo ""
fi

# 4. Install hook
echo ""
echo "--- Installing Claude Code hook ---"
bash "$SCRIPT_DIR/hook/install.sh"

# 5. Install skill
echo ""
echo "--- Installing skill ---"
SKILL_DIR="$HOME/.claude/skills/preflight-check"
mkdir -p "$SKILL_DIR"
cp "$SCRIPT_DIR/skill/SKILL.md" "$SKILL_DIR/SKILL.md"
if [ -d "$SCRIPT_DIR/skill/scripts" ]; then
    cp -r "$SCRIPT_DIR/skill/scripts" "$SKILL_DIR/"
fi
if [ -d "$SCRIPT_DIR/skill/examples" ]; then
    cp -r "$SCRIPT_DIR/skill/examples" "$SKILL_DIR/"
fi
echo "[ok] Skill installed to $SKILL_DIR"

# 6. Summary
echo ""
echo "========================================="
echo "  Installation complete!"
echo "========================================="
echo ""
echo "  Hook:  registered in ~/.claude/settings.json"
echo "  Skill: installed to $SKILL_DIR"
echo "  Config: ~/.claude/preflight.yaml"
echo "  Logs:   ~/.claude/preflight.log"
echo ""
echo "  Test it:"
echo "    echo 'AKIAIOSFODNN7EXAMPLE' | preflight-check"
echo ""
echo "  Restart Claude Code for hooks to take effect."
