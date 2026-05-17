#!/usr/bin/env bash
set -euo pipefail

# preflight-check-skill — One-command installer
# Creates a dedicated venv, installs the package, registers hooks.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$HOME/.local/share/preflight-check/venv"

echo "=== preflight-check-skill installer ==="
echo ""

# 1. Check Python 3.10+
PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: python3 not found. Install Python 3.10+ first."
    exit 1
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "ERROR: Python 3.10+ required (found $PY_VERSION)"
    exit 1
fi
echo "[ok] Python $PY_VERSION ($PYTHON)"

# 2. Create dedicated venv (avoids PEP 668 / system-packages issues)
echo ""
echo "--- Setting up environment ---"
if [ "${1:-}" = "--dev" ]; then
    echo "Dev mode: using editable install in current venv"
    PIP_CMD="pip install -e"
    PIP_SUFFIX="[dev]"
    # In dev mode, use whatever pip is available
    if command -v pip3 &>/dev/null; then
        pip3 install -e "$SCRIPT_DIR[dev]"
    else
        "$PYTHON" -m pip install -e "$SCRIPT_DIR[dev]"
    fi
    PREFLIGHT_BIN="$(command -v preflight-check)"
    echo "[ok] preflight-check-skill installed (editable/dev mode)"
else
    mkdir -p "$(dirname "$VENV_DIR")"
    if [ ! -d "$VENV_DIR" ]; then
        echo "Creating venv at $VENV_DIR..."
        "$PYTHON" -m venv "$VENV_DIR"
    else
        echo "Using existing venv at $VENV_DIR"
    fi
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet 2>/dev/null || true
    "$VENV_DIR/bin/pip" install "$SCRIPT_DIR"
    PREFLIGHT_BIN="$VENV_DIR/bin/preflight-check"
    echo "[ok] preflight-check-skill installed to $VENV_DIR"
fi

# 3. Verify the install works
if ! "$PREFLIGHT_BIN" status &>/dev/null; then
    echo "ERROR: Installation verification failed."
    echo "  The command '$PREFLIGHT_BIN' does not work."
    exit 1
fi
echo "[ok] CLI verified: $PREFLIGHT_BIN"

# 4. Check gitleaks
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

# 5. Install hook (pass the absolute CLI path)
echo ""
echo "--- Installing Claude Code hook ---"
PREFLIGHT_BIN="$PREFLIGHT_BIN" bash "$SCRIPT_DIR/hook/install.sh"

# 6. Install skill
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

# 7. Summary
echo ""
echo "========================================="
echo "  Installation complete!"
echo "========================================="
echo ""
echo "  Hook:  registered in ~/.claude/settings.json"
echo "  Skill: installed to $SKILL_DIR"
echo "  Config: ~/.claude/preflight.yaml"
echo "  Logs:   ~/.claude/preflight.log"
echo "  CLI:    $PREFLIGHT_BIN"
echo ""
echo "  Test it:"
echo "    echo 'AKIAIOSFODNN7EXAMPLE' | $PREFLIGHT_BIN scan"
echo ""
echo "  Restart Claude Code for hooks to take effect."
