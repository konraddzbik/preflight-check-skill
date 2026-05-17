"""
Claude Code hook entry point — thin wrapper.

Production hooks should use `preflight-check hook` (the installed CLI).
This script exists for development and as a fallback.
"""

from __future__ import annotations

import sys

try:
    from core.hook_handler import main
except ImportError as exc:
    print(
        f"[preflight-hook] import error: {exc}. "
        f"Run: pip install preflight-check-skill",
        file=sys.stderr,
    )
    sys.exit(0)

if __name__ == "__main__":
    sys.exit(main())
