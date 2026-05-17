"""
Claude Code hook entry point — thin wrapper.

Production hooks use `preflight-check hook` (the installed CLI).
This script exists for development/testing and as a fallback.
"""

from __future__ import annotations

import sys
from pathlib import Path

_repo_root = str(Path(__file__).resolve().parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

try:
    from core.hook_handler import main
except ImportError as exc:
    print(
        f"[preflight-hook] import error: {exc}. "
        f"Run: pip install -e . (from repo root)",
        file=sys.stderr,
    )
    sys.exit(0)

if __name__ == "__main__":
    sys.exit(main())
