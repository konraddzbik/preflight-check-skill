"""Allow running as `python3 -m core` when the CLI entry point is not on PATH."""

from core.cli import main

raise SystemExit(main())
