#!/usr/bin/env python3
"""Redact secrets and PII from a file using the preflight-check CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: redact_file.py <file_path>", file=sys.stderr)
        return 1

    source = Path(sys.argv[1])
    if not source.exists():
        print(f"Error: file not found: {source}", file=sys.stderr)
        return 1

    result = subprocess.run(
        ["preflight-check", "scan", "--file", str(source)],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(result.stderr, file=sys.stderr, end="")
        return result.returncode

    out_name = f"{source.stem}.redacted{source.suffix}"
    out_path = source.parent / out_name
    if out_path.exists():
        print(f"Error: output already exists: {out_path}", file=sys.stderr)
        return 1

    out_path.write_text(result.stdout, encoding="utf-8")

    if result.stderr:
        print(result.stderr, end="")
    print(f"Output: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
