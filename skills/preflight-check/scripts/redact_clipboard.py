#!/usr/bin/env python3
"""Redact secrets and PII from the system clipboard using the preflight-check CLI."""

from __future__ import annotations

import platform
import subprocess
import sys


def _read_clipboard() -> str:
    system = platform.system()
    if system == "Darwin":
        return subprocess.run(
            ["pbpaste"], capture_output=True, text=True, check=True
        ).stdout
    elif system == "Linux":
        clipboard_cmds = (
            ["xclip", "-selection", "clipboard", "-o"],
            ["xsel", "--clipboard", "--output"],
        )
        for cmd in clipboard_cmds:
            try:
                return subprocess.run(
                    cmd, capture_output=True, text=True, check=True
                ).stdout
            except FileNotFoundError:
                continue
        raise RuntimeError("Install xclip or xsel for clipboard access on Linux")
    elif system == "Windows":
        return subprocess.run(
            ["powershell", "-command", "Get-Clipboard"],
            capture_output=True, text=True, check=True,
        ).stdout
    raise RuntimeError(f"Unsupported platform: {system}")


def _write_clipboard(text: str) -> None:
    system = platform.system()
    if system == "Darwin":
        subprocess.run(["pbcopy"], input=text, text=True, check=True)
    elif system == "Linux":
        clipboard_cmds = (
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        )
        for cmd in clipboard_cmds:
            try:
                subprocess.run(cmd, input=text, text=True, check=True)
                return
            except FileNotFoundError:
                continue
        raise RuntimeError("Install xclip or xsel for clipboard access on Linux")
    elif system == "Windows":
        subprocess.run(
            ["powershell", "-command", "Set-Clipboard", "-Value", text],
            text=True, check=True,
        )
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def main() -> int:
    try:
        text = _read_clipboard()
    except Exception as e:
        print(f"Error reading clipboard: {e}", file=sys.stderr)
        return 1

    if not text.strip():
        print("Clipboard is empty.", file=sys.stderr)
        return 1

    result = subprocess.run(
        ["preflight-check", "scan"],
        input=text,
        capture_output=True,
        text=True,
    )

    try:
        _write_clipboard(result.stdout)
    except Exception as e:
        print(f"Error writing to clipboard: {e}", file=sys.stderr)
        return 1

    if result.stderr:
        print(result.stderr, end="")
    else:
        print("No secrets or PII found in clipboard.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
