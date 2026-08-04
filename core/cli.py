"""
Command-line interface for preflight-check-skill.

Usage:
    echo "secret stuff" | preflight-check
    preflight-check scan --file path/to/file.txt
    preflight-check scan --json
    preflight-check status
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from core.redactor import Redactor


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 1
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            print(f"Error: {path} is not a text file", file=sys.stderr)
            return 1
    else:
        text = sys.stdin.read()

    redactor = Redactor.from_default_catalog()

    if args.json:
        try:
            payload = json.loads(text)
            for key in ("prompt", "tool_input"):
                if key in payload and isinstance(payload[key], str):
                    result = redactor.redact(payload[key])
                    payload[key] = result.text
            sys.stdout.write(json.dumps(payload))
        except json.JSONDecodeError:
            print("Error: invalid JSON input", file=sys.stderr)
            return 1
    else:
        result = redactor.redact(text)
        sys.stdout.write(result.text)
        if result.findings:
            summary = ", ".join(f"{k}={v}" for k, v in result.summary().items())
            sys.stderr.write(
                f"[preflight-check] {len(result.findings)} finding(s): "
                f"{summary}\n"
            )

    return 0


def _cmd_hook(_args: argparse.Namespace) -> int:
    from core.hook_handler import main as hook_main
    return hook_main()


def _cmd_status(_args: argparse.Namespace) -> int:
    settings_path = Path.home() / ".claude" / "settings.json"
    config_path = Path.home() / ".claude" / "preflight.yaml"

    print("preflight-check-skill status")
    print("=" * 40)

    if config_path.exists():
        print(f"[ok] Config: {config_path}")
    else:
        print(f"[--] Config: not found ({config_path})")

    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            hooks = settings.get("hooks", {})
            registered = any(
                "preflight-check hook" in cmd or "claude_redact_hook" in cmd
                for event_hooks in hooks.values()
                for group in event_hooks
                if isinstance(group, dict)
                for h in group.get("hooks", [])
                if isinstance(h, dict)
                for cmd in [h.get("command", "")]
            )
            if registered:
                print(f"[ok] Hook: registered in {settings_path}")
            else:
                print(f"[--] Hook: not registered in {settings_path}")
        except Exception:
            print(f"[??] Hook: could not read {settings_path}")
    else:
        print(f"[--] Hook: settings file not found ({settings_path})")

    if shutil.which("gitleaks"):
        print("[ok] Gitleaks: available")
    else:
        print("[--] Gitleaks: not installed (regex-only mode)")

    skill_path = Path.home() / ".claude" / "skills" / "preflight-check" / "SKILL.md"
    if skill_path.exists():
        print(f"[ok] Skill: installed at {skill_path.parent}")
    else:
        print(f"[--] Skill: not installed ({skill_path.parent})")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="preflight-check",
        description="Detect and redact secrets/PII from text.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan and redact text")
    scan_parser.add_argument("--file", "-f", help="Read from file instead of stdin")
    scan_parser.add_argument(
        "--json", "-j", action="store_true", help="Parse input as JSON (hook mode)"
    )

    subparsers.add_parser("hook", help="Run as Claude Code hook (reads stdin)")
    subparsers.add_parser("status", help="Show installation status")

    args = parser.parse_args()

    if args.command == "hook":
        return _cmd_hook(args)
    elif args.command == "status":
        return _cmd_status(args)
    elif args.command == "scan":
        return _cmd_scan(args)
    else:
        # Default: scan from stdin (backwards-compatible)
        args.file = None
        args.json = False
        return _cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
