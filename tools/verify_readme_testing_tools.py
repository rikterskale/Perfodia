#!/usr/bin/env python3
"""Ensure README testing commands map to installed Python tooling requirements."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
REQ = ROOT / "requirements.txt"


def _extract_testing_commands(readme_text: str) -> list[str]:
    lines = readme_text.splitlines()
    in_testing = False
    in_block = False
    commands: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            in_testing = stripped.lower() == "## testing"
            in_block = False
            continue

        if not in_testing:
            continue

        if stripped.startswith("```"):
            in_block = not in_block
            continue

        if in_block and stripped:
            commands.append(stripped)

    return commands


def _req_packages(req_text: str) -> set[str]:
    pkgs: set[str] = set()
    for raw in req_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        base = re.split(r"[<>=!~]", line, maxsplit=1)[0].strip().lower()
        if base:
            pkgs.add(base)
    return pkgs


def main() -> int:
    readme_text = README.read_text(encoding="utf-8")
    req_text = REQ.read_text(encoding="utf-8")

    commands = _extract_testing_commands(readme_text)
    if not commands:
        print("[FAIL] No testing commands found in README.md")
        return 1

    command_tools = [cmd.split()[0] for cmd in commands if cmd.split()]

    required_packages = {
        "pytest": "pytest",
        "ruff": "ruff",
        "mypy": "mypy",
    }
    req_pkgs = _req_packages(req_text)

    missing: list[str] = []
    for tool in command_tools:
        pkg = required_packages.get(tool)
        if pkg and pkg not in req_pkgs:
            missing.append(f"{tool} (needs `{pkg}` in requirements.txt)")

    if missing:
        print("[FAIL] README testing tooling drift detected:")
        for item in missing:
            print(f"  - {item}")
        return 1

    print("[OK] README testing commands are represented in requirements.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
