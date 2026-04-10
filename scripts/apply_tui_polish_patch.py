#!/usr/bin/env python3
"""Apply the TUI polish patch used for phase timeline/activity enhancements.

Usage:
  python scripts/apply_tui_polish_patch.py --check
  python scripts/apply_tui_polish_patch.py --apply
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PATCH_PATH = REPO_ROOT / "scripts" / "tui_polish.patch"


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=REPO_ROOT, text=True, capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply/check the TUI polish patch")
    parser.add_argument("--apply", action="store_true", help="Apply patch")
    parser.add_argument("--check", action="store_true", help="Dry-run patch validation")
    args = parser.parse_args()

    if not PATCH_PATH.exists():
        print(f"Patch file not found: {PATCH_PATH}")
        return 1

    mode = "--apply" if args.apply else "--check" if args.check else "--check"
    git_apply_arg = "--check" if mode == "--check" else ""

    cmd = ["git", "apply"]
    if git_apply_arg:
        cmd.append(git_apply_arg)
    cmd.append(str(PATCH_PATH))

    result = run(cmd)
    if result.returncode == 0:
        verb = "validated" if mode == "--check" else "applied"
        print(f"TUI polish patch {verb} successfully: {PATCH_PATH}")
        return 0

    print(result.stdout.strip())
    print(result.stderr.strip())
    if mode == "--check":
        print("Patch check failed. The tree may already be patched or diverged from expected base.")
    else:
        print("Patch apply failed. Re-run with --check to inspect applicability.")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
