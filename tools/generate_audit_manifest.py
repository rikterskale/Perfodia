#!/usr/bin/env python3
"""Generate a machine-readable audit manifest for all tracked repository files."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "AUDIT_MANIFEST.json"


def _git_tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _line_count(path: Path) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def build_manifest(output_path: Path) -> dict:
    output_rel = output_path.resolve().relative_to(ROOT).as_posix()
    files = []
    for rel in _git_tracked_files():
        if rel == output_rel:
            continue
        abs_path = ROOT / rel
        files.append(
            {
                "path": rel,
                "size_bytes": abs_path.stat().st_size,
                "line_count": _line_count(abs_path),
                "sha256": _sha256(abs_path),
                "status": "pending_review",
            }
        )

    return {
        "schema_version": 1,
        "generated_by": "tools/generate_audit_manifest.py",
        "file_count": len(files),
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if current manifest differs from generated content.",
    )
    args = parser.parse_args()

    manifest = build_manifest(args.output)
    rendered = json.dumps(manifest, indent=2, sort_keys=False) + "\n"

    if args.check:
        if not args.output.exists():
            print(f"[FAIL] Missing manifest file: {args.output}")
            return 1
        existing = args.output.read_text(encoding="utf-8")
        if existing != rendered:
            print("[FAIL] AUDIT_MANIFEST.json is stale. Regenerate with:")
            print("  python3 tools/generate_audit_manifest.py")
            return 1
        print("[OK] AUDIT_MANIFEST.json is up to date.")
        return 0

    args.output.write_text(rendered, encoding="utf-8")
    print(f"[OK] Wrote {args.output} ({manifest['file_count']} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
