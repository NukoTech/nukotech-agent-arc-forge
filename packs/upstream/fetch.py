#!/usr/bin/env python3
"""Fetch pinned upstream packs at exact commits and apply overlays.

Usage: python packs/upstream/fetch.py [--dest packs/upstream/_checkout] [--mirror NAME=PATH ...]
--mirror lets CI or an offline machine use a local clone instead of the network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(*cmd: str, cwd: Path | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def apply_line_overlay(path: Path, target: Path) -> None:
    """Replace whole lines; each original is checked by SHA-256 so its text never lives in this repo."""
    spec = json.loads(path.read_text(encoding="utf-8"))
    for edit in spec["edits"]:
        file = target / edit["file"]
        lines = file.read_text(encoding="utf-8").split("\n")
        index = edit["line"] - 1
        actual = hashlib.sha256(lines[index].encode("utf-8")).hexdigest()
        if actual != edit["original_sha256"]:
            raise SystemExit(f"{path.name}: {edit['file']}:{edit['line']} does not match the pinned original")
        lines[index] = edit["replacement"]
        file.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=HERE / "_checkout")
    ap.add_argument("--mirror", action="append", default=[])
    args = ap.parse_args()
    mirrors = dict(m.split("=", 1) for m in args.mirror)
    lock = json.loads((HERE / "lock.json").read_text())
    args.dest.mkdir(parents=True, exist_ok=True)
    for pack in lock["packs"]:
        target = args.dest / pack["name"]
        if target.exists():
            shutil.rmtree(target)
        run("git", "clone", "--quiet", mirrors.get(pack["name"], pack["url"]), str(target))
        run("git", "-c", "advice.detachedHead=false", "checkout", "--quiet", pack["commit"], cwd=target)
        head = run("git", "rev-parse", "HEAD", cwd=target)
        if head != pack["commit"]:
            raise SystemExit(f"{pack['name']}: pinned {pack['commit']} but got {head}")
        for overlay in pack["overlays"]:
            if overlay.endswith(".json"):
                apply_line_overlay(HERE / overlay, target)
            else:
                run("git", "apply", "--whitespace=nowarn", str(HERE / overlay), cwd=target)
        print(f"PINNED {pack['name']} {head[:12]} overlays={len(pack['overlays'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
