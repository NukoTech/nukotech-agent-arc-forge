#!/usr/bin/env python3
"""Fail closed on alpha artifact inventory, hashes, SBOM, and architecture."""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def refuse(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_alpha_artifact.py ARTIFACT EXPECTED_ARCH")
    artifact = Path(sys.argv[1]).resolve()
    architecture = sys.argv[2]
    expected_root = f"nukotech-hive-local-alpha-v0.1.0-linux-{architecture}"
    with tempfile.TemporaryDirectory(prefix="nukotech-hive-artifact-verify.") as temporary:
        extraction_root = Path(temporary)
        with tarfile.open(artifact, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not path.parts:
                    refuse(f"unsafe archive member: {member.name}")
                if path.parts[0] != expected_root or member.issym() or member.islnk():
                    refuse(f"unexpected archive boundary or link: {member.name}")
                if not (member.isfile() or member.isdir()):
                    refuse(f"unsupported archive member type: {member.name}")
            archive.extractall(extraction_root, filter="data")
        bundle = extraction_root / expected_root
        manifest_path = bundle / "MANIFEST.sha256.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != "nukotech.hive-local.artifact-manifest.v1":
            refuse("manifest schema is invalid")
        entries = manifest.get("files")
        if not isinstance(entries, list) or not entries:
            refuse("manifest file inventory is invalid")
        expected_files = {"MANIFEST.sha256.json"}
        for entry in entries:
            relative = PurePosixPath(str(entry.get("path", "")))
            if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != entry.get("path"):
                refuse(f"unsafe manifest path: {relative}")
            if relative.as_posix() in expected_files:
                refuse(f"duplicate manifest path: {relative}")
            expected_files.add(relative.as_posix())
            path = bundle.joinpath(*relative.parts)
            if not path.is_file() or path.is_symlink():
                refuse(f"manifest file is missing or unsafe: {relative}")
            if path.stat().st_size != entry.get("size_bytes") or sha256(path) != entry.get("sha256"):
                refuse(f"manifest mismatch: {relative}")
        actual_files = {
            path.relative_to(bundle).as_posix()
            for path in bundle.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        if actual_files != expected_files:
            refuse("archive and manifest inventories differ")
        for required in (
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "SBOM.cdx.json",
            "verify/m4-installed-shell-e2e.py",
        ):
            if required not in actual_files:
                refuse(f"required artifact file missing: {required}")
        sbom = json.loads((bundle / "SBOM.cdx.json").read_text(encoding="utf-8"))
        components = sbom.get("components")
        if sbom.get("bomFormat") != "CycloneDX" or not isinstance(components, list):
            refuse("CycloneDX SBOM is invalid")
        wheels = sorted((bundle / "wheelhouse").glob("*.whl"))
        if len(wheels) != len(components):
            refuse("SBOM and wheelhouse component counts differ")
        compiled = [path.name for path in wheels if "-none-any.whl" not in path.name]
        if not compiled or any(architecture not in name for name in compiled):
            refuse("compiled wheel architecture does not match artifact")
        foreign = "aarch64" if architecture == "x86_64" else "x86_64"
        if any(foreign in path.name for path in wheels):
            refuse("foreign-architecture wheel found")
        result = {
            "outcome": "VERIFIED",
            "artifact": artifact.name,
            "artifact_sha256": sha256(artifact),
            "architecture": architecture,
            "manifest_entries": len(entries),
            "sbom_components": len(components),
            "compiled_wheels": compiled,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
