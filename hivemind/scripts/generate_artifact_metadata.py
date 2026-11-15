#!/usr/bin/env python3
"""Generate a checksum manifest and CycloneDX SBOM for one alpha bundle tree."""

from __future__ import annotations

import email.parser
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5


LICENSES = {
    "attrs": "MIT",
    "cffi": "MIT",
    "cryptography": "Apache-2.0 OR BSD-3-Clause",
    "jsonschema": "MIT",
    "jsonschema-specifications": "MIT",
    "nukotech-hive-local": "MIT",
    "pycparser": "BSD-3-Clause",
    "PyYAML": "MIT",
    "referencing": "MIT",
    "rpds-py": "MIT",
    "typing-extensions": "PSF-2.0",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wheel_component(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise SystemExit(f"unexpected wheel metadata inventory: {path}")
        message = email.parser.BytesParser().parsebytes(archive.read(metadata_names[0]))
    name = str(message["Name"])
    version = str(message["Version"])
    license_expression = LICENSES.get(name, str(message.get("License-Expression") or "NOASSERTION"))
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{version}",
        "hashes": [{"alg": "SHA-256", "content": sha256(path)}],
        "licenses": [{"license": {"id": license_expression}}]
        if " OR " not in license_expression and license_expression != "NOASSERTION"
        else [{"expression": license_expression}],
    }


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_artifact_metadata.py BUNDLE_ROOT")
    root = Path(sys.argv[1]).resolve()
    wheels = sorted((root / "wheelhouse").glob("*.whl"))
    if not wheels:
        raise SystemExit("wheelhouse is empty")
    components = [wheel_component(path) for path in wheels]
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, ':'.join(str(item['purl']) for item in components))}",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "nukotech-hive-local", "version": "0.1.0"}},
        "components": components,
    }
    (root / "SBOM.cdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.sha256.json":
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    manifest = {
        "schema_version": "nukotech.hive-local.artifact-manifest.v1",
        "product": "NukoTech Hive Local Alpha",
        "version": "0.1.0",
        "files": files,
    }
    (root / "MANIFEST.sha256.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
