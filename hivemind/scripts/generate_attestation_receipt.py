#!/usr/bin/env python3
"""Generate a deterministic source/artifact binding receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = {
        "schema": "nukotech.hive.alpha.attested-build-receipt.v1",
        "artifact": {"name": args.artifact.name, "sha256": sha256(args.artifact)},
        "manifest": {"name": args.manifest.name, "sha256": sha256(args.manifest)},
        "policy": {"name": args.policy.name, "sha256": sha256(args.policy)},
        "sbom": {"name": args.sbom.name, "sha256": sha256(args.sbom)},
        "source": {"commit": args.source_head, "tree": args.source_tree},
        "status": "CANDIDATE_ATTESTATION_NOT_A_RELEASE",
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
