#!/usr/bin/env python3
"""Verify byte-for-byte product payload parity with immutable alpha.1."""

from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path


EXPECTED_ENTRY_COUNT = 38
EXPECTED_PAYLOAD_SHA256 = "13364247845de7ffc47fc594bf6dfa8831ee476104991e93303ca677a23e0ee3"


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_alpha1_wheel_parity.py PRODUCT_WHEEL")
    wheel = Path(sys.argv[1]).resolve()
    digest = hashlib.sha256()
    with zipfile.ZipFile(wheel) as archive:
        names = sorted(name for name in archive.namelist() if not name.endswith("/"))
        if len(names) != EXPECTED_ENTRY_COUNT or len(names) != len(set(names)):
            raise SystemExit("product wheel inventory differs from immutable alpha.1")
        for name in names:
            digest.update(name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(archive.read(name))
            digest.update(b"\0")
    actual = digest.hexdigest()
    if actual != EXPECTED_PAYLOAD_SHA256:
        raise SystemExit(
            "product payload differs from immutable alpha.1: "
            f"expected={EXPECTED_PAYLOAD_SHA256} actual={actual}"
        )
    print(f"PASS: alpha.1 product payload parity sha256={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
