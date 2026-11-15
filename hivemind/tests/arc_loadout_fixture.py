"""Build the Arc loadout golden fixture at test time from plain source files.

The repository stores no binary archives. Each package is rebuilt
deterministically so its SHA-256 matches the pin recorded in PROVENANCE.md.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import zipfile

FIXTURE_ROOT = Path(__file__).with_name("fixtures") / "arc-loadout-0.3.0"
PACKAGE_SOURCES = "package-src"
PACKAGE_PINS = {
    "1.0.0": "ddf4e9cfd68f04b4cf18cf3c0fcb9920076da6db29f0f09c92adebf2974948b0",
    "1.0.1": "4e5ee8adff84fcbb567d33028d0fc9b6fd2dbb76a03a423b82a121f3b134e0a0",
}
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def build_package(members: Path, destination: Path) -> Path:
    """Write one reproducible Arc package ZIP from a directory of members."""
    files = sorted(path for path in members.rglob("*") if path.is_file())
    with zipfile.ZipFile(destination, "w") as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(members).as_posix(), _FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    return destination


def materialize(destination: Path) -> Path:
    """Copy the fixture without package sources and build every package ZIP."""
    shutil.copytree(FIXTURE_ROOT, destination, ignore=shutil.ignore_patterns(PACKAGE_SOURCES))
    for sources in sorted(FIXTURE_ROOT.rglob(PACKAGE_SOURCES)):
        relative = sources.parent.relative_to(FIXTURE_ROOT)
        for members in sorted(path for path in sources.iterdir() if path.is_dir()):
            build_package(members, destination / relative / f"{members.name}.zip")
    return destination
