from __future__ import annotations

import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from nukotech_agent_arc.package import verify_package
from nukotech_agent_arc.skill_import import SkillImportError, import_skill

ROOT = Path(__file__).resolve().parents[1]


def _skill(tmp_path: Path, name: str = "demo-skill", body: str = "Do one bounded thing.\n") -> Path:
    folder = tmp_path / "skills" / name
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: test\nmetadata:\n  version: 1.2.3\n---\n{body}", encoding="utf-8"
    )
    return folder


def test_import_skill_pins_exact_bytes(tmp_path: Path) -> None:
    folder = _skill(tmp_path)
    entry = import_skill(folder, registry_root=tmp_path, capabilities=("draft_content",))
    assert entry["id"] == "demo-skill"
    assert entry["version"] == "1.2.3"
    assert entry["path"] == "skills/demo-skill/SKILL.md"
    assert entry["sha256"] == hashlib.sha256((folder / "SKILL.md").read_bytes()).hexdigest()
    assert entry["capabilities"] == ["draft_content"]


def test_import_skill_refuses_missing_frontmatter(tmp_path: Path) -> None:
    folder = tmp_path / "bad"
    folder.mkdir()
    (folder / "SKILL.md").write_text("no frontmatter\n", encoding="utf-8")
    with pytest.raises(SkillImportError):
        import_skill(folder)


def test_import_skill_refuses_unsafe_name_and_type(tmp_path: Path) -> None:
    folder = _skill(tmp_path, name="Bad Name")
    with pytest.raises(SkillImportError):
        import_skill(folder)
    with pytest.raises(SkillImportError):
        import_skill(_skill(tmp_path, name="ok"), component_type="runtime")


def test_python_dash_m_entry_point_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "nukotech_agent_arc", "--help"], capture_output=True, text=True, cwd=ROOT, check=False
    )
    assert result.returncode == 0
    assert "import-skill" in result.stdout


def test_malformed_zip_compression_is_unreadable_not_crash(tmp_path: Path) -> None:
    package = tmp_path / "bad.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", b"x" * 4096)
    data = bytearray(package.read_bytes())
    start = data.find(b"a.txt") + len("a.txt")
    for index in range(start, start + 16):
        data[index] ^= 0xFF
    package.write_bytes(bytes(data))
    manifest = tmp_path / "bad.MANIFEST.sha256"
    manifest.write_text(f"{'0' * 64}  a.txt\n", encoding="utf-8")
    result = verify_package(package, manifest)
    assert not result.ok
