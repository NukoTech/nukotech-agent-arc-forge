"""The fleet turn-note folder was renamed; old vaults must keep every note."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

import hive_protocol.turn as turn
from hive_protocol.core import ProtocolError
from hive_protocol.turn import FLEET_FOLDER, LEGACY_FLEET_FOLDER, _fleet_note_path


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _current_note(vault: Path, name: str) -> Path:
    return vault / FLEET_FOLDER / name


def test_neither_folder_returns_current_path(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    assert _fleet_note_path(fresh, "a.md") == _current_note(fresh, "a.md")
    assert not (fresh / FLEET_FOLDER).exists()
    assert not (fresh / LEGACY_FLEET_FOLDER).exists()


def test_missing_vault_root_returns_current_path_and_creates_nothing(tmp_path: Path) -> None:
    missing = tmp_path / "missing-root"
    path = _fleet_note_path(missing, "a.md")
    assert path == missing / FLEET_FOLDER / "a.md"
    assert not missing.exists()
    assert not (missing / FLEET_FOLDER).exists()
    assert not (missing / LEGACY_FLEET_FOLDER).exists()


def test_dangling_symlink_vault_root_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "missing-target"
    dangling = tmp_path / "dangling-root"
    dangling.symlink_to(target)
    with pytest.raises(ProtocolError, match="VAULT_FOLDER_UNSAFE"):
        _fleet_note_path(dangling, "a.md")
    assert dangling.is_symlink()
    assert not target.exists()
    assert not (dangling / FLEET_FOLDER).exists()


def test_missing_vault_under_existing_run_dir_matches_caller_shape(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    path = _fleet_note_path(run_dir / "vault", "turn.md")
    assert path == run_dir / "vault" / FLEET_FOLDER / "turn.md"
    assert run_dir.is_dir()
    assert not (run_dir / "vault").exists()
    assert list(run_dir.iterdir()) == []


def test_only_legacy_folder_is_renamed_atomically(tmp_path: Path) -> None:
    vault = tmp_path / "old"
    _write(vault / LEGACY_FLEET_FOLDER / "a.md", "alpha")
    _write(vault / LEGACY_FLEET_FOLDER / "nested" / "b.md", "beta")
    path = _fleet_note_path(vault, "a.md")
    assert path == _current_note(vault, "a.md")
    assert path.read_text(encoding="utf-8") == "alpha"
    assert (vault / FLEET_FOLDER / "nested" / "b.md").read_text(encoding="utf-8") == "beta"
    assert not (vault / LEGACY_FLEET_FOLDER).exists()


def test_only_current_folder_is_left_untouched(tmp_path: Path) -> None:
    vault = tmp_path / "current"
    _write(vault / FLEET_FOLDER / "a.md", "alpha")
    path = _fleet_note_path(vault, "a.md")
    assert path == _current_note(vault, "a.md")
    assert path.read_text(encoding="utf-8") == "alpha"
    assert not (vault / LEGACY_FLEET_FOLDER).exists()


def test_both_folders_are_refused_and_left_untouched(tmp_path: Path) -> None:
    vault = tmp_path / "both"
    _write(vault / FLEET_FOLDER / "new.md", "new")
    _write(vault / LEGACY_FLEET_FOLDER / "old.md", "old")
    _write(vault / LEGACY_FLEET_FOLDER / "same.md", "legacy copy")
    _write(vault / FLEET_FOLDER / "same.md", "current copy")
    with pytest.raises(ProtocolError, match="VAULT_FOLDER_CONFLICT"):
        _fleet_note_path(vault, "same.md")
    assert (vault / FLEET_FOLDER / "new.md").read_text(encoding="utf-8") == "new"
    assert (vault / FLEET_FOLDER / "same.md").read_text(encoding="utf-8") == "current copy"
    assert (vault / LEGACY_FLEET_FOLDER / "old.md").read_text(encoding="utf-8") == "old"
    assert (vault / LEGACY_FLEET_FOLDER / "same.md").read_text(encoding="utf-8") == "legacy copy"


def test_legacy_folder_symlink_is_refused(tmp_path: Path) -> None:
    vault = tmp_path / "linked-legacy"
    target = tmp_path / "elsewhere"
    _write(target / "a.md", "outside")
    vault.mkdir()
    (vault / LEGACY_FLEET_FOLDER).symlink_to(target, target_is_directory=True)
    with pytest.raises(ProtocolError, match="VAULT_FOLDER_UNSAFE"):
        _fleet_note_path(vault, "a.md")
    assert (target / "a.md").read_text(encoding="utf-8") == "outside"
    assert (vault / LEGACY_FLEET_FOLDER).is_symlink()
    assert not (vault / FLEET_FOLDER).exists()


def test_current_folder_symlink_is_refused(tmp_path: Path) -> None:
    vault = tmp_path / "linked-current"
    target = tmp_path / "elsewhere-current"
    _write(target / "a.md", "outside")
    _write(vault / LEGACY_FLEET_FOLDER / "b.md", "legacy")
    (vault / FLEET_FOLDER).symlink_to(target, target_is_directory=True)
    with pytest.raises(ProtocolError, match="VAULT_FOLDER_UNSAFE"):
        _fleet_note_path(vault, "a.md")
    assert (target / "a.md").read_text(encoding="utf-8") == "outside"
    assert (vault / LEGACY_FLEET_FOLDER / "b.md").read_text(encoding="utf-8") == "legacy"
    assert (vault / FLEET_FOLDER).is_symlink()


def test_vault_under_symlinked_parent_succeeds_when_root_is_owned(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    vault = real_parent / "vault"
    _write(vault / LEGACY_FLEET_FOLDER / "a.md", "alpha")
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    linked_vault = parent_link / "vault"
    path = _fleet_note_path(linked_vault, "a.md")
    assert path == linked_vault / FLEET_FOLDER / "a.md"
    assert path.read_text(encoding="utf-8") == "alpha"
    assert not (vault / LEGACY_FLEET_FOLDER).exists()

    real_root = tmp_path / "real-root"
    _write(real_root / LEGACY_FLEET_FOLDER / "b.md", "beta")
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    path = _fleet_note_path(linked_root, "b.md")
    assert path == linked_root / FLEET_FOLDER / "b.md"
    assert path.read_text(encoding="utf-8") == "beta"
    assert not (real_root / LEGACY_FLEET_FOLDER).exists()


def test_failed_rename_leaves_legacy_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "failed"
    _write(vault / LEGACY_FLEET_FOLDER / "a.md", "alpha")

    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(turn, "_rename_legacy_fleet", boom)
    with pytest.raises(ProtocolError, match="VAULT_FOLDER_UNSAFE"):
        _fleet_note_path(vault, "a.md")
    assert (vault / LEGACY_FLEET_FOLDER / "a.md").read_text(encoding="utf-8") == "alpha"
    assert not (vault / FLEET_FOLDER).exists()


def test_migration_is_idempotent_across_repeated_calls(tmp_path: Path) -> None:
    vault = tmp_path / "repeat"
    _write(vault / LEGACY_FLEET_FOLDER / "a.md", "alpha")
    first = _fleet_note_path(vault, "a.md")
    second = _fleet_note_path(vault, "a.md")
    third = _fleet_note_path(vault, "a.md")
    assert first == second == third == _current_note(vault, "a.md")
    assert first.read_text(encoding="utf-8") == "alpha"
    assert not (vault / LEGACY_FLEET_FOLDER).exists()


def test_read_only_path_is_not_migrated(tmp_path: Path) -> None:
    vault = tmp_path / "readonly"
    _write(vault / LEGACY_FLEET_FOLDER / "a.md", "alpha")
    vault.chmod(0o555)
    try:
        with pytest.raises(ProtocolError, match="VAULT_FOLDER_UNSAFE"):
            _fleet_note_path(vault, "a.md")
        assert (vault / LEGACY_FLEET_FOLDER / "a.md").read_text(encoding="utf-8") == "alpha"
        assert not (vault / FLEET_FOLDER).exists()
    finally:
        vault.chmod(0o755)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="renameat2 RENAME_NOREPLACE is Linux-only",
)
def test_linux_noreplace_refuses_existing_empty_destination(tmp_path: Path) -> None:
    if not turn._renameat2_available():
        pytest.skip("renameat2 RENAME_NOREPLACE is not available on this kernel")
    vault = tmp_path / "noreplace"
    _write(vault / LEGACY_FLEET_FOLDER / "a.md", "alpha")
    (vault / FLEET_FOLDER).mkdir()
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(vault, flags)
    try:
        with pytest.raises(ProtocolError, match="VAULT_FOLDER_CONFLICT"):
            turn._rename_legacy_fleet(fd)
    finally:
        os.close(fd)
    assert (vault / LEGACY_FLEET_FOLDER / "a.md").read_text(encoding="utf-8") == "alpha"
    assert (vault / FLEET_FOLDER).is_dir()
    assert list((vault / FLEET_FOLDER).iterdir()) == []
