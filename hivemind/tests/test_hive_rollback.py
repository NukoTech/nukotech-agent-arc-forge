from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, unsigned_document
from hive_protocol.product.integrity import (
    UnsignedCheckpointWarning,
    checkpoint_path,
    sign_integrity_document,
    write_signed_checkpoint,
)
from hive_protocol.product.workspace import HiveWorkspace


def _seeded(tmp_path: Path) -> HiveWorkspace:
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.md").write_bytes(b"# Note\n\nFrozen parent.\n")
    workspace = HiveWorkspace.create(tmp_path / "hive")
    workspace.import_content(source)
    return workspace


def test_signed_snapshot_rollback_restores_without_flag(tmp_path: Path) -> None:
    workspace = _seeded(tmp_path)
    checkpoint = workspace.snapshot("parent")["commit"]
    assert checkpoint_path(workspace.root, checkpoint).is_file()
    target = next(workspace.sources.rglob("*.md"))
    before = target.read_bytes()
    target.write_bytes(before + b"\nmutation\n")
    result = workspace.rollback(checkpoint)
    assert result["target"] == checkpoint
    assert target.read_bytes() == before


def test_unsigned_checkpoint_rollback_is_refused(tmp_path: Path) -> None:
    workspace = _seeded(tmp_path)
    workspace.snapshot("signed parent")
    extra = workspace.sources / "extra.md"
    extra.write_text("unsigned ancestor\n", encoding="utf-8")
    workspace._git("add", "sources/extra.md")
    workspace._git("commit", "-m", "raw unsigned commit")
    unsigned = workspace._git("rev-parse", "HEAD").stdout.strip()
    later = workspace.sources / "later.md"
    later.write_text("after the unsigned ancestor\n", encoding="utf-8")
    workspace._git("add", "sources/later.md")
    workspace._git("commit", "-m", "later state")

    with pytest.raises(ProtocolError, match="CHECKPOINT_REQUIRED"):
        workspace.rollback(unsigned)
    assert later.is_file()

    with pytest.warns(UnsignedCheckpointWarning, match="unsigned or legacy"):
        workspace.rollback(unsigned, allow_unsigned=True)
    assert extra.is_file()
    assert not later.exists()


def test_forged_checkpoint_rollback_is_refused_even_with_flag(tmp_path: Path) -> None:
    workspace = _seeded(tmp_path)
    commit = workspace.snapshot("parent")["commit"]
    path = checkpoint_path(workspace.root, commit)
    document = json.loads(path.read_text(encoding="utf-8"))
    forged = dict(document)
    forged["signature"] = dict(document["signature"])
    forged["signature"]["value"] = "A" * len(document["signature"]["value"])
    path.write_text(json.dumps(forged, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ProtocolError, match="CHECKPOINT_SIGNATURE_INVALID|SIGNATURE_INVALID"):
        workspace.rollback(commit)
    with pytest.raises(ProtocolError, match="CHECKPOINT_SIGNATURE_INVALID|SIGNATURE_INVALID"):
        workspace.rollback(commit, allow_unsigned=True)


def test_wrong_key_checkpoint_is_refused(tmp_path: Path) -> None:
    workspace = _seeded(tmp_path)
    commit = workspace.snapshot("parent")["commit"]
    path = checkpoint_path(workspace.root, commit)
    original = json.loads(path.read_text(encoding="utf-8"))
    attacker = Ed25519PrivateKey.generate()
    resigned = sign_integrity_document(unsigned_document(original), attacker)
    write_signed_checkpoint(workspace.root, resigned)

    with pytest.raises(ProtocolError, match="CHECKPOINT_SIGNATURE_INVALID|UNKNOWN_SIGNING_KEY"):
        workspace.rollback(commit)


def test_symlink_preflight_still_runs_before_unsigned_checkpoint_rule(
    tmp_path: Path,
) -> None:
    """A malicious ancestor is still refused for its symlink tree first."""

    workspace = _seeded(tmp_path)
    tracked = workspace.sources / "tracked.md"
    tracked.write_text("safe parent", encoding="utf-8")
    workspace.snapshot("safe parent")

    external = tmp_path / "external-target.txt"
    external.write_text("preserve", encoding="utf-8")
    tracked.unlink()
    tracked.symlink_to(external)
    workspace._git("add", "sources/tracked.md")
    workspace._git("commit", "-m", "malicious symlink fixture")
    unsafe = workspace._git("rev-parse", "HEAD").stdout.strip()

    tracked.unlink()
    tracked.write_text("safe current", encoding="utf-8")
    workspace._git("add", "sources/tracked.md")
    workspace._git("commit", "-m", "safe current fixture")

    with pytest.raises(ProtocolError, match="ROLLBACK_PATH_DENIED"):
        workspace.rollback(unsafe)
    assert tracked.read_text(encoding="utf-8") == "safe current"
    assert external.read_text(encoding="utf-8") == "preserve"
