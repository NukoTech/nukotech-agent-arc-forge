"""Uninstall must preserve bytes across real local writers and interrupted moves."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from hive_protocol.core import ProtocolError, document_digest, sign_document, verify_document
from hive_protocol.storage import atomic_write_json
from hive_protocol.loadouts import manager as module


@pytest.fixture
def installed(tmp_path):
    vault = tmp_path.resolve()
    target = dict(persona_id="persona:test", surface_id="surface:test", machine_id="machine:test",
                  project_id="project:test", os="macos" if sys.platform == "darwin" else "linux",
                  architecture="arm64" if sys.platform == "darwin" else "x86_64", runtime="python3.12")
    identity = {key: target[key] for key in ("persona_id", "surface_id", "machine_id", "project_id")}
    identity["app_actor"] = "app:test"
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    manager = module.LoadoutManager(vault, target=target, registry=None, request_key=keys[0],
        approver_key=keys[1], state_key=keys[2], approver_identity=identity)
    content = b"attended admitted original\n"
    pin = hashlib.sha256(b"test-version").hexdigest()
    root = manager.root / "objects" / pin
    root.mkdir(mode=0o700)
    (root / "owned.txt").write_bytes(content)
    (root / "other.txt").write_bytes(b"second retained bytes")
    version = {"manifest": {}, "files": {"owned.txt": hashlib.sha256(content).hexdigest(),
        "other.txt": hashlib.sha256(b"second retained bytes").hexdigest()}}
    state = manager._read_state()
    state["records"]["test"] = {"active": pin, "versions": {pin: version}, "history": [pin], "revoked": []}
    manager._write_state(state)
    plan = manager.plan("uninstall", "test", authorization_ref="attended-test")
    approval = manager.approve(plan)
    destination = manager.root / "recovery" / document_digest(plan) / pin
    return manager, plan, approval, root, destination, content


class ConcurrentWriter:
    """Use a separate process; synchronise only the otherwise nondeterministic window."""
    def __init__(self, path, mode):
        trigger_read, self.trigger = os.pipe()
        self.reply, reply_write = os.pipe()
        program = """
import os,sys
from pathlib import Path
p=Path(sys.argv[1]);mode=sys.argv[2];r=int(sys.argv[3]);w=int(sys.argv[4])
fd=os.open(p,os.O_WRONLY) if mode=='openwrite' else None
os.write(w,b'R');os.read(r,1)
payload=b'concurrent user bytes must survive\\n'
if fd is not None:
 os.ftruncate(fd,0);os.write(fd,payload);os.fsync(fd);os.close(fd)
else:
 t=p.with_name('replacement.tmp');t.write_bytes(payload);os.replace(t,p)
os.write(w,b'D')
"""
        self.process = subprocess.Popen([sys.executable, "-I", "-c", program, str(path), mode,
            str(trigger_read), str(reply_write)], pass_fds=(trigger_read, reply_write))
        os.close(trigger_read); os.close(reply_write)
        self.receive(b"R")

    def receive(self, expected):
        assert select.select([self.reply], [], [], 10)[0], "writer did not reach bounded checkpoint"
        assert os.read(self.reply, 1) == expected

    def change(self):
        os.write(self.trigger, b"1")
        self.receive(b"D")

    def close(self):
        os.close(self.trigger); os.close(self.reply)
        try:
            assert self.process.wait(timeout=10) == 0
        finally:
            if self.process.poll() is None:
                self.process.kill(); self.process.wait()


def test_uninstall_retains_signed_recovery_and_replays_without_writes(installed):
    manager, plan, approval, root, destination, content = installed
    receipt = manager.apply(plan, approval)
    assert not root.exists() and (destination / "owned.txt").read_bytes() == content
    assert receipt["content_purged"] is False
    assert receipt["retained_recovery"] == [{"version_digest": root.name,
        "path": destination.relative_to(manager.vault).as_posix(), "disposition": "RETAINED_NOT_PURGED"}]
    verify_document(receipt, manager._state_keys)
    before = {p.relative_to(manager.vault): p.read_bytes() for p in manager.vault.rglob("*") if p.is_file()}
    assert manager.apply(plan, approval) == receipt
    assert manager.status()[0]["status"] == "UNINSTALLED"
    assert before == {p.relative_to(manager.vault): p.read_bytes() for p in manager.vault.rglob("*") if p.is_file()}


def test_separate_process_replacement_after_verification_is_preserved(installed, monkeypatch):
    manager, plan, approval, root, destination, _ = installed
    writer = ConcurrentWriter(root / "owned.txt", "replace")
    move = module._rename_preserving_destination
    def interleave(*args):
        writer.change()
        return move(*args)
    monkeypatch.setattr(module, "_rename_preserving_destination", interleave)
    try:
        with pytest.raises(ProtocolError, match="LOADOUT_OWNED_CONTENT_CHANGED"):
            manager.apply(plan, approval)
    finally:
        writer.close()
    assert (destination / "owned.txt").read_bytes() == b"concurrent user bytes must survive\n"
    assert document_digest(plan) not in manager._read_state()["completed"]


def test_already_open_writer_after_final_check_survives_success(installed, monkeypatch):
    manager, plan, approval, root, destination, _ = installed
    writer = ConcurrentWriter(root / "owned.txt", "openwrite")
    verify = module._verify_directory_content
    calls = 0
    def interleave(*args, **kwargs):
        nonlocal calls
        verify(*args, **kwargs)
        calls += 1
        if calls == 3:  # prepared, pre-move, then final captured-directory readback
            writer.change()
    monkeypatch.setattr(module, "_verify_directory_content", interleave)
    try:
        receipt = manager.apply(plan, approval)
    finally:
        writer.close()
    assert calls == 3 and receipt["outcome"] == "APPLIED" and receipt["content_purged"] is False
    assert (destination / "owned.txt").read_bytes() == b"concurrent user bytes must survive\n"


@pytest.mark.parametrize("substitution", ["directory", "symlink"])
def test_root_substitution_at_move_is_retained_and_refused(installed, monkeypatch, substitution):
    manager, plan, approval, root, destination, content = installed
    saved = root.with_name("original-preserved")
    outside = manager.vault / "unrelated"
    outside.mkdir(); (outside / "important.txt").write_bytes(b"outside must survive")
    move = module._rename_preserving_destination
    def interleave(*args):
        root.rename(saved)
        if substitution == "symlink":
            root.symlink_to(outside, target_is_directory=True)
        else:
            root.mkdir(); (root / "important.txt").write_bytes(b"replacement must survive")
        return move(*args)
    monkeypatch.setattr(module, "_rename_preserving_destination", interleave)
    with pytest.raises(ProtocolError, match="LOADOUT_OWNED_CONTENT_CHANGED"):
        manager.apply(plan, approval)
    assert (saved / "owned.txt").read_bytes() == content
    assert (outside / "important.txt").read_bytes() == b"outside must survive"
    if substitution == "symlink":
        assert destination.is_symlink() and destination.readlink() == outside
    else:
        assert (destination / "important.txt").read_bytes() == b"replacement must survive"


def test_atomic_no_clobber_preserves_racing_empty_destination(installed, monkeypatch):
    manager, plan, approval, root, destination, content = installed
    move = module._rename_preserving_destination
    identity = []
    def interleave(*args):
        destination.mkdir(); identity.append(destination.stat().st_ino)
        return move(*args)
    monkeypatch.setattr(module, "_rename_preserving_destination", interleave)
    with pytest.raises(ProtocolError, match="LOADOUT_RECOVERY_COLLISION"):
        manager.apply(plan, approval)
    assert destination.stat().st_ino == identity[0]
    assert (root / "owned.txt").read_bytes() == content


def test_new_original_path_is_never_overwritten_on_failure(installed, monkeypatch):
    manager, plan, approval, root, destination, content = installed
    move = module._rename_preserving_destination
    def interleave(*args):
        move(*args)
        root.mkdir(); (root / "replacement.txt").write_bytes(b"new occupant")
    monkeypatch.setattr(module, "_rename_preserving_destination", interleave)
    with pytest.raises(ProtocolError, match="LOADOUT_RECOVERY_COLLISION"):
        manager.apply(plan, approval)
    assert (destination / "owned.txt").read_bytes() == content
    assert (root / "replacement.txt").read_bytes() == b"new occupant"


@pytest.mark.parametrize("boundary", ["before_move", "after_move", "state_commit"])
def test_exact_signed_replay_recovers_each_interruption(installed, monkeypatch, boundary):
    manager, plan, approval, root, destination, content = installed
    move, write = module._rename_preserving_destination, manager._write_state
    class Interrupted(RuntimeError): pass
    def interleave(*args):
        if boundary == "before_move": raise Interrupted("before move")
        move(*args)
        raise Interrupted("after move")
    if boundary == "state_commit":
        monkeypatch.setattr(manager, "_write_state", lambda _: (_ for _ in ()).throw(Interrupted("state")))
    else:
        monkeypatch.setattr(module, "_rename_preserving_destination", interleave)
    with pytest.raises(Interrupted): manager.apply(plan, approval)
    monkeypatch.setattr(module, "_rename_preserving_destination", move)
    monkeypatch.setattr(manager, "_write_state", write)
    receipt = manager.apply(plan, approval)
    assert receipt["outcome"] == "APPLIED" and not root.exists()
    assert (destination / "owned.txt").read_bytes() == content


def test_fresh_approval_after_expiry_keeps_original_signed_destination(installed, monkeypatch):
    manager, plan, approval, root, destination, content = installed
    write = manager._write_state
    monkeypatch.setattr(manager, "_write_state", lambda _: (_ for _ in ()).throw(RuntimeError("interrupted")))
    with pytest.raises(RuntimeError): manager.apply(plan, approval)
    monkeypatch.setattr(manager, "_write_state", write)
    moment = datetime.fromisoformat(plan["expires_at"]) + timedelta(seconds=1)
    monkeypatch.setattr(module, "_now", lambda: moment)
    with pytest.raises(ProtocolError, match="LOADOUT_EXPIRED"): manager.apply(plan, approval)
    renewed = manager.plan("uninstall", "test", authorization_ref="fresh-attended-test")
    receipt = manager.apply(renewed, manager.approve(renewed))
    assert (destination / "owned.txt").read_bytes() == content
    assert receipt["retained_recovery"][0]["path"] == destination.relative_to(manager.vault).as_posix()


@pytest.mark.parametrize("resign", [False, True])
def test_tampered_removal_journal_cannot_adopt_another_root(installed, monkeypatch, resign):
    manager, plan, approval, root, destination, content = installed
    move = module._rename_preserving_destination
    monkeypatch.setattr(module, "_rename_preserving_destination", lambda *args: (_ for _ in ()).throw(RuntimeError("interrupted")))
    with pytest.raises(RuntimeError): manager.apply(plan, approval)
    path = manager.root / "journals" / (document_digest(plan) + ".json")
    value = json.loads(path.read_text()); value["removals"]["origin_plan_digest"] = "b" * 64
    if resign:
        value = sign_document(value, manager.state_key)
    path.write_text(json.dumps(value))
    monkeypatch.setattr(module, "_rename_preserving_destination", move)
    with pytest.raises(ProtocolError): manager.apply(plan, approval)
    assert (root / "owned.txt").read_bytes() == content and not destination.exists()


def test_legacy_signed_partial_removal_retains_remaining_bytes(installed):
    manager, plan, approval, root, destination, _ = installed
    # Simulate a pre-fix signed PREPARED operation which removed one expected file.
    (root / "owned.txt").unlink()
    journal = sign_document({"schema_version": "hive.loadout-journal.v1", "plan": plan,
        "approval": approval, "phase": "PREPARED", "recovery_from": None}, manager.state_key)
    atomic_write_json(manager.root / "journals" / (document_digest(plan) + ".json"), journal)
    receipt = manager.apply(plan, approval)
    assert receipt["outcome"] == "APPLIED" and receipt["content_purged"] is False
    assert destination.is_dir() and not root.exists()
    assert (destination / "other.txt").read_bytes() == b"second retained bytes"


def test_unsigned_missing_file_is_never_treated_as_partial_recovery(installed):
    manager, plan, approval, root, destination, _ = installed
    (root / "owned.txt").unlink()
    with pytest.raises(ProtocolError, match="LOADOUT_OWNED_CONTENT_CHANGED"):
        manager.apply(plan, approval)
    assert root.is_dir() and not destination.exists()


def test_approval_expiring_during_content_read_cannot_move(installed, monkeypatch):
    manager, plan, approval, root, destination, content = installed
    verify = module._verify_directory_content
    calls = 0
    def interleave(*args, **kwargs):
        nonlocal calls
        verify(*args, **kwargs)
        calls += 1
        if calls == 2:
            moment = datetime.fromisoformat(plan["expires_at"]) + timedelta(seconds=1)
            monkeypatch.setattr(module, "_now", lambda: moment)
    monkeypatch.setattr(module, "_verify_directory_content", interleave)
    with pytest.raises(ProtocolError, match="LOADOUT_EXPIRED"):
        manager.apply(plan, approval)
    assert not destination.exists() and (root / "owned.txt").read_bytes() == content


@pytest.mark.parametrize("component", ["objects", "recovery"])
def test_symlinked_parent_never_moves_or_overwrites_outside_content(installed, component):
    manager, plan, approval, root, destination, content = installed
    outside = manager.vault / "outside"
    outside.mkdir(); sentinel = outside / "sentinel.txt"; sentinel.write_bytes(b"outside user content")
    parent = manager.root / component
    saved = None
    if parent.exists():
        saved = parent.with_name(component + "-preserved"); parent.rename(saved)
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises((ProtocolError, OSError)):
        manager.apply(plan, approval)
    assert sentinel.read_bytes() == b"outside user content"
    assert list(outside.iterdir()) == [sentinel]
    preserved = saved / root.name if saved else root
    assert (preserved / "owned.txt").read_bytes() == content
