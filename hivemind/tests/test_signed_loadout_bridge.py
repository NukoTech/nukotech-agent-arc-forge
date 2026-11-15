"""Real Arc artifact admission plus adversarial target and lifecycle boundaries."""

import copy
from datetime import timedelta
import hashlib
import io
import json
from pathlib import Path
import stat
import zipfile

import pytest

from hive_protocol.core import ProtocolError, document_digest, sign_document, verify_document
from hive_protocol.loadouts.artifacts import inspect_arc_package
from hive_protocol.loadouts import manager as manager_module
from hive_protocol.product.loadout_adapter import loadout_services
from hive_protocol.product import loadout_adapter
from hive_protocol.product.workspace import HiveWorkspace

from arc_loadout_fixture import PACKAGE_PINS, materialize


def source_files(directory: Path, version="1.0.0"):
    return {"package": directory / f"marketing-operator-{version}.zip",
        "checksum_manifest": directory / f"marketing-operator-{version}.MANIFEST.sha256",
        "recipe": directory / "recipe.yaml", "registry": directory / "registry.yaml",
        "authorization": directory / "authorization.yaml"}


@pytest.fixture
def source(tmp_path):
    directory = tmp_path.resolve() / "arc"
    materialize(directory)
    return source_files(directory)


@pytest.fixture
def manager(tmp_path):
    root = tmp_path.resolve() / "Hive"
    HiveWorkspace.create(root)
    return loadout_services(root)


def admit(manager, source, loadout_id="drafting"):
    plan = manager.plan("admit", loadout_id, authorization_ref="synthetic-attended-review", source=source)
    approval = manager.approve(plan)
    return manager.apply(plan, approval, source=source)


def rewrite_zip(source, modify):
    with zipfile.ZipFile(source["package"]) as archive:
        entries = {entry.filename: (entry, archive.read(entry)) for entry in archive.infolist()}
    modify(entries)
    with zipfile.ZipFile(source["package"], "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, (info, payload) in entries.items():
            info.filename = name
            archive.writestr(info, payload)
    source["checksum_manifest"].write_text("".join(
        f"{hashlib.sha256(payload).hexdigest()}  {name}\n" for name, (_, payload) in sorted(entries.items())))


def test_real_arc_composition_artifact_and_inputs_are_exact(source):
    result = inspect_arc_package(**source)
    assert result.manifest["artifact_pins"]["package_sha256"] == PACKAGE_PINS["1.0.0"]
    assert result.manifest["components"][0]["dependencies"] == []
    assert result.manifest["grants_authority"] is False


def test_generated_fixture_packages_are_reproducible(source):
    upgrade = source["package"].parent / "upgrade" / "marketing-operator-1.0.1.zip"
    assert hashlib.sha256(source["package"].read_bytes()).hexdigest() == PACKAGE_PINS["1.0.0"]
    assert hashlib.sha256(upgrade.read_bytes()).hexdigest() == PACKAGE_PINS["1.0.1"]
    assert not list(source["package"].parent.rglob("package-src"))


def test_admission_requires_distinct_plan_and_approval_then_survives_reopen(manager, source):
    plan = manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source)
    assert manager.status() == []
    assert not list((manager.root / "objects").iterdir())
    with pytest.raises(ProtocolError):
        manager.apply(plan, {}, source=source)
    receipt = manager.apply(plan, manager.approve(plan), source=source)
    verify_document(receipt, manager._state_keys)
    reopened = loadout_services(manager.vault)
    assert reopened.status()[0]["status"] == "ACTIVE"
    assert "draft" in reopened.read_active("drafting")["components/draft-skill.txt"].lower()
    assert receipt["grants_authority"] is False


@pytest.mark.parametrize("field,value", [("project_id", "other-project"), ("machine_id", "other-machine"),
    ("surface_id", "other-surface"), ("persona_id", "other-persona"),
    ("os", "linux"), ("architecture", "x86_64"), ("runtime", "unapproved-runtime")])
def test_exact_target_mismatch_is_refused_even_with_valid_signature(manager, source, field, value):
    plan = manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source)
    if field == "os":
        value = "macos" if plan["target"][field] == "linux" else "linux"
    elif field == "architecture":
        value = "arm64" if plan["target"][field] == "x86_64" else "x86_64"
    plan["target"][field] = value
    plan = sign_document(plan, manager.request_key)
    with pytest.raises(ProtocolError, match="LOADOUT_TARGET_MISMATCH"):
        manager.approve(plan)
    assert manager.status() == []


def test_approval_is_bound_to_exact_plan(manager, source):
    one = manager.plan("admit", "one", authorization_ref="attended-fixture", source=source)
    two = manager.plan("admit", "two", authorization_ref="attended-fixture", source=source)
    with pytest.raises(ProtocolError, match="LOADOUT_APPROVAL_INVALID"):
        manager.apply(two, manager.approve(one), source=source)


def test_changed_source_after_approval_has_no_active_effect(manager, source):
    plan = manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source)
    approval = manager.approve(plan)
    source["recipe"].write_bytes(source["recipe"].read_bytes() + b"\n# changed after approval\n")
    with pytest.raises(ProtocolError, match="LOADOUT_ARTIFACT_CHANGED"):
        manager.apply(plan, approval, source=source)
    assert manager.status() == []


def test_stale_state_plan_cannot_replace_another_commit(manager, source):
    plan = manager.plan("admit", "later", authorization_ref="attended-fixture", source=source)
    approval = manager.approve(plan)
    admit(manager, source, "first")
    with pytest.raises(ProtocolError, match="LOADOUT_STATE_CHANGED"):
        manager.apply(plan, approval, source=source)


def test_committed_replay_after_expiry_returns_same_signed_receipt(manager, source, monkeypatch):
    plan = manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source)
    approval = manager.approve(plan)
    result = manager.apply(plan, approval, source=source)
    state = (manager.root / "state.json").read_bytes()
    now = manager_module._now()
    monkeypatch.setattr(manager_module, "_now", lambda: now + timedelta(hours=2))
    assert manager.apply(plan, approval, source=source) == result
    assert (manager.root / "state.json").read_bytes() == state
    verify_document(result, manager._state_keys)


def test_expiry_during_staging_cannot_create_active_pin(manager, source, monkeypatch):
    now = manager_module._now()
    plan = manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source, ttl_seconds=10)
    approval = manager.approve(plan)
    original = manager._install
    def delayed(*args):
        result = original(*args)
        monkeypatch.setattr(manager_module, "_now", lambda: now + timedelta(minutes=1))
        return result
    monkeypatch.setattr(manager, "_install", delayed)
    with pytest.raises(ProtocolError, match="LOADOUT_EXPIRED"):
        manager.apply(plan, approval, source=source)
    assert manager.status() == []
    monkeypatch.setattr(manager, "_install", original)
    # A fresh exact approval can reuse the identical inactive staged bytes.
    admit(manager, source)
    assert manager.status()[0]["status"] == "ACTIVE"


def test_upgrade_rollback_revoke_and_clean_owned_uninstall(manager, source):
    first = admit(manager, source)
    upgrade = source_files(source["package"].parent / "upgrade", "1.0.1")
    second = admit(manager, upgrade)
    assert first["active_version_digest"] != second["active_version_digest"]
    rollback = manager.plan("rollback", "drafting", authorization_ref="attended-fixture")
    manager.apply(rollback, manager.approve(rollback))
    assert manager.status()[0]["active_version_digest"] == first["active_version_digest"]
    revoke = manager.plan("revoke", "drafting", authorization_ref="attended-fixture")
    manager.apply(revoke, manager.approve(revoke))
    with pytest.raises(ProtocolError, match="LOADOUT_NOT_ACTIVE"):
        manager.read_active("drafting")
    with pytest.raises(ProtocolError, match="LOADOUT_REVOKED"):
        manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source)
    unrelated = manager.vault / "keep.md"
    unrelated.write_text("User content remains.")
    uninstall = manager.plan("uninstall", "drafting", authorization_ref="attended-fixture")
    manager.apply(uninstall, manager.approve(uninstall))
    assert not list((manager.root / "objects").iterdir())
    assert unrelated.read_text() == "User content remains."
    assert manager.status()[0]["status"] == "UNINSTALLED"


def test_tampered_installed_file_is_preserved_and_blocks_read_and_uninstall(manager, source):
    receipt = admit(manager, source)
    path = manager.root / "objects" / receipt["active_version_digest"] / "components/draft-skill.txt"
    path.write_text("User changed this component.")
    assert manager.status()[0]["status"] == "BLOCKED"
    with pytest.raises(ProtocolError, match="LOADOUT_OWNED_CONTENT_CHANGED"):
        manager.read_active("drafting")
    plan = manager.plan("uninstall", "drafting", authorization_ref="attended-fixture")
    with pytest.raises(ProtocolError, match="LOADOUT_OWNED_CONTENT_CHANGED"):
        manager.apply(plan, manager.approve(plan))
    assert path.read_text() == "User changed this component."


def test_uninstall_resumes_only_its_signed_preverified_removal(manager, source, monkeypatch):
    receipt = admit(manager, source)
    plan = manager.plan("uninstall", "drafting", authorization_ref="attended-fixture")
    approval = manager.approve(plan)
    original = manager._remove
    def interrupted(pin, version, **context):
        original(pin, version, **context)
        raise OSError("simulated interruption after atomic retention")
    monkeypatch.setattr(manager, "_remove", interrupted)
    with pytest.raises(OSError):
        manager.apply(plan, approval)
    monkeypatch.setattr(manager, "_remove", original)
    result = manager.apply(plan, approval)
    assert result["outcome"] == "APPLIED"
    assert not list((manager.root / "objects").iterdir())
    assert result["content_purged"] is False
    assert (manager.vault / result["retained_recovery"][0]["path"] / "components/draft-skill.txt").is_file()


def test_uninstall_preserves_unowned_empty_directory(manager, source):
    receipt = admit(manager, source)
    extra = manager.root / "objects" / receipt["active_version_digest"] / "user-added-empty-directory"
    extra.mkdir()
    plan = manager.plan("uninstall", "drafting", authorization_ref="attended-fixture")
    with pytest.raises(ProtocolError, match="LOADOUT_OWNED_CONTENT_CHANGED"):
        manager.apply(plan, manager.approve(plan))
    assert extra.is_dir()


def test_expired_interrupted_uninstall_needs_fresh_exact_approval(manager, source, monkeypatch):
    admit(manager, source)
    now = manager_module._now()
    plan = manager.plan("uninstall", "drafting", authorization_ref="first-attended-review", ttl_seconds=10)
    approval = manager.approve(plan)
    original = manager._remove
    def interrupted(pin, version, **context):
        original(pin, version, **context)
        raise OSError("simulated interruption after atomic retention")
    monkeypatch.setattr(manager, "_remove", interrupted)
    with pytest.raises(OSError):
        manager.apply(plan, approval)
    monkeypatch.setattr(manager, "_remove", original)
    monkeypatch.setattr(manager_module, "_now", lambda: now + timedelta(minutes=1))
    with pytest.raises(ProtocolError, match="LOADOUT_EXPIRED"):
        manager.apply(plan, approval)
    fresh = manager.plan("uninstall", "drafting", authorization_ref="renewed-attended-review")
    result = manager.apply(fresh, manager.approve(fresh))
    assert result["authorization_ref"] == "renewed-attended-review"
    assert not list((manager.root / "objects").iterdir())
    assert result["content_purged"] is False
    assert (manager.vault / result["retained_recovery"][0]["path"] / "components/draft-skill.txt").is_file()


def test_missing_original_signing_key_is_never_regenerated(manager, source):
    admit(manager, source)
    key = manager.vault / ".hive/keys/application-adapters/attended-request.private.pem"
    key.unlink()
    with pytest.raises(ProtocolError, match="LOADOUT_SIGNING_KEY_MISSING"):
        loadout_services(manager.vault)
    assert not key.exists()


def test_product_status_and_read_never_bootstrap_or_refresh_grants(manager, source, monkeypatch):
    admit(manager, source)
    def snapshot():
        return {str(path.relative_to(manager.vault)): (path.stat().st_mtime_ns, path.stat().st_mode,
            hashlib.sha256(path.read_bytes()).hexdigest()) for path in manager.vault.rglob("*") if path.is_file()}
    before = snapshot()
    def denied(*args, **kwargs):
        raise AssertionError("read called product mutation services")
    monkeypatch.setattr(loadout_adapter, "product_adapter_services", denied)
    assert loadout_adapter.loadout_status(manager.vault)[0]["status"] == "ACTIVE"
    assert loadout_adapter.read_loadout(manager.vault, "drafting")
    assert snapshot() == before


def test_uninitialized_loadout_status_creates_nothing(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "Hive"
    HiveWorkspace.create(root)
    before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
    assert loadout_adapter.loadout_status(root) == []
    assert sorted(str(path.relative_to(root)) for path in root.rglob("*")) == before


@pytest.mark.parametrize("attack", ["traversal", "symlink", "case_collision", "undeclared", "hash", "credential"])
def test_malicious_arc_archive_is_refused(source, attack):
    def modify(entries):
        name = "components/draft-skill.txt"
        if attack == "traversal":
            entries["../escape.txt"] = entries.pop(name)
        elif attack == "symlink":
            entries[name][0].external_attr = (stat.S_IFLNK | 0o777) << 16
        elif attack == "case_collision":
            entries["COMPONENTS/DRAFT-SKILL.TXT"] = (zipfile.ZipInfo("COMPONENTS/DRAFT-SKILL.TXT"), b"shadow")
        elif attack == "undeclared":
            entries["components/extra.txt"] = (zipfile.ZipInfo("components/extra.txt"), b"extra")
        elif attack == "credential":
            # Construct this non-key marker at runtime so source credential scans
            # remain meaningful; the exercised rejection bytes are unchanged.
            marker = b"-----BEGIN " + b"PRIVATE KEY-----\nsynthetic-fixture\n"
            entries[name] = (entries[name][0], marker)
        else:
            entries[name] = (entries[name][0], b"hash differs from the exact component pin")
    rewrite_zip(source, modify)
    with pytest.raises(ProtocolError):
        inspect_arc_package(**source)


@pytest.mark.parametrize("mutation", ["missing_dependency", "conflict", "unknown_license", "duplicate_yaml", "alias", "python_tag"])
def test_invalid_original_registry_closure_is_refused(source, mutation):
    text = source["registry"].read_text()
    if mutation == "missing_dependency":
        text = text.replace("dependencies: []", "dependencies: [missing-runtime]")
    elif mutation == "conflict":
        text = text.replace("conflicts: []", "conflicts: [community-draft-skill]")
    elif mutation == "unknown_license":
        text = text.replace("license: MIT", "license: UNKNOWN")
    elif mutation == "duplicate_yaml":
        text += "\nregistry_version: different\n"
    elif mutation == "alias":
        text += "\nextra: &anchor [value]\nreused: *anchor\n"
    else:
        text += "\nextra: !!python/object/apply:os.system ['false']\n"
    source["registry"].write_text(text)
    with pytest.raises(ProtocolError):
        inspect_arc_package(**source)


def test_adapter_reference_remains_exact_and_obeys_fresh_durable_revocation(manager, source):
    entry = manager.registry.require_current("nukotech.hive.local-capture")
    reference = {"adapter_id": entry.manifest.adapter_id, "version": entry.manifest.version,
        "manifest_digest": entry.manifest_digest, "capability_ids": [entry.manifest.capability_ids[0]]}
    plan = manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source,
                        adapter_references=[reference])
    approval = manager.approve(plan)
    another = loadout_services(manager.vault)
    another.registry.revoke(reference["adapter_id"], reason="synthetic test", authorization_ref="attended-test")
    with pytest.raises(ProtocolError, match="LOADOUT_ADAPTER_REVOKED"):
        manager.apply(plan, approval, source=source)
    assert manager.status() == []


@pytest.mark.parametrize("field,value", [("version", "999.0.0"), ("manifest_digest", "0" * 64),
                                       ("capability_ids", ["undeclared.admin"] )])
def test_adapter_reference_cannot_substitute_or_broaden(manager, source, field, value):
    entry = manager.registry.require_current("nukotech.hive.local-capture")
    reference = {"adapter_id": entry.manifest.adapter_id, "version": entry.manifest.version,
        "manifest_digest": entry.manifest_digest, "capability_ids": [entry.manifest.capability_ids[0]]}
    reference[field] = value
    with pytest.raises(ProtocolError):
        manager.plan("admit", "drafting", authorization_ref="attended-fixture", source=source,
                     adapter_references=[reference])
