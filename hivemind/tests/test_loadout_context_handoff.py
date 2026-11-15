"""A context consumer must revalidate its exact bytes against current admission."""

import copy
import hashlib
import json

import pytest

from hive_protocol.core import ProtocolError, canonical_bytes
from hive_protocol.loadouts import manager as manager_module
from hive_protocol.product import cli, loadout_adapter
from hive_protocol.product.workspace import HiveWorkspace

from arc_loadout_fixture import materialize


def source_files(directory, version="1.0.0"):
    return {"package": directory / f"marketing-operator-{version}.zip",
        "checksum_manifest": directory / f"marketing-operator-{version}.MANIFEST.sha256",
        "recipe": directory / "recipe.yaml", "registry": directory / "registry.yaml",
        "authorization": directory / "authorization.yaml"}


def admit(manager, source, loadout_id="drafting"):
    plan = manager.plan("admit", loadout_id, authorization_ref="synthetic-attended-context-review", source=source)
    return manager.apply(plan, manager.approve(plan), source=source)


def tree(root):
    return {str(path.relative_to(root)): "directory" if path.is_dir()
        else hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob("*")}


@pytest.fixture
def admitted(tmp_path):
    root = tmp_path.resolve() / "Hive"
    HiveWorkspace.create(root)
    manager = loadout_adapter.loadout_services(root)
    source_dir = tmp_path.resolve() / "arc"
    materialize(source_dir)
    source = source_files(source_dir)
    admit(manager, source)
    return manager, source


def test_snapshot_roundtrip_exact_context_without_writes(admitted):
    manager, _ = admitted
    before = tree(manager.vault)
    context = loadout_adapter.read_loadout_context(manager.vault, "drafting")
    assert context == loadout_adapter.read_loadout_context(manager.vault, "drafting")
    assert {path: value["text"] for path, value in context["components"].items()} == manager.read_active("drafting")
    assert context["grants_authority"] is False
    assert context["execution_mode"] == "DECLARATIVE_ONLY"
    result = loadout_adapter.verify_loadout_context(manager.vault, context)
    assert result["outcome"] == "LOADOUT_CONTEXT_VERIFIED"
    assert result["version_digest"] == context["version_digest"]
    assert result["context_sha256"] == context["context_sha256"]
    assert result["grants_authority"] is False
    assert tree(manager.vault) == before


@pytest.mark.parametrize("change", ["text", "component_hash", "target", "version", "key", "authority", "execution", "digest", "extra"])
@pytest.mark.parametrize("rehash", [False, True])
def test_changed_snapshot_refuses_even_if_digest_is_recomputed(admitted, change, rehash):
    manager, _ = admitted
    context = manager.context_snapshot("drafting")
    component = next(iter(context["components"].values()))
    if change == "text":
        component["text"] += "\nChanged consumer instruction."
    elif change == "component_hash":
        component["sha256"] = "0" * 64
    elif change == "target":
        context["target"]["machine_id"] = "other-machine"
    elif change == "version":
        context["version_digest"] = "0" * 64
    elif change == "key":
        context["admission_key_id"] = "other-vault"
    elif change == "authority":
        context["grants_authority"] = True
    elif change == "execution":
        context["execution_mode"] = "EXECUTE"
    elif change == "digest":
        context["context_sha256"] = "0" * 64
    else:
        context["unreviewed"] = True
    if rehash and change != "digest":
        payload = {key: value for key, value in context.items() if key != "context_sha256"}
        context["context_sha256"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    before = tree(manager.vault)
    with pytest.raises(ProtocolError, match="LOADOUT_CONTEXT_"):
        manager.verify_context(context)
    assert tree(manager.vault) == before


def test_same_pack_in_another_vault_cannot_verify_first_vault_snapshot(admitted, tmp_path):
    manager, source = admitted
    context = manager.context_snapshot("drafting")
    other = HiveWorkspace.create(tmp_path.resolve() / "other")
    other_manager = loadout_adapter.loadout_services(other.root)
    admit(other_manager, source)
    assert other_manager.target == manager.target
    assert other_manager.context_snapshot("drafting")["version_digest"] == context["version_digest"]
    with pytest.raises(ProtocolError, match="LOADOUT_CONTEXT_CHANGED"):
        other_manager.verify_context(context)


@pytest.mark.parametrize("operation", ["revoke", "uninstall"])
def test_current_admission_required_after_lifecycle_change(admitted, operation):
    manager, _ = admitted
    context = manager.context_snapshot("drafting")
    plan = manager.plan(operation, "drafting", authorization_ref="synthetic-context-cleanup")
    manager.apply(plan, manager.approve(plan))
    before = tree(manager.vault)
    with pytest.raises(ProtocolError, match="LOADOUT_NOT_ACTIVE"):
        manager.verify_context(context)
    assert tree(manager.vault) == before


def test_upgrade_invalidates_previous_context(admitted):
    manager, source = admitted
    old = manager.context_snapshot("drafting")
    upgrade = source_files(source["recipe"].parent / "upgrade", "1.0.1")
    admit(manager, upgrade)
    with pytest.raises(ProtocolError, match="LOADOUT_CONTEXT_CHANGED"):
        manager.verify_context(old)
    current = manager.context_snapshot("drafting")
    assert current["version_digest"] != old["version_digest"]
    assert manager.verify_context(current)["outcome"] == "LOADOUT_CONTEXT_VERIFIED"


def test_unrelated_admission_does_not_invalidate_context(admitted):
    manager, source = admitted
    context = manager.context_snapshot("drafting")
    admit(manager, source, "another-task")
    assert manager.verify_context(context)["outcome"] == "LOADOUT_CONTEXT_VERIFIED"


def test_context_aggregate_limit_refuses_without_writes(admitted, monkeypatch):
    manager, _ = admitted
    context = manager.context_snapshot("drafting")
    before = tree(manager.vault)
    monkeypatch.setattr(manager_module, "MAX_CONTEXT_BYTES", 128)
    with pytest.raises(ProtocolError, match="LOADOUT_CONTEXT_LIMIT"):
        manager.context_snapshot("drafting")
    with pytest.raises(ProtocolError, match="LOADOUT_CONTEXT_LIMIT"):
        manager.verify_context(context)
    assert tree(manager.vault) == before


def test_installed_object_drift_refuses_context(admitted):
    manager, _ = admitted
    context = manager.context_snapshot("drafting")
    path = next(iter(context["components"]))
    (manager.root / "objects" / context["version_digest"] / path).write_text("changed installed instruction")
    with pytest.raises(ProtocolError):
        manager.verify_context(context)


def test_bytes_changed_between_object_check_and_context_read_refuse(admitted, monkeypatch):
    manager, _ = admitted
    original = manager_module.read_bounded
    original_check = manager._verify_object
    checked = False

    def mark_checked(*args):
        nonlocal checked
        original_check(*args)
        checked = True

    def changed_read(path, *args):
        content = original(path, *args)
        if checked and "components" in path.parts:
            return content + b"\nchanged after integrity check"
        return content

    monkeypatch.setattr(manager, "_verify_object", mark_checked)
    monkeypatch.setattr(manager_module, "read_bounded", changed_read)
    with pytest.raises(ProtocolError, match="LOADOUT_CONTEXT_CHANGED"):
        manager.context_snapshot("drafting")


def test_non_internal_scope_and_missing_history_leave_no_new_files(tmp_path):
    customer = HiveWorkspace.create(tmp_path.resolve() / "customer", tenant_id="customer")
    before = tree(customer.root)
    with pytest.raises(ProtocolError, match="LOADOUT_SCOPE_UNSUPPORTED"):
        loadout_adapter.read_loadout_context(customer.root, "drafting")
    assert tree(customer.root) == before
    internal = HiveWorkspace.create(tmp_path.resolve() / "new-hive")
    before = tree(internal.root)
    with pytest.raises(ProtocolError):
        loadout_adapter.read_loadout_context(internal.root, "drafting")
    assert tree(internal.root) == before


def test_cli_roundtrip_and_duplicate_key_refusal(admitted, tmp_path, capsys):
    manager, _ = admitted
    output = tmp_path.resolve() / "context.json"
    before = tree(manager.vault)
    assert cli.main(["loadout-context", "--vault", str(manager.vault), "--loadout-id", "drafting", "--output", str(output)]) == 0
    assert cli.main(["loadout-context-verify", "--vault", str(manager.vault), "--context", str(output)]) == 0
    assert tree(manager.vault) == before
    capsys.readouterr()
    output.write_text('{"loadout_id":"drafting","loadout_id":"other"}')
    refusal_output = tmp_path.resolve() / "refusal.json"
    assert cli.main(["loadout-context-verify", "--vault", str(manager.vault), "--context", str(output), "--output", str(refusal_output)]) == 2
    assert "duplicate JSON key" in capsys.readouterr().out
    assert not refusal_output.exists()
    assert tree(manager.vault) == before


@pytest.mark.parametrize("operation", ["loadout-context", "loadout-context-verify"])
def test_cli_context_output_cannot_overwrite_vault_files(admitted, tmp_path, operation, capsys):
    manager, _ = admitted
    context_path = tmp_path.resolve() / "context.json"
    context_path.write_text(json.dumps(manager.context_snapshot("drafting")))
    args = [operation, "--vault", str(manager.vault), "--output", str(manager.vault / ".hive/loadouts/state.json")]
    args += ["--loadout-id", "drafting"] if operation == "loadout-context" else ["--context", str(context_path)]
    before = tree(manager.vault)
    assert cli.main(args) == 2
    assert "CLI_OUTPUT_BOUNDARY" in capsys.readouterr().out
    assert tree(manager.vault) == before


def test_cli_context_output_refuses_symlink_parent(admitted, tmp_path, capsys):
    manager, _ = admitted
    alias = tmp_path.resolve() / "alias"
    alias.symlink_to(manager.vault, target_is_directory=True)
    before = tree(manager.vault)
    assert cli.main(["loadout-context", "--vault", str(manager.vault), "--loadout-id", "drafting", "--output", str(alias / "context.json")]) == 2
    assert "CLI_OUTPUT_BOUNDARY" in capsys.readouterr().out
    assert tree(manager.vault) == before


@pytest.mark.parametrize("invalid", [None, [], {}, {"loadout_id": 1}, {"loadout_id": "../outside"}])
def test_malformed_context_refuses_without_writes(admitted, invalid):
    manager, _ = admitted
    before = tree(manager.vault)
    with pytest.raises(ProtocolError, match="LOADOUT_CONTEXT_INVALID"):
        manager.verify_context(copy.deepcopy(invalid))
    assert tree(manager.vault) == before
