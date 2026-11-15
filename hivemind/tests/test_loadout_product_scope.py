"""The attended loadout bridge signs only its configured Hive scope."""

import hashlib
import json
import os
from pathlib import Path
import subprocess  # nosec B404
import sys

import pytest

from arc_loadout_fixture import materialize

from hive_protocol.core import ProtocolError
from hive_protocol.product import scope
from hive_protocol.product.loadout_adapter import loadout_services
from hive_protocol.product.workspace import HiveWorkspace

SRC = Path(__file__).resolve().parents[1] / "src"


def snapshot(root):
    return {
        str(path.relative_to(root)): (
            "directory" if path.is_dir()
            else hashlib.sha256(path.read_bytes()).hexdigest()
        )
        for path in root.rglob("*")
    }


def set_scope(workspace, **fields):
    config = json.loads(workspace.config_path.read_text())
    for key, value in fields.items():
        if value is None:
            config.pop(key)
        else:
            config[key] = value
    workspace.config_path.write_text(json.dumps(config))


def run_with_scope(code, tmp_path, *args, **env):
    """Run in a fresh interpreter: the scope setting is read once at import."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"HIVE_TENANT_ID", "HIVE_PROJECT_ID"}}
    environment.update(env, PYTHONPATH=str(SRC))
    return subprocess.run(  # nosec B603
        [sys.executable, "-c", code, str(tmp_path.resolve() / "Hive"), *args],
        env=environment, capture_output=True, text=True, timeout=120, check=False,
    )


def test_default_scope_is_local_user_hivemind(tmp_path):
    if {"HIVE_TENANT_ID", "HIVE_PROJECT_ID"} & set(os.environ):
        pytest.skip("scope override set for this test process")
    assert (scope.TENANT_ID, scope.ADAPTER_PROJECT_ID) == ("local-user", "HiveMind")
    workspace = HiveWorkspace.create(tmp_path.resolve() / "Hive")
    assert workspace.scope() == {"tenant_id": "local-user", "project_id": "HiveMind"}
    assert loadout_services(workspace.root).target["project_id"] == "HiveMind"


@pytest.mark.parametrize("tenant,project", [
    ("local-user", "Research"),
    ("customer-one", "HiveMind"),
    ("customer-one", "Research"),
])
@pytest.mark.parametrize("read_only", [False, True])
def test_non_configured_scope_refuses_before_adapter_or_loadout_writes(
    tmp_path, tenant, project, read_only
):
    workspace = HiveWorkspace.create(
        tmp_path.resolve() / "Hive", tenant_id=tenant, project_id=project
    )
    before = snapshot(workspace.root)
    with pytest.raises(ProtocolError, match="LOADOUT_SCOPE_UNSUPPORTED"):
        loadout_services(workspace.root, read_only=read_only)
    assert snapshot(workspace.root) == before


def test_legacy_scope_keeps_default_target_and_reopens(tmp_path):
    workspace = HiveWorkspace.create(tmp_path.resolve() / "Hive")
    set_scope(workspace, tenant_id=None, project_id=None)
    manager = loadout_services(workspace.root)
    assert manager.target["project_id"] == scope.ADAPTER_PROJECT_ID
    assert loadout_services(workspace.root, read_only=True).target == manager.target


def test_changed_scope_preserves_established_loadout_history(tmp_path):
    workspace = HiveWorkspace.create(tmp_path.resolve() / "Hive")
    loadout_services(workspace.root)
    set_scope(workspace, project_id="Research")
    before = snapshot(workspace.root)
    with pytest.raises(ProtocolError, match="LOADOUT_SCOPE_UNSUPPORTED"):
        loadout_services(workspace.root)
    with pytest.raises(ProtocolError, match="LOADOUT_SCOPE_UNSUPPORTED"):
        loadout_services(workspace.root, read_only=True)
    assert snapshot(workspace.root) == before


OVERRIDE = """
import json, sys
from pathlib import Path
from hive_protocol.product import agent_adapter, scope
from hive_protocol.product.loadout_adapter import loadout_services
from hive_protocol.product.workspace import HiveWorkspace
workspace = HiveWorkspace.create(Path(sys.argv[1]))
manager = loadout_services(workspace.root)
print(json.dumps({
    "setting": [scope.TENANT_ID, scope.ADAPTER_PROJECT_ID],
    "adapter": [agent_adapter.TENANT_ID, agent_adapter.ADAPTER_OPERATOR_IDENTITY["project_id"]],
    "workspace": workspace.scope(),
    "target": manager.target["project_id"],
    "reopened": loadout_services(workspace.root, read_only=True).target == manager.target,
}))
"""


def test_overridden_scope_is_used_consistently(tmp_path):
    result = run_with_scope(OVERRIDE, tmp_path, HIVE_TENANT_ID="customer-one", HIVE_PROJECT_ID="Research")
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed == {
        "setting": ["customer-one", "Research"],
        "adapter": ["customer-one", "Research"],
        "workspace": {"tenant_id": "customer-one", "project_id": "Research"},
        "target": "Research",
        "reopened": True,
    }


MISMATCH = """
import sys
from pathlib import Path
from hive_protocol.core import ProtocolError
from hive_protocol.product.loadout_adapter import loadout_services
from hive_protocol.product.workspace import HiveWorkspace
try:
    loadout_services(HiveWorkspace.open(Path(sys.argv[1])).root, read_only=sys.argv[2:] == ["ro"])
except ProtocolError as exc:
    print(exc.code)
    raise SystemExit(3)
"""


@pytest.mark.parametrize("read_only", [False, True])
def test_override_refuses_hive_created_with_default_scope(tmp_path, read_only):
    workspace = HiveWorkspace.create(tmp_path.resolve() / "Hive")
    loadout_services(workspace.root)
    before = snapshot(workspace.root)
    args = ["ro"] if read_only else []
    result = run_with_scope(MISMATCH, tmp_path, *args, HIVE_PROJECT_ID="Research")
    assert result.returncode == 3, result.stderr
    assert "LOADOUT_SCOPE_UNSUPPORTED" in result.stdout
    assert snapshot(workspace.root) == before


def test_override_refuses_legacy_hive_with_established_default_history(tmp_path):
    workspace = HiveWorkspace.create(tmp_path.resolve() / "Hive")
    manager = loadout_services(workspace.root)
    arc = materialize(tmp_path.resolve() / "arc")
    source = {"package": arc / "marketing-operator-1.0.0.zip",
              "checksum_manifest": arc / "marketing-operator-1.0.0.MANIFEST.sha256",
              "recipe": arc / "recipe.yaml", "registry": arc / "registry.yaml",
              "authorization": arc / "authorization.yaml"}
    plan = manager.plan("admit", "drafting", authorization_ref="synthetic-scope-review", source=source)
    manager.apply(plan, manager.approve(plan), source=source)
    set_scope(workspace, tenant_id=None, project_id=None)
    before = snapshot(workspace.root)
    result = run_with_scope(MISMATCH, tmp_path, HIVE_PROJECT_ID="Research")
    assert result.returncode == 3, result.stderr
    assert "LOADOUT_SCOPE_UNSUPPORTED" in result.stdout
    assert snapshot(workspace.root) == before


def test_invalid_explicit_scope_refuses_before_creating_hive(tmp_path):
    root = tmp_path.resolve() / "Hive"
    with pytest.raises(ProtocolError, match="VAULT_SCOPE_INVALID"):
        HiveWorkspace.create(root, tenant_id="same", project_id="same")
    assert not root.exists()


@pytest.mark.parametrize("env", [
    {"HIVE_TENANT_ID": ""},
    {"HIVE_PROJECT_ID": "has space"},
    {"HIVE_PROJECT_ID": "../outside"},
    {"HIVE_TENANT_ID": "x" * 129},
    {"HIVE_TENANT_ID": "same", "HIVE_PROJECT_ID": "same"},
])
def test_invalid_scope_setting_fails_closed(tmp_path, env):
    result = run_with_scope("import hive_protocol.product.scope", tmp_path, **env)
    assert result.returncode != 0
    assert "VAULT_SCOPE_INVALID" in result.stderr
