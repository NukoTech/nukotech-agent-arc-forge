from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, public_key_id, sign_document
from hive_protocol.workflows.definitions import WorkflowDefinitionStore
from hive_protocol.workflows.models import WorkflowDefinition, workflow_document_digest


NOW = datetime(2026, 9, 1, 7, 15, tzinfo=timezone.utc)


def _actor(key: Ed25519PrivateKey) -> dict[str, str]:
    return {
        "actor_id": "agent:operator",
        "persona_id": "persona:Director",
        "surface_id": "surface:LeadA",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "app:hive-local-attended",
        "key_id": public_key_id(key.public_key()),
    }


def _step(
    step_id: str,
    *,
    dependencies: list[str] | None = None,
    input_type: str | None = None,
) -> dict[str, object]:
    inputs = []
    if input_type is not None:
        inputs = [
            {
                "name": "upstream",
                "type": input_type,
                "source_step_id": "collect",
                "source_output": "result",
                "required": True,
            }
        ]
    return {
        "step_id": step_id,
        "kind": "TASK",
        "dependencies": dependencies or [],
        "inputs": inputs,
        "outputs": [{"name": "result", "type": "application/json"}],
        "required_capabilities": ["vault:search"],
        "required_trust": "ATTENDED",
        "target": {
            "project_id": "HiveMind",
            "machine_id": "machine:hive-lab-host",
            "surface_id": None,
        },
        "approval": {"required": False, "risk_class": "LOW"},
        "retry": {"max_attempts": 2, "timeout_seconds": 300},
        "resources": {
            "max_tokens": 1000,
            "max_cost_microunits": 5000,
            "max_memory_mb": 256,
        },
        "ownership": {
            "branches": [f"workflows/{step_id}"],
            "files": [f"research/{step_id}.md"],
        },
        "rollback": {"mode": "GIT_CHECKPOINT", "compensation_step_id": None},
    }


def _definition(
    key: Ed25519PrivateKey,
    *,
    version: int = 1,
    parent_digest: str | None = None,
    steps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return sign_document(
        {
            "schema_version": "hive.workflow-definition.v1",
            "workflow_id": "workflow:alpha",
            "version": version,
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "title": f"Attended workflow v{version}",
            "description": "A bounded local workflow.",
            "parent_digest": parent_digest,
            "steps": steps or [_step("collect")],
            "metadata": {"tags": ["internal-alpha"]},
            "publisher": _actor(key),
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def _store(tmp_path: Path, key: Ed25519PrivateKey) -> WorkflowDefinitionStore:
    return WorkflowDefinitionStore(
        tmp_path / "hive", {public_key_id(key.public_key()): key.public_key()}
    )


def test_preview_is_read_only_and_publish_is_immutable_and_idempotent(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    store = _store(tmp_path, key)
    document = _definition(key)

    preview = store.preview(document)
    assert preview["workflow_sha256"] == workflow_document_digest(document)
    assert not (tmp_path / "hive" / "workflows").exists()

    published = store.publish(document, idempotency_key="publish-alpha-v1")
    assert published["changed"] is True
    assert store.load("workflow:alpha", 1).as_dict() == document
    assert store.list_versions("workflow:alpha") == [1]
    assert store.publish(document, idempotency_key="publish-alpha-v1")["changed"] is False
    assert len(list((tmp_path / "hive" / ".hive" / "receipts" / "workflows" / "definitions").rglob("*.json"))) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda steps: steps[0]["dependencies"].append("collect"),
        lambda steps: steps[0]["dependencies"].append("missing"),
        lambda steps: steps.extend(
            [
                _step("analyze", dependencies=["collect"], input_type="text/plain")
            ]
        ),
        lambda steps: steps[0]["ownership"].update(files=["../escape.md"]),
        lambda steps: steps[0].update(kind="APPROVAL"),
        lambda steps: steps[0]["rollback"].update(
            mode="COMPENSATION", compensation_step_id=None
        ),
    ],
)
def test_publish_refuses_invalid_dag_types_ownership_and_control_placement(
    tmp_path: Path, mutation
) -> None:
    key = Ed25519PrivateKey.generate()
    steps = [_step("collect")]
    mutation(steps)
    with pytest.raises(ProtocolError):
        _store(tmp_path, key).publish(
            _definition(key, steps=steps), idempotency_key="publish-invalid"
        )


def test_publish_refuses_dependency_cycle(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    steps = [
        _step("collect", dependencies=["analyze"]),
        _step("analyze", dependencies=["collect"]),
    ]
    with pytest.raises(ProtocolError, match="acyclic"):
        _store(tmp_path, key).publish(
            _definition(key, steps=steps), idempotency_key="publish-cycle"
        )


def test_new_version_binds_parent_without_mutating_history(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    store = _store(tmp_path, key)
    first = _definition(key)
    store.publish(first, idempotency_key="publish-v1")
    first_bytes = store.definition_path("workflow:alpha", 1).read_bytes()

    second = _definition(
        key,
        version=2,
        parent_digest=workflow_document_digest(first),
        steps=[_step("collect"), _step("review", dependencies=["collect"], input_type="application/json")],
    )
    store.publish(second, idempotency_key="publish-v2")
    assert store.list_versions("workflow:alpha") == [1, 2]
    assert store.definition_path("workflow:alpha", 1).read_bytes() == first_bytes

    wrong_parent = _definition(key, version=3, parent_digest="f" * 64)
    with pytest.raises(ProtocolError):
        store.publish(wrong_parent, idempotency_key="publish-v3-wrong")


def test_signature_trust_and_version_bytes_fail_closed(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    stranger = Ed25519PrivateKey.generate()
    store = _store(tmp_path, key)
    with pytest.raises(ProtocolError):
        store.publish(_definition(stranger), idempotency_key="unknown-signer")

    original = _definition(key)
    store.publish(original, idempotency_key="publish-original")
    conflicting = copy.deepcopy(original)
    conflicting["title"] = "Changed historical bytes"
    conflicting = sign_document(conflicting, key)
    with pytest.raises(ProtocolError):
        store.publish(conflicting, idempotency_key="publish-conflict")


def test_publish_adopts_exact_crash_window_once(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    store = _store(tmp_path, key)
    document = _definition(key)

    with pytest.raises(SystemExit, match="crash after definition"):
        store.publish(
            document,
            idempotency_key="crash-window",
            after_definition_write=lambda: (_ for _ in ()).throw(
                SystemExit("crash after definition")
            ),
        )

    assert store.definition_path("workflow:alpha", 1).is_file()
    recovered = WorkflowDefinitionStore(
        tmp_path / "hive", {public_key_id(key.public_key()): key.public_key()}
    ).publish(document, idempotency_key="crash-window")
    assert recovered["changed"] is True
    assert recovered["outcome"] == "PUBLISHED"


def test_definition_root_and_version_file_symlinks_are_refused(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    outside = tmp_path / "outside"
    outside.mkdir()
    hive = tmp_path / "hive"
    hive.mkdir()
    (hive / "workflows").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProtocolError):
        WorkflowDefinitionStore(
            hive, {public_key_id(key.public_key()): key.public_key()}
        )

    safe_store = _store(tmp_path / "second", key)
    target = safe_store.definition_path("workflow:alpha", 1)
    target.parent.mkdir(parents=True)
    outside_file = outside / "definition.json"
    outside_file.write_text("{}", encoding="utf-8")
    target.symlink_to(outside_file)
    with pytest.raises(ProtocolError):
        safe_store.publish(_definition(key), idempotency_key="symlink-version")
