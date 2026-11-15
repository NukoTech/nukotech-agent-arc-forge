from __future__ import annotations

import json
from pathlib import Path

import pytest

from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.core import ProtocolError


class FakeAdapter:
    def health(self) -> dict:
        return {"status": "HEALTHY", "evidence": []}

    def plan(self, payload: dict) -> dict:
        return {
            "side_effects": [],
            "network_destinations": [],
            "requires_approval": False,
            "payload": payload,
        }

    def apply(self, payload: dict, *, operation_key: str) -> dict:
        return {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": [],
            "resource_use": {},
        }

    def recover(self, operation_key: str) -> dict | None:
        return None

    def export(self, scope: dict, *, operation_key: str) -> dict:
        return {
            "outcome": "NO_OP",
            "evidence_refs": [],
            "side_effects": [],
            "resource_use": {},
        }

    def rollback(self, rollback_ref: str, *, operation_key: str) -> dict:
        return {
            "outcome": "NO_OP",
            "evidence_refs": [],
            "side_effects": [],
            "resource_use": {},
        }

    def recover_lifecycle(self, operation: str, operation_key: str) -> dict | None:
        return None


@pytest.fixture
def manifest_document() -> dict:
    root = Path(__file__).parents[1]
    document = json.loads(
        (
            root
            / "tests/fixtures/adapters/sample-heartbeat.manifest.json"
        ).read_text(encoding="utf-8")
    )
    document["adapter_id"] = "nukotech.hive.test-adapter"
    document["name"] = "Test Adapter"
    document["version"] = "1.0.0"
    document["platforms"] = [
        {"os": "linux", "architecture": "aarch64", "runtime": "python>=3.11"}
    ]
    document["capability_ids"] = ["capture.text"]
    document["required_permissions"] = ["filesystem.write.adapter-state"]
    document["accepted_data_classifications"] = ["PROJECT_PRIVATE"]
    document["network_destinations"] = []
    document["credential_references"] = []
    return document


def _registry(tmp_path: Path) -> AdapterRegistry:
    return AdapterRegistry(
        tmp_path / "runtime",
        tmp_path / "policy",
        os_name="linux",
        architecture="aarch64",
        runtime="python>=3.11",
    )


def test_registry_refuses_duplicate_and_revoked_adapter(
    tmp_path: Path, manifest_document: dict
) -> None:
    registry = _registry(tmp_path)
    registry.register(FakeAdapter(), manifest_document)
    with pytest.raises(ProtocolError, match="ADAPTER_ALREADY_REGISTERED"):
        registry.register(FakeAdapter(), manifest_document)
    registry.revoke(
        manifest_document["adapter_id"],
        reason="operator decision",
        authorization_ref="decision:1",
    )
    with pytest.raises(ProtocolError, match="ADAPTER_REVOKED"):
        registry.require(manifest_document["adapter_id"], manifest_document["version"])


def test_registry_refuses_wrong_version_and_platform(
    tmp_path: Path, manifest_document: dict
) -> None:
    registry = _registry(tmp_path)
    registry.register(FakeAdapter(), manifest_document)
    with pytest.raises(ProtocolError, match="ADAPTER_VERSION_MISMATCH"):
        registry.require(manifest_document["adapter_id"], "2.0.0")

    incompatible = dict(manifest_document)
    incompatible["adapter_id"] = "nukotech.hive.incompatible"
    incompatible["platforms"] = [
        {"os": "windows", "architecture": "x86_64", "runtime": "python>=3.11"}
    ]
    with pytest.raises(ProtocolError, match="ADAPTER_PLATFORM_INCOMPATIBLE"):
        registry.register(FakeAdapter(), incompatible)


def test_status_is_sorted_and_omits_credential_references(
    tmp_path: Path, manifest_document: dict
) -> None:
    registry = _registry(tmp_path)
    registry.register(FakeAdapter(), manifest_document)
    status = registry.list_status()
    assert status[0]["adapter_id"] == "nukotech.hive.test-adapter"
    assert status[0]["health"] == {"status": "HEALTHY", "evidence": []}
    assert "credential_references" not in json.dumps(status)


def test_registry_rejects_symlink_roots(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked-runtime"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ProtocolError, match="ADAPTER_REGISTRY_ROOT_BOUNDARY"):
        AdapterRegistry(
            link,
            tmp_path / "policy",
            os_name="linux",
            architecture="aarch64",
            runtime="python>=3.11",
        )
