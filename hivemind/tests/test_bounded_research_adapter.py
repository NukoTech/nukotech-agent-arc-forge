from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.adapters.policy import InvocationContext
from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.adapters.research import BoundedResearchAdapter
from hive_protocol.adapters.runtime import AdapterRuntime
from hive_protocol.ask import AskHive
from hive_protocol.core import ProtocolError, public_key_id, sign_document
from hive_protocol.retrieval import LocalRetriever, SourceDocument
from hive_protocol.storage import atomic_write_json, read_json


IDENTITY = {
    "persona_id": "Director",
    "surface_id": "LeadA",
    "machine_id": "hive-lab-host",
    "project_id": "HiveMind",
    "app_actor": "hive-builda-app",
}


def source_document(workspace_id: str, content: str, source_id: str) -> SourceDocument:
    return SourceDocument(
        tenant_id="tenant-a",
        workspace_id=workspace_id,
        source_id=source_id,
        source_path=f"notes/{source_id}.md",
        content=content,
        sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        provenance={"kind": "adapter-fixture", "revision": "1"},
    )


def _signed_request(
    request_key: Ed25519PrivateKey,
    *,
    request_id: str,
    nonce: str,
    capability_id: str,
    payload: dict,
    evidence_sha256: list[str] | None = None,
) -> dict:
    text = payload.get("query", payload.get("question", ""))
    evidence_sha256 = evidence_sha256 or [
        hashlib.sha256(str(text).encode("utf-8")).hexdigest()
    ]
    return sign_document(
        AdapterRequest(
            request_id=request_id,
            adapter_id="nukotech.hive.bounded-research",
            adapter_version="1.0.0",
            sender=dict(IDENTITY),
            project_id="HiveMind",
            capability_id=capability_id,
            data_classification="PROJECT_PRIVATE",
            authorization_ref="grant:hivemind:research",
            evidence_sha256=evidence_sha256,
            payload=payload,
            nonce=nonce,
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
        ).as_dict(),
        request_key,
    )


@pytest.fixture
def runtime_fixture(tmp_path: Path):
    retriever = LocalRetriever(tmp_path / "research.sqlite3")
    adapter = BoundedResearchAdapter(
        retriever,
        AskHive(retriever),
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        project_id="HiveMind",
        state_root=tmp_path / "research-state",
        state_signing_key=Ed25519PrivateKey.generate(),
    )
    manifest_path = (
        Path(__file__).parents[1]
        / "src/hive_protocol/adapters/research/bounded-research.manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    registry = AdapterRegistry(
        tmp_path / "runtime",
        tmp_path / "runtime/policy",
        os_name="linux",
        architecture="aarch64",
        runtime="python>=3.11",
    )
    registry.register(adapter, manifest)
    request_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    runtime = AdapterRuntime(
        tmp_path / "runtime",
        registry,
        {public_key_id(request_key.public_key()): request_key.public_key()},
        {},
        runtime_key,
        trusted_approver_identities={},
    )
    context = InvocationContext(
        project_id="HiveMind",
        authorization_ref="grant:hivemind:research",
        identity=dict(IDENTITY),
        granted_capabilities=frozenset({"research.ask", "research.search"}),
        granted_permissions=frozenset(
            {
                "filesystem.read.workspace",
                "filesystem.write.adapter-state",
                "filesystem.write.workspace",
            }
        ),
        allowed_data_classifications=frozenset({"PROJECT_PRIVATE"}),
        allowed_network_destinations=frozenset(),
        available_credential_references=frozenset(),
    )
    return runtime, retriever, adapter, request_key, context


@pytest.fixture
def signed_ask_request(runtime_fixture) -> dict:
    _, _, _, request_key, _ = runtime_fixture
    return _signed_request(
        request_key,
        request_id="research-ask-001",
        nonce="research-ask-nonce-001",
        capability_id="research.ask",
        payload={
            "operation": "ask",
            "tenant_id": "tenant-a",
            "workspace_id": "workspace-a",
            "question": "approved fact",
            "limit": 5,
        },
    )


def test_bounded_research_never_crosses_workspace(
    runtime_fixture, signed_ask_request
) -> None:
    runtime, retriever, adapter, _, context = runtime_fixture
    retriever.index(source_document("workspace-a", "approved fact", "source-a"))
    retriever.index(
        source_document(
            "workspace-b",
            "approved fact; secret other fact",
            "source-b",
        )
    )
    assert not adapter.state_root.exists()
    plan = runtime.plan(signed_ask_request, context)
    assert not adapter.state_root.exists()
    result = runtime.invoke(
        signed_ask_request, plan, context, approval_document=None
    )
    assert result["outcome"] == "APPLIED"
    assert {item["source_id"] for item in result["detail"]["citations"]} == {
        "source-a"
    }
    assert "secret other fact" not in json.dumps(result)


def test_absent_model_is_labeled_retrieval_only(
    runtime_fixture, signed_ask_request
) -> None:
    runtime, retriever, _, _, context = runtime_fixture
    retriever.index(source_document("workspace-a", "approved fact", "source-a"))
    plan = runtime.plan(signed_ask_request, context)
    result = runtime.invoke(
        signed_ask_request, plan, context, approval_document=None
    )
    assert result["detail"]["status"] == "RETRIEVAL_ONLY"
    assert result["detail"]["provider_called"] is False


def test_research_apply_is_idempotent_for_one_operation_key(runtime_fixture) -> None:
    _, retriever, adapter, _, _ = runtime_fixture
    retriever.index(source_document("workspace-a", "idempotent fact", "source-a"))
    planned = adapter.plan(
        {
            "operation": "search",
            "tenant_id": "tenant-a",
            "workspace_id": "workspace-a",
            "query": "idempotent fact",
            "limit": 3,
        }
    )
    key = "b" * 64

    first = adapter.apply(planned["payload"], operation_key=key)
    second = adapter.apply(planned["payload"], operation_key=key)

    assert second == first
    assert adapter.recover(key) == first

    operation_path = adapter._operation_path(key)
    durable = read_json(operation_path)
    assert durable["signature"]["key_id"] == adapter.state_key_id
    tampered = copy.deepcopy(durable)
    tampered["result"]["side_effects"] = []
    atomic_write_json(operation_path, tampered, mode=0o600)
    with pytest.raises(ProtocolError, match="ADAPTER_OPERATION_KEY_MISMATCH"):
        adapter.recover(key)


def test_research_request_evidence_must_match_exact_query(runtime_fixture) -> None:
    runtime, _, _, request_key, context = runtime_fixture
    request = _signed_request(
        request_key,
        request_id="research-evidence-mismatch",
        nonce="research-evidence-mismatch-nonce",
        capability_id="research.search",
        payload={
            "operation": "search",
            "tenant_id": "tenant-a",
            "workspace_id": "workspace-a",
            "query": "exact query",
            "limit": 3,
        },
        evidence_sha256=["0" * 64],
    )

    with pytest.raises(ProtocolError, match="ADAPTER_EVIDENCE_MISMATCH"):
        runtime.plan(request, context)


def test_search_and_no_evidence_are_applied_without_invention(runtime_fixture) -> None:
    runtime, retriever, _, request_key, context = runtime_fixture
    retriever.index(source_document("workspace-a", "approved fact", "source-a"))
    search = _signed_request(
        request_key,
        request_id="research-search-001",
        nonce="research-search-nonce-001",
        capability_id="research.search",
        payload={
            "operation": "search",
            "tenant_id": "tenant-a",
            "workspace_id": "workspace-a",
            "query": "approved fact",
            "limit": 3,
        },
    )
    plan = runtime.plan(search, context)
    result = runtime.invoke(search, plan, context, approval_document=None)
    assert result["outcome"] == "APPLIED"
    assert result["detail"]["status"] == "SEARCH_COMPLETE"
    assert [item["source_id"] for item in result["evidence_refs"]] == ["source-a"]

    absent = _signed_request(
        request_key,
        request_id="research-ask-absent",
        nonce="research-ask-absent-nonce",
        capability_id="research.ask",
        payload={
            "operation": "ask",
            "tenant_id": "tenant-a",
            "workspace_id": "workspace-a",
            "question": "missing zeppelin",
            "limit": 3,
        },
    )
    absent_plan = runtime.plan(absent, context)
    absent_result = runtime.invoke(
        absent, absent_plan, context, approval_document=None
    )
    assert absent_result["outcome"] == "APPLIED"
    assert absent_result["detail"]["status"] == "NO_EVIDENCE"
    assert absent_result["evidence_refs"] == []
    assert absent_result["detail"]["answer"] is None


def test_research_scope_and_capability_confusion_fail_before_apply(
    runtime_fixture,
) -> None:
    runtime, _, _, request_key, context = runtime_fixture
    payloads = [
        (
            "research.ask",
            {
                "operation": "ask",
                "tenant_id": "tenant-a",
                "workspace_id": "workspace-b",
                "question": "secret other fact",
                "limit": 5,
            },
            "RESEARCH_SCOPE_DENIED",
        ),
        (
            "research.search",
            {
                "operation": "ask",
                "tenant_id": "tenant-a",
                "workspace_id": "workspace-a",
                "question": "approved fact",
                "limit": 5,
            },
            "ADAPTER_CAPABILITY_PAYLOAD_MISMATCH",
        ),
    ]
    for index, (capability, payload, code) in enumerate(payloads, start=1):
        request = _signed_request(
            request_key,
            request_id=f"research-refused-{index}",
            nonce=f"research-refused-nonce-{index}",
            capability_id=capability,
            payload=payload,
        )
        with pytest.raises(ProtocolError, match=code):
            runtime.plan(request, context)


@dataclass(frozen=True)
class _Capability:
    available: bool = True
    reason: str = "AVAILABLE"


class _ForgingProvider:
    def chat_capability(self) -> _Capability:
        return _Capability()

    def chat(self, system: str, user: str) -> str:
        return "invented answer [source:other-workspace]"


def test_model_output_status_and_provider_call_are_retained(
    runtime_fixture, signed_ask_request
) -> None:
    runtime, retriever, adapter, _, context = runtime_fixture
    retriever.index(source_document("workspace-a", "approved fact", "source-a"))
    adapter.ask_hive.provider = _ForgingProvider()
    plan = runtime.plan(signed_ask_request, context)
    result = runtime.invoke(
        signed_ask_request, plan, context, approval_document=None
    )
    assert result["outcome"] == "APPLIED"
    assert result["detail"]["status"] == "MODEL_OUTPUT_REJECTED"
    assert result["detail"]["provider_called"] is True
    assert result["detail"]["answer"] is None


def test_health_export_and_uninstall_preserve_scoped_sources(
    tmp_path: Path, runtime_fixture
) -> None:
    _, retriever, adapter, _, _ = runtime_fixture
    retriever.index(source_document("workspace-a", "approved fact", "source-a"))
    retriever.index(
        source_document("workspace-b", "secret other fact", "source-b")
    )
    health = adapter.health()
    assert health["status"] == "HEALTHY"
    assert health["evidence"][0]["model"]["available"] is False

    export_root = tmp_path / "research-export"
    export_root.mkdir()
    exported = adapter.export(
        {
            "root": str(export_root.resolve()),
            "tenant_id": "tenant-a",
            "workspace_id": "workspace-a",
        },
        operation_key="e" * 64,
    )
    assert exported["outcome"] == "APPLIED"
    exported_sources = json.loads(
        (export_root / "sources.json").read_text(encoding="utf-8")
    )
    assert [item["source_id"] for item in exported_sources["sources"]] == [
        "source-a"
    ]
    assert "secret other fact" not in json.dumps(exported_sources)
    manifest = json.loads(
        (export_root / "manifest.json").read_text(encoding="utf-8")
    )
    for entry in manifest["files"]:
        assert entry["sha256"] == hashlib.sha256(
            (export_root / entry["path"]).read_bytes()
        ).hexdigest()

    assert not callable(getattr(adapter, "uninstall", None))
    assert [
        item.source_id
        for item in retriever.search(
            "approved fact",
            tenant_id="tenant-a",
            workspace_id="workspace-a",
        )
    ] == ["source-a"]
    assert adapter.rollback(
        "research-derived:no-op", operation_key="b" * 64
    )["outcome"] == "NO_OP"
