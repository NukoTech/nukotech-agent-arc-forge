from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.adapters.research import BoundedResearchAdapter
from hive_protocol.ask import AskHive
from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.core import ProtocolError, document_digest
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.research.artifacts import ResearchArtifactStore
from hive_protocol.research.query import ResearchQueryService
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.retrieval import LocalRetriever
from hive_protocol.storage import read_json


POLICY = {
    "exact_first": True,
    "semantic_allowed": False,
    "max_results": 10,
    "max_quote_bytes": 2048,
}
ARTIFACT_TYPES = (
    "CITED_ANSWER",
    "SOURCE_SUMMARY",
    "COMPARISON",
    "TIMELINE",
    "BRIEF",
    "QUESTIONS",
    "OUTLINE",
    "STUDY_GUIDE",
    "ACTION_ITEMS",
)


def _fixture(tmp_path: Path, *texts: str):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    capture = CaptureAdmissionService(
        workspace,
        tmp_path / "capture-state",
        registry=NormalizerRegistry(),
        signing_key=Ed25519PrivateKey.generate(),
    )
    workspace_store = BoundedResearchWorkspaceStore(workspace)
    workspace_store.create_workspace(
        workspace_id="research:alpha",
        tenant_id="tenant:local",
        project_id="HiveMind",
        name="Alpha Research",
        privacy_class="PROJECT_PRIVATE",
    )
    source_ids: list[str] = []
    for index, source_text in enumerate(texts, start=1):
        plan = capture.plan_bytes(
            source_text.encode(),
            tenant_id="tenant:local",
            project_id="HiveMind",
            privacy_class="PROJECT_PRIVATE",
            channel="MARKDOWN",
            source_owner="Owner",
            rights_assertion="USER_PROVIDED",
            media_type="text/markdown",
            filename=f"artifact-source-{index}.md",
            destination="RESEARCH",
        )
        source_ids.append(
            capture.apply(plan, operation_key=f"{index:x}" * 64)["source_id"]
        )
    version = workspace_store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=source_ids,
        retrieval_policy=POLICY,
        created_at="2026-08-31T23:00:00-05:00",
    )
    retriever = LocalRetriever(workspace.derived / "retrieval.sqlite3")
    query = ResearchQueryService(workspace_store, retriever)
    artifacts = ResearchArtifactStore(
        workspace_store,
        tmp_path / "artifact-state",
        signing_key=Ed25519PrivateKey.generate(),
    )
    return workspace, workspace_store, retriever, query, artifacts, version


def _retrieval_result(query: ResearchQueryService, version: dict) -> dict:
    return AskHive(query.retriever).ask_research(
        "launch color",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )


def test_all_artifact_types_have_deterministic_ids_and_digests(tmp_path: Path) -> None:
    _, _, _, query, artifacts, version = _fixture(
        tmp_path, "The launch color is amber.\n"
    )
    research_result = _retrieval_result(query, version)
    seen: set[str] = set()

    for index, artifact_type in enumerate(ARTIFACT_TYPES, start=1):
        operation_key = f"{index:x}" * 64
        first = artifacts.create_artifact(
            workspace_id="research:alpha",
            source_set_digest=version["source_set_digest"],
            artifact_type=artifact_type,
            title=f"Artifact {index}",
            research_result=research_result,
            operation_key=operation_key,
            created_at="2026-08-31T23:01:00-05:00",
        )
        replay = artifacts.create_artifact(
            workspace_id="research:alpha",
            source_set_digest=version["source_set_digest"],
            artifact_type=artifact_type,
            title=f"Artifact {index}",
            research_result=research_result,
            operation_key=operation_key,
            created_at="2026-08-31T23:01:00-05:00",
        )
        assert first == replay
        assert first["artifact_id"].startswith("artifact:")
        assert len(first["artifact_digest"]) == 64
        assert first["artifact_id"] not in seen
        seen.add(first["artifact_id"])


def test_retrieval_only_pack_is_canonical_and_clearly_labeled(tmp_path: Path) -> None:
    workspace, _, _, query, artifacts, version = _fixture(
        tmp_path, "The launch color is amber.\n"
    )
    result = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
        artifact_type="SOURCE_SUMMARY",
        title="Launch evidence",
        research_result=_retrieval_result(query, version),
        operation_key="a" * 64,
        created_at="2026-08-31T23:02:00-05:00",
    )

    markdown = (workspace.root / result["markdown_path"]).read_text()
    sidecar = read_json(workspace.root / result["sidecar_path"])
    assert "RETRIEVAL ONLY — no model answer generated" in markdown
    assert "[cite:anchor:" in markdown
    assert sidecar["status"] == "RETRIEVAL_ONLY"
    assert sidecar["verification_state"] == "RETRIEVAL_VERIFIED"
    assert sidecar["claims"][0]["uncertainty"] == "RETRIEVAL_ONLY_EVIDENCE"


def test_model_artifact_rechecks_claims_anchors_and_exact_source_set(
    tmp_path: Path,
) -> None:
    _, _, _, query, artifacts, version = _fixture(
        tmp_path, "The launch color is amber.\n"
    )
    retrieval = _retrieval_result(query, version)
    anchor_id = retrieval["citations"][0]["anchor_id"]
    answered = {
        **retrieval,
        "status": "ANSWERED",
        "answer": f"The launch color is amber. [cite:{anchor_id}]",
        "provider_called": True,
        "claims": [
            {
                "text": "The launch color is amber.",
                "citation_anchor_ids": [anchor_id],
                "uncertainty": None,
            }
        ],
    }
    created = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
        artifact_type="CITED_ANSWER",
        title="Verified answer",
        research_result=answered,
        operation_key="b" * 64,
        created_at="2026-08-31T23:03:00-05:00",
        generator_id="test-provider",
    )
    assert created["status"] == "ANSWERED"

    for index, mutation in enumerate(("claim", "anchor", "source_set"), start=12):
        invalid = copy.deepcopy(answered)
        source_set_digest = version["source_set_digest"]
        if mutation == "claim":
            invalid["claims"][0]["text"] = "The launch color is blue."
        elif mutation == "anchor":
            invalid["claims"][0]["citation_anchor_ids"] = ["anchor:" + "f" * 64]
        else:
            invalid["source_set_digest"] = "e" * 64
        with pytest.raises(ProtocolError, match="RESEARCH_ARTIFACT_"):
            artifacts.create_artifact(
                workspace_id="research:alpha",
                source_set_digest=source_set_digest,
                artifact_type="CITED_ANSWER",
                title="Rejected",
                research_result=invalid,
                operation_key=f"{index:x}" * 64,
                created_at="2026-08-31T23:03:00-05:00",
            )


def test_contradictions_and_uncertainties_are_retained(tmp_path: Path) -> None:
    workspace, _, _, query, artifacts, version = _fixture(
        tmp_path,
        "The status is approved.\n",
        "The status is not approved.\n",
    )
    citations = query.search(
        "status approved",
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    result = {
        "source_set_digest": version["source_set_digest"],
        "status": "MODEL_OUTPUT_REJECTED",
        "grounded": False,
        "answer": None,
        "provider_called": True,
        "reason": "UNSUPPORTED_CLAIM",
        "citations": citations,
        "claims": [],
        "contradictions": [
            {
                "reason": "EXPLICIT_NEGATION_CONFLICT",
                "citation_anchor_ids": [item["anchor_id"] for item in citations],
            }
        ],
        "uncertainties": [
            {
                "reason": "UNSUPPORTED_CLAIM",
                "text": "A model claim was not supported and was rejected.",
            }
        ],
    }
    created = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
        artifact_type="BRIEF",
        title="Rejected synthesis record",
        research_result=result,
        operation_key="c" * 64,
        created_at="2026-08-31T23:04:00-05:00",
    )
    sidecar = read_json(workspace.root / created["sidecar_path"])
    assert sidecar["contradictions"] == result["contradictions"]
    assert result["uncertainties"][0] in sidecar["uncertainties"]
    assert "UNSUPPORTED_CLAIM" in (
        workspace.root / created["markdown_path"]
    ).read_text()


def test_source_set_versions_cannot_overwrite_each_other(tmp_path: Path) -> None:
    workspace, workspace_store, _, query, artifacts, version = _fixture(
        tmp_path, "The launch color is amber.\n"
    )
    old = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
        artifact_type="SOURCE_SUMMARY",
        title="Versioned evidence",
        research_result=_retrieval_result(query, version),
        operation_key="d" * 64,
        created_at="2026-08-31T23:05:00-05:00",
    )
    old_bytes = (workspace.root / old["sidecar_path"]).read_bytes()
    v2 = workspace_store.update_source_set(
        "research:alpha",
        expected_parent_digest=version["source_set_digest"],
        source_ids=[item["source_id"] for item in version["source_set"].sources],
        retrieval_policy=POLICY,
        created_at="2026-08-31T23:06:00-05:00",
    )
    new = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=v2["source_set_digest"],
        artifact_type="SOURCE_SUMMARY",
        title="Versioned evidence",
        research_result=_retrieval_result(query, v2),
        operation_key="e" * 64,
        created_at="2026-08-31T23:06:01-05:00",
    )
    assert new["artifact_id"] != old["artifact_id"]
    assert (workspace.root / old["sidecar_path"]).read_bytes() == old_bytes


def test_artifact_sidecar_is_content_addressed_and_tamper_evident(
    tmp_path: Path,
) -> None:
    workspace, _, _, query, artifacts, version = _fixture(
        tmp_path, "The launch color is amber.\n"
    )
    created = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
        artifact_type="SOURCE_SUMMARY",
        title="Tamper evidence",
        research_result=_retrieval_result(query, version),
        operation_key="7" * 64,
        created_at="2026-08-31T23:06:30-05:00",
    )
    sidecar_path = workspace.root / created["sidecar_path"]
    sidecar = read_json(sidecar_path)
    sidecar["claims"][0]["uncertainty"] = "MUTATED"
    sidecar_path.write_text(
        json.dumps(sidecar, sort_keys=True, separators=(",", ":")) + "\n"
    )
    with pytest.raises(ProtocolError, match="RESEARCH_ARTIFACT_DRIFT"):
        artifacts.verify_artifact("research:alpha", created["artifact_id"])


def test_crash_recovery_replay_and_exact_rollback(tmp_path: Path, monkeypatch) -> None:
    workspace, _, _, query, artifacts, version = _fixture(
        tmp_path, "The launch color is amber.\n"
    )
    operation_key = "f" * 64
    original_hook = artifacts._after_stage

    def crash(stage: str) -> None:
        if stage == "RECEIPT_WRITTEN":
            raise RuntimeError("simulated crash")

    monkeypatch.setattr(artifacts, "_after_stage", crash)
    with pytest.raises(RuntimeError, match="simulated crash"):
        artifacts.create_artifact(
            workspace_id="research:alpha",
            source_set_digest=version["source_set_digest"],
            artifact_type="SOURCE_SUMMARY",
            title="Crash-safe evidence",
            research_result=_retrieval_result(query, version),
            operation_key=operation_key,
            created_at="2026-08-31T23:07:00-05:00",
        )
    monkeypatch.setattr(artifacts, "_after_stage", original_hook)
    recovered = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
        artifact_type="SOURCE_SUMMARY",
        title="Crash-safe evidence",
        research_result=_retrieval_result(query, version),
        operation_key=operation_key,
        created_at="2026-08-31T23:07:00-05:00",
    )
    before = {
        name: (workspace.root / recovered[name]).read_bytes()
        for name in ("markdown_path", "sidecar_path", "receipt_path")
    }
    replay = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
        artifact_type="SOURCE_SUMMARY",
        title="Crash-safe evidence",
        research_result=_retrieval_result(query, version),
        operation_key=operation_key,
        created_at="2026-08-31T23:07:00-05:00",
    )
    assert replay == recovered
    assert before == {
        name: (workspace.root / recovered[name]).read_bytes()
        for name in ("markdown_path", "sidecar_path", "receipt_path")
    }

    rolled_back = artifacts.rollback(operation_key)
    assert rolled_back["outcome"] == "ROLLED_BACK"
    assert artifacts.rollback(operation_key) == rolled_back
    for name in ("markdown_path", "sidecar_path", "receipt_path"):
        assert not (workspace.root / recovered[name]).exists()
    assert workspace_store_source_files(workspace)


def test_bounded_adapter_exposes_exact_offline_artifact_capability(
    tmp_path: Path,
) -> None:
    workspace, _, retriever, query, artifacts, version = _fixture(
        tmp_path, "The launch color is amber.\n"
    )
    research_result = _retrieval_result(query, version)
    adapter = BoundedResearchAdapter(
        retriever,
        AskHive(retriever),
        tenant_id="tenant:local",
        workspace_id="research:alpha",
        project_id="HiveMind",
        state_root=tmp_path / "research-state",
        state_signing_key=Ed25519PrivateKey.generate(),
        research_query_service=query,
        artifact_store=artifacts,
    )
    payload = {
        "operation": "artifact",
        "tenant_id": "tenant:local",
        "workspace_id": "research:alpha",
        "source_set_digest": version["source_set_digest"],
        "artifact_type": "SOURCE_SUMMARY",
        "title": "Adapter artifact",
        "research_result": research_result,
    }
    request = AdapterRequest(
        request_id="request:artifact",
        adapter_id="nukotech.hive.bounded-research",
        adapter_version="1.0.0",
        sender={"persona_id": "Director", "surface_id": "LeadA"},
        project_id="HiveMind",
        capability_id="research.artifact",
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:research",
        evidence_sha256=[
            document_digest(research_result),
            version["source_set_digest"],
        ],
        payload=payload,
        nonce="nonce:artifact",
        expires_at="2026-09-01T05:00:00Z",
    )
    adapter.validate_request(request)
    adapter.validate_evidence(request)
    plan = adapter.plan(payload)
    assert plan["network_destinations"] == []
    result = adapter.apply(payload, operation_key="9" * 64)
    assert result["outcome"] == "APPLIED"
    assert result["rollback_ref"] == "research-artifact:" + "9" * 64
    assert (workspace.root / result["detail"]["sidecar_path"]).is_file()

    rollback = adapter.rollback(result["rollback_ref"], operation_key="8" * 64)
    assert rollback["outcome"] == "ROLLED_BACK"
    manifest = json.loads(
        (
            Path(__file__).parents[1]
            / "src/hive_protocol/adapters/research/bounded-research.manifest.json"
        ).read_text()
    )
    assert "research.artifact" in manifest["capability_ids"]
    assert "filesystem.write.workspace" in manifest["required_permissions"]
    assert manifest["network_destinations"] == []


def workspace_store_source_files(workspace: HiveWorkspace) -> list[Path]:
    return [path for path in workspace.sources.rglob("*") if path.is_file()]
