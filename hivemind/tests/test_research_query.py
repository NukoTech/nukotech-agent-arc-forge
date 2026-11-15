from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.research import BoundedResearchAdapter
from hive_protocol.ask import AskHive
from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.core import ProtocolError
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.research.query import ResearchQueryService
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.retrieval import LocalRetriever, SourceDocument


POLICY = {
    "exact_first": True,
    "semantic_allowed": False,
    "max_results": 10,
    "max_quote_bytes": 2048,
}


@dataclass(frozen=True)
class _Capability:
    available: bool = True
    reason: str = "AVAILABLE"


class _Provider:
    def __init__(self, answer: str | Exception, *, available: bool = True):
        self.answer = answer
        self.available = available
        self.calls = 0

    def chat_capability(self):
        return _Capability(self.available, "AVAILABLE" if self.available else "NO_MODEL")

    def chat(self, system: str, user: str) -> str:
        self.calls += 1
        assert "[cite:anchor:" in system
        assert "<anchor" in user
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _fixture(tmp_path: Path, *texts: str):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    capture = CaptureAdmissionService(
        workspace,
        tmp_path / "capture-state",
        registry=NormalizerRegistry(),
        signing_key=Ed25519PrivateKey.generate(),
    )
    store = BoundedResearchWorkspaceStore(workspace)
    store.create_workspace(
        workspace_id="research:alpha",
        tenant_id="tenant:local",
        project_id="HiveMind",
        name="Alpha Research",
        privacy_class="PROJECT_PRIVATE",
    )
    source_ids = []
    for index, text in enumerate(texts, start=1):
        key = f"{index:x}" * 64
        plan = capture.plan_bytes(
            text.encode(),
            tenant_id="tenant:local",
            project_id="HiveMind",
            privacy_class="PROJECT_PRIVATE",
            channel="MARKDOWN",
            source_owner="Owner",
            rights_assertion="USER_PROVIDED",
            media_type="text/markdown",
            filename=f"source-{index}.md",
            destination="RESEARCH",
        )
        source_ids.append(capture.apply(plan, operation_key=key)["source_id"])
    version = store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=source_ids,
        retrieval_policy=POLICY,
    )
    retriever = LocalRetriever(workspace.derived / "retrieval.sqlite3")
    query = ResearchQueryService(store, retriever)
    return workspace, store, retriever, query, version


def test_search_is_source_set_isolated_and_returns_exact_anchors(tmp_path: Path) -> None:
    _, store, retriever, query, v1 = _fixture(
        tmp_path, "The launch color is amber.\n", "The private code is violet.\n"
    )
    first_source = query.search(
        "launch color",
        workspace_id="research:alpha",
        source_set_digest=v1["source_set_digest"],
    )[0]["source_id"]
    v2 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=v1["source_set_digest"],
        source_ids=[first_source],
        retrieval_policy=POLICY,
    )
    retriever.index(
        SourceDocument(
            tenant_id="tenant:local",
            workspace_id=f"research:alpha@{v2['source_set_digest']}",
            source_id="source:" + "f" * 64,
            source_path="adversarial.md",
            content="The launch color is stolen.",
            sha256=hashlib.sha256(b"The launch color is stolen.").hexdigest(),
            provenance={"kind": "adversarial-index-row"},
        )
    )

    hits = query.search(
        "launch color",
        workspace_id="research:alpha",
        source_set_digest=v2["source_set_digest"],
    )
    assert len(hits) == 1
    assert hits[0]["source_id"] == first_source
    assert hits[0]["anchor_id"].startswith("anchor:")
    assert hits[0]["source_record_digest"] == v2["source_set"].sources[0][
        "source_record_digest"
    ]
    assert hits[0]["quote"] == "The launch color is amber."
    assert "stolen" not in str(hits)


def test_no_hits_and_absent_provider_degrade_without_invention(tmp_path: Path) -> None:
    _, _, retriever, query, version = _fixture(tmp_path, "Grounded local evidence.\n")
    ask = AskHive(retriever)
    absent = ask.ask_research(
        "missing zephyr",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    assert absent["status"] == "NO_EVIDENCE"
    assert absent["provider_called"] is False

    retrieval_only = ask.ask_research(
        "local evidence",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    assert retrieval_only["status"] == "RETRIEVAL_ONLY"
    assert retrieval_only["answer"] is None
    assert retrieval_only["citations"][0]["anchor_id"].startswith("anchor:")


def test_answer_requires_supported_exact_in_set_anchor_on_every_span(tmp_path: Path) -> None:
    _, _, retriever, query, version = _fixture(tmp_path, "The launch color is amber.\n")
    hit = query.search(
        "launch color",
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )[0]
    citation = f"[cite:{hit['anchor_id']}]"

    answered = AskHive(
        retriever, _Provider(f"The launch color is amber. {citation}")
    ).ask_research(
        "launch color",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    assert answered["status"] == "ANSWERED"
    assert answered["claims"][0]["citation_anchor_ids"] == [hit["anchor_id"]]

    for output, reason in [
        ("The launch color is amber.", "MISSING_CITATION"),
        (
            f"The launch color is amber. The launch color is amber. {citation}",
            "MISSING_CITATION",
        ),
        ("The launch color is amber. [cite:anchor:" + "0" * 64 + "]", "UNKNOWN_CITATION"),
        (f"The launch color is blue. {citation}", "UNSUPPORTED_CLAIM"),
    ]:
        rejected = AskHive(retriever, _Provider(output)).ask_research(
            "launch color",
            query_service=query,
            workspace_id="research:alpha",
            source_set_digest=version["source_set_digest"],
        )
        assert rejected["status"] == "MODEL_OUTPUT_REJECTED"
        assert rejected["reason"] == reason
        assert rejected["answer"] is None


def test_provider_failure_and_oversized_output_are_bounded(tmp_path: Path) -> None:
    _, _, retriever, query, version = _fixture(tmp_path, "Bounded evidence exists.\n")
    failed = AskHive(retriever, _Provider(RuntimeError("provider failed"))).ask_research(
        "bounded evidence",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    assert failed["status"] == "DEGRADED"
    assert failed["answer"] is None

    oversized = AskHive(retriever, _Provider("x" * 40_000)).ask_research(
        "bounded evidence",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    assert oversized["status"] == "MODEL_OUTPUT_REJECTED"
    assert oversized["reason"] == "OUTPUT_LIMIT"


def test_explicitly_conflicting_cited_spans_remain_visible(tmp_path: Path) -> None:
    _, _, retriever, query, version = _fixture(
        tmp_path,
        "The status is approved.\n",
        "The status is not approved.\n",
    )
    hits = query.search(
        "status approved",
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    answer = "\n".join(
        f"{hit['quote']} [cite:{hit['anchor_id']}]" for hit in hits
    )
    result = AskHive(retriever, _Provider(answer)).ask_research(
        "status approved",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=version["source_set_digest"],
    )
    assert result["status"] == "ANSWERED"
    assert result["contradictions"]


def test_bounded_adapter_binds_search_and_ask_to_exact_source_set(tmp_path: Path) -> None:
    _, _, retriever, query, version = _fixture(tmp_path, "Adapter bound evidence.\n")
    adapter = BoundedResearchAdapter(
        retriever,
        AskHive(retriever),
        tenant_id="tenant:local",
        workspace_id="research:alpha",
        project_id="HiveMind",
        state_root=tmp_path / "research-state",
        state_signing_key=Ed25519PrivateKey.generate(),
        research_query_service=query,
    )
    payload = {
        "operation": "search",
        "tenant_id": "tenant:local",
        "workspace_id": "research:alpha",
        "source_set_digest": version["source_set_digest"],
        "query": "bound evidence",
        "limit": 5,
    }
    planned = adapter.plan(payload)
    result = adapter.apply(planned["payload"], operation_key="a" * 64)
    assert result["detail"]["source_set_digest"] == version["source_set_digest"]
    assert result["evidence_refs"][0]["anchor_id"].startswith("anchor:")

    wrong = dict(payload)
    wrong["source_set_digest"] = "0" * 64
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SET_ABSENT"):
        adapter.plan(wrong)
