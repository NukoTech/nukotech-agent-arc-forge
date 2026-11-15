from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.core import ProtocolError
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.storage import atomic_write_json, read_json


POLICY = {
    "exact_first": True,
    "semantic_allowed": False,
    "max_results": 10,
    "max_quote_bytes": 2048,
}


def _fixture(tmp_path: Path):
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
    return workspace, capture, store


def _capture(capture: CaptureAdmissionService, key: str, text: str) -> dict:
    plan = capture.plan_bytes(
        text.encode(),
        tenant_id="tenant:local",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel="MARKDOWN",
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type="text/markdown",
        filename=f"{key}.md",
        destination="RESEARCH",
    )
    return capture.apply(plan, operation_key=key * 64)


def test_workspace_creation_is_immutable_and_scope_bound(tmp_path: Path) -> None:
    _, _, store = _fixture(tmp_path)
    first = store.open_workspace("research:alpha")
    replay = store.create_workspace(
        workspace_id="research:alpha",
        tenant_id="tenant:local",
        project_id="HiveMind",
        name="Alpha Research",
        privacy_class="PROJECT_PRIVATE",
    )
    assert replay == first

    with pytest.raises(ProtocolError, match="RESEARCH_WORKSPACE_MISMATCH"):
        store.create_workspace(
            workspace_id="research:alpha",
            tenant_id="tenant:other",
            project_id="Other",
            name="Mutated",
            privacy_class="NON_PRIVATE",
        )


def test_add_remove_refresh_creates_immutable_parent_linked_versions(tmp_path: Path) -> None:
    workspace, capture, store = _fixture(tmp_path)
    alpha = _capture(capture, "a", "alpha evidence\n")
    beta = _capture(capture, "b", "beta evidence\n")

    v1 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=[alpha["source_id"]],
        retrieval_policy=POLICY,
    )
    v2 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=v1["source_set_digest"],
        source_ids=[alpha["source_id"], beta["source_id"]],
        retrieval_policy=POLICY,
    )
    v3 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=v2["source_set_digest"],
        source_ids=[beta["source_id"]],
        retrieval_policy=POLICY,
    )
    refreshed = store.update_source_set(
        "research:alpha",
        expected_parent_digest=v3["source_set_digest"],
        source_ids=[beta["source_id"]],
        retrieval_policy=POLICY,
    )

    assert v2["source_set"].parent_digest == v1["source_set_digest"]
    assert v3["source_set"].parent_digest == v2["source_set_digest"]
    assert refreshed["source_set_digest"] != v3["source_set_digest"]
    assert (workspace.root / alpha["asset_path"]).is_file()
    assert (workspace.root / alpha["source_record_path"]).is_file()
    assert store.verify_source_set("research:alpha", v1["source_set_digest"]) == v1[
        "source_set"
    ]


def test_old_version_uses_exact_source_record_snapshot_after_new_capture(tmp_path: Path) -> None:
    _, capture, store = _fixture(tmp_path)
    alpha = _capture(capture, "c", "shared evidence\n")
    v1 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=[alpha["source_id"]],
        retrieval_policy=POLICY,
    )
    original_record_digest = v1["source_set"].sources[0]["source_record_digest"]

    _capture(capture, "d", "shared evidence\n")
    current_record = read_json(store.source_record_path(alpha["source_id"]))
    assert store.source_record_digest(current_record) != original_record_digest
    assert store.verify_source_set("research:alpha", v1["source_set_digest"]) == v1[
        "source_set"
    ]


def test_stale_duplicate_absent_cross_project_and_tampered_sources_refuse(tmp_path: Path) -> None:
    workspace, capture, store = _fixture(tmp_path)
    alpha = _capture(capture, "e", "alpha evidence\n")
    v1 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=[alpha["source_id"]],
        retrieval_policy=POLICY,
    )
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SET_STALE"):
        store.update_source_set(
            "research:alpha",
            expected_parent_digest=None,
            source_ids=[alpha["source_id"]],
            retrieval_policy=POLICY,
        )
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SET_NONCANONICAL"):
        store.update_source_set(
            "research:alpha",
            expected_parent_digest=v1["source_set_digest"],
            source_ids=[alpha["source_id"], alpha["source_id"]],
            retrieval_policy=POLICY,
        )
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_ABSENT"):
        store.update_source_set(
            "research:alpha",
            expected_parent_digest=v1["source_set_digest"],
            source_ids=["source:" + "0" * 64],
            retrieval_policy=POLICY,
        )

    record_path = store.source_record_path(alpha["source_id"])
    record = read_json(record_path)
    cross_project = copy.deepcopy(record)
    cross_project["project_id"] = "Other"
    atomic_write_json(record_path, cross_project)
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SCOPE_MISMATCH"):
        store.update_source_set(
            "research:alpha",
            expected_parent_digest=v1["source_set_digest"],
            source_ids=[alpha["source_id"]],
            retrieval_policy=POLICY,
        )
    atomic_write_json(record_path, record)
    normalized = workspace.root / str(record["normalized_text_path"])
    normalized.write_text("tampered", encoding="utf-8")
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_DRIFT"):
        store.update_source_set(
            "research:alpha",
            expected_parent_digest=v1["source_set_digest"],
            source_ids=[alpha["source_id"]],
            retrieval_policy=POLICY,
        )


def test_concurrent_updates_serialize_and_rewrite_or_symlink_is_refused(tmp_path: Path) -> None:
    _, capture, store = _fixture(tmp_path)
    alpha = _capture(capture, "f", "alpha\n")
    beta = _capture(capture, "1", "beta\n")

    def update(source_id: str):
        return store.update_source_set(
            "research:alpha",
            expected_parent_digest=None,
            source_ids=[source_id],
            retrieval_policy=POLICY,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(update, source) for source in (alpha["source_id"], beta["source_id"])]
    outcomes = []
    for future in futures:
        try:
            outcomes.append(future.result()["source_set_digest"])
        except ProtocolError as exc:
            assert exc.code == "RESEARCH_SOURCE_SET_STALE"
    assert len(outcomes) == 1

    head = store.current_source_set("research:alpha")
    assert head is not None
    path = store.source_set_path("research:alpha", head["source_set_digest"])
    document = read_json(path)
    document["created_at"] = "2026-01-01T00:00:00Z"
    atomic_write_json(path, document)
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SET_DIGEST_MISMATCH"):
        store.current_source_set("research:alpha")


def test_source_set_verifies_without_derived_indexes(tmp_path: Path) -> None:
    workspace, capture, store = _fixture(tmp_path)
    alpha = _capture(capture, "2", "offline evidence\n")
    version = store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=[alpha["source_id"]],
        retrieval_policy=POLICY,
    )
    for path in (workspace.index_path, workspace.intelligence_index_path):
        if path.exists():
            path.unlink()
    assert store.verify_source_set(
        "research:alpha", version["source_set_digest"]
    ) == version["source_set"]


def test_source_set_symlink_is_refused(tmp_path: Path) -> None:
    _, capture, store = _fixture(tmp_path)
    alpha = _capture(capture, "3", "symlink evidence\n")
    version = store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=[alpha["source_id"]],
        retrieval_policy=POLICY,
    )
    path = store.source_set_path("research:alpha", version["source_set_digest"])
    outside = tmp_path / "outside.json"
    path.rename(outside)
    path.symlink_to(outside)
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SET_DIGEST_MISMATCH"):
        store.verify_source_set("research:alpha", version["source_set_digest"])
