from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.research import BoundedResearchAdapter
from hive_protocol.ask import AskHive
from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.core import ProtocolError
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.research.artifacts import ResearchArtifactStore
from hive_protocol.research.portable import ResearchPortableService
from hive_protocol.research.query import ResearchQueryService
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.retrieval import LocalRetriever


POLICY = {
    "exact_first": True,
    "semantic_allowed": False,
    "max_results": 10,
    "max_quote_bytes": 2048,
}


def _capture(
    service: CaptureAdmissionService, operation_key: str, text: str, filename: str
) -> dict:
    plan = service.plan_bytes(
        text.encode(),
        tenant_id="tenant:local",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel="MARKDOWN",
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type="text/markdown",
        filename=filename,
        destination="RESEARCH",
    )
    return service.apply(plan, operation_key=operation_key)


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
        created_at="2026-09-01T04:30:00Z",
    )
    amber = _capture(capture, "1" * 64, "The launch color is amber.\n", "amber.md")
    violet = _capture(capture, "2" * 64, "The private code is violet.\n", "violet.md")
    v1 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=None,
        source_ids=[amber["source_id"]],
        retrieval_policy=POLICY,
        created_at="2026-09-01T04:31:00Z",
    )
    v2 = store.update_source_set(
        "research:alpha",
        expected_parent_digest=v1["source_set_digest"],
        source_ids=[amber["source_id"], violet["source_id"]],
        retrieval_policy=POLICY,
        created_at="2026-09-01T04:32:00Z",
    )
    retriever = LocalRetriever(workspace.derived / "retrieval.sqlite3")
    query = ResearchQueryService(store, retriever)
    retrieval_result = AskHive(retriever).ask_research(
        "launch color",
        query_service=query,
        workspace_id="research:alpha",
        source_set_digest=v1["source_set_digest"],
    )
    artifacts = ResearchArtifactStore(
        store,
        tmp_path / "artifact-state",
        signing_key=Ed25519PrivateKey.generate(),
    )
    artifact = artifacts.create_artifact(
        workspace_id="research:alpha",
        source_set_digest=v1["source_set_digest"],
        artifact_type="SOURCE_SUMMARY",
        title="Launch evidence",
        research_result=retrieval_result,
        operation_key="3" * 64,
        created_at="2026-09-01T04:33:00Z",
    )

    store.create_workspace(
        workspace_id="research:other",
        tenant_id="tenant:local",
        project_id="HiveMind",
        name="Unrelated Research",
        privacy_class="PROJECT_PRIVATE",
        created_at="2026-09-01T04:34:00Z",
    )
    other = _capture(capture, "4" * 64, "Unrelated secret source.\n", "other.md")
    other_version = store.update_source_set(
        "research:other",
        expected_parent_digest=None,
        source_ids=[other["source_id"]],
        retrieval_policy=POLICY,
        created_at="2026-09-01T04:35:00Z",
    )
    (workspace.runtime / "secret-journal").mkdir(parents=True)
    (workspace.runtime / "secret-journal" / "operation.json").write_text("private")
    (workspace.derived / "provider-cache.bin").write_bytes(b"provider context")
    (workspace.meta / "keys").mkdir()
    (workspace.meta / "keys" / "private.pem").write_text("not-for-export")
    portable = ResearchPortableService(store)
    return {
        "workspace": workspace,
        "store": store,
        "query": query,
        "artifact": artifact,
        "artifacts": artifacts,
        "portable": portable,
        "v1": v1,
        "v2": v2,
        "other": other,
        "other_version": other_version,
        "amber": amber,
        "violet": violet,
    }


def _workspace_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(root).parts[:2]
        not in {(".hive", "derived"), (".hive", "runtime")}
        and not path.relative_to(root).as_posix().startswith(
            (".hive/index.sqlite3", ".hive/intelligence.sqlite3")
        )
    }


def _archive_members(bundle: Path) -> tuple[dict[str, bytes], dict]:
    with tarfile.open(bundle, "r:gz") as archive:
        members = {
            member.name: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile()
        }
    manifest = json.loads(
        members["hive-research-export/manifest.json"].decode("utf-8")
    )
    return members, manifest


def _write_archive(
    output: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
) -> None:
    with tarfile.open(output, "w:gz") as archive:
        for info, payload in members:
            archive.addfile(info, None if payload is None else io.BytesIO(payload))


def _regular(name: str, payload: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    return info, payload


def test_exact_export_is_deterministic_scoped_and_source_read_only(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    workspace = fixture["workspace"]
    before = _workspace_bytes(workspace.root)
    first = tmp_path / "alpha-1.tar.gz"
    second = tmp_path / "alpha-2.tar.gz"

    result = fixture["portable"].export(
        workspace_id="research:alpha",
        source_set_digest=fixture["v1"]["source_set_digest"],
        output=first,
    )
    fixture["portable"].export(
        workspace_id="research:alpha",
        source_set_digest=fixture["v1"]["source_set_digest"],
        output=second,
    )
    assert first.read_bytes() == second.read_bytes()
    assert result["sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    assert _workspace_bytes(workspace.root) == before

    members, manifest = _archive_members(first)
    member_names = set(members)
    serialized = "\n".join(sorted(member_names))
    assert manifest["workspace_id"] == "research:alpha"
    assert manifest["source_set_digest"] == fixture["v1"]["source_set_digest"]
    assert fixture["amber"]["source_id"].removeprefix("source:") in str(members)
    assert fixture["violet"]["source_id"].removeprefix("source:") not in str(members)
    assert fixture["other"]["source_id"].removeprefix("source:") not in str(members)
    assert fixture["artifact"]["sidecar_path"] in serialized
    for forbidden in (
        ".sqlite",
        "-wal",
        "-shm",
        ".hive/runtime",
        ".hive/derived",
        ".hive/keys",
        "provider-cache",
        "research:other",
    ):
        assert forbidden not in serialized


def test_verified_reopen_rebuilds_exact_query_ask_and_artifact_evidence(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    bundle = tmp_path / "alpha.tar.gz"
    fixture["portable"].export(
        workspace_id="research:alpha",
        source_set_digest=fixture["v1"]["source_set_digest"],
        output=bundle,
    )
    reopened = ResearchPortableService.reopen(bundle, tmp_path / "reopened")
    assert reopened.workspace_id == "research:alpha"
    assert reopened.source_set_digest == fixture["v1"]["source_set_digest"]
    reopened_store = BoundedResearchWorkspaceStore(reopened.workspace)
    reopened_query = ResearchQueryService(
        reopened_store,
        LocalRetriever(reopened.workspace.derived / "retrieval.sqlite3"),
    )
    original_hits = fixture["query"].search(
        "launch color",
        workspace_id="research:alpha",
        source_set_digest=fixture["v1"]["source_set_digest"],
    )
    reopened_hits = reopened_query.search(
        "launch color",
        workspace_id="research:alpha",
        source_set_digest=fixture["v1"]["source_set_digest"],
    )
    assert reopened_hits == original_hits
    answer = AskHive(reopened_query.retriever).ask_research(
        "launch color",
        query_service=reopened_query,
        workspace_id="research:alpha",
        source_set_digest=fixture["v1"]["source_set_digest"],
    )
    assert answer["status"] == "RETRIEVAL_ONLY"
    verifier = ResearchArtifactStore(
        reopened_store,
        tmp_path / "reopened-artifact-state",
        signing_key=Ed25519PrivateKey.generate(),
    )
    verified_artifact = verifier.verify_artifact(
        "research:alpha", fixture["artifact"]["artifact_id"]
    )
    assert verified_artifact.source_set_digest == fixture["v1"]["source_set_digest"]
    assert (reopened.workspace.root / verified_artifact.markdown_path).read_bytes() == (
        fixture["workspace"].root / fixture["artifact"]["markdown_path"]
    ).read_bytes()


def test_reopen_refuses_traversal_links_duplicates_types_limits_and_nonempty(
    tmp_path: Path, monkeypatch
) -> None:
    fixture = _fixture(tmp_path)
    valid = tmp_path / "valid.tar.gz"
    fixture["portable"].export(
        workspace_id="research:alpha",
        source_set_digest=fixture["v1"]["source_set_digest"],
        output=valid,
    )
    payloads, _ = _archive_members(valid)
    regular_members = [_regular(name, payload) for name, payload in payloads.items()]

    bad_cases: list[tuple[str, list[tuple[tarfile.TarInfo, bytes | None]], str]] = []
    bad_cases.append(
        (
            "traversal",
            [*regular_members, _regular("hive-research-export/../escape", b"x")],
            "RESEARCH_BUNDLE_PATH",
        )
    )
    link = tarfile.TarInfo("hive-research-export/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/tmp/escape"
    bad_cases.append(("link", [*regular_members, (link, None)], "RESEARCH_BUNDLE_MEMBER"))
    bad_cases.append(
        (
            "duplicate",
            [*regular_members, regular_members[0]],
            "RESEARCH_BUNDLE_DUPLICATE",
        )
    )
    directory = tarfile.TarInfo("hive-research-export/directory")
    directory.type = tarfile.DIRTYPE
    bad_cases.append(
        ("directory", [*regular_members, (directory, None)], "RESEARCH_BUNDLE_MEMBER")
    )
    bad_cases.append(
        (
            "extra",
            [*regular_members, _regular("hive-research-export/extra.txt", b"x")],
            "RESEARCH_BUNDLE_FILE_SET",
        )
    )
    missing_members = regular_members[:-1]
    bad_cases.append(("missing", missing_members, "RESEARCH_BUNDLE_FILE_SET"))
    case_name, case_payload = regular_members[-1]
    collision = _regular(case_name.name.upper(), case_payload)
    bad_cases.append(
        (
            "case-collision",
            [*regular_members, collision],
            "RESEARCH_BUNDLE_CASE_COLLISION",
        )
    )
    manifest_name = "hive-research-export/manifest.json"
    tampered = dict(payloads)
    manifest = json.loads(tampered[manifest_name])
    manifest["files"][0]["sha256"] = "0" * 64
    tampered[manifest_name] = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    bad_cases.append(
        (
            "manifest",
            [_regular(name, payload) for name, payload in tampered.items()],
            "RESEARCH_BUNDLE_HASH",
        )
    )

    for name, members, error in bad_cases:
        bundle = tmp_path / f"bad-{name}.tar.gz"
        _write_archive(bundle, members)
        with pytest.raises(ProtocolError, match=error):
            ResearchPortableService.reopen(bundle, tmp_path / f"target-{name}")

    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "sentinel").write_text("preserve")
    with pytest.raises(ProtocolError, match="RESEARCH_REOPEN_TARGET_NOT_EMPTY"):
        ResearchPortableService.reopen(valid, nonempty)
    assert (nonempty / "sentinel").read_text() == "preserve"

    import hive_protocol.research.portable as portable_module

    monkeypatch.setattr(portable_module, "MAX_MEMBER_BYTES", 16)
    with pytest.raises(ProtocolError, match="RESEARCH_BUNDLE_LIMIT"):
        ResearchPortableService.reopen(valid, tmp_path / "target-limit")


def test_whole_hive_export_inventory_accepts_m31_records_and_receipts(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    bundle = tmp_path / "whole-hive.tar.gz"
    fixture["workspace"].export(bundle)
    reopened = HiveWorkspace.reopen_export(bundle, tmp_path / "whole-reopened")
    assert reopened.research.is_dir()
    reopened_store = BoundedResearchWorkspaceStore(reopened)
    assert reopened_store.verify_source_set(
        "research:alpha", fixture["v1"]["source_set_digest"]
    ).workspace_id == "research:alpha"


def test_bounded_adapter_exports_one_exact_portable_source_set(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    adapter = BoundedResearchAdapter(
        fixture["query"].retriever,
        AskHive(fixture["query"].retriever),
        tenant_id="tenant:local",
        workspace_id="research:alpha",
        project_id="HiveMind",
        state_root=tmp_path / "research-state",
        state_signing_key=Ed25519PrivateKey.generate(),
        research_query_service=fixture["query"],
        portable_service=fixture["portable"],
    )
    bundle = tmp_path / "adapter-portable.tar.gz"
    result = adapter.export(
        {
            "bundle": str(bundle.resolve()),
            "workspace_id": "research:alpha",
            "source_set_digest": fixture["v1"]["source_set_digest"],
        },
        operation_key="6" * 64,
    )
    assert result["outcome"] == "APPLIED"
    assert result["detail"]["source_set_digest"] == fixture["v1"][
        "source_set_digest"
    ]
    assert bundle.is_file()
