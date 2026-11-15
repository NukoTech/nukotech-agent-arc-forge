from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.core import ProtocolError
from hive_protocol.knowledge.editor import KnowledgeEditor
from hive_protocol.product.workspace import HiveWorkspace


NOW = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)


def _editor(root: Path, *, fault_hook=None) -> KnowledgeEditor:
    HiveWorkspace.create(root)
    authority = CognitionAuthority(root, trusted_reviewer_actors={"Owner"})
    return KnowledgeEditor(root, authority, fault_hook=fault_hook)


def test_preview_and_apply_create_one_canonical_markdown_note(tmp_path: Path) -> None:
    editor = _editor(tmp_path)
    content = "# Alpha\n\n#architecture\n\n- supports [[MOC HiveMind]]\n\n[anchor:alpha]\n"
    preview = editor.preview(
        project_id="HiveMind",
        relative_path="notes/alpha.md",
        content=content,
        expected_sha256=None,
        now=NOW,
    )
    assert preview["operation"] == "CREATE"
    assert preview["parsed"] == {
        "wikilinks": ["MOC HiveMind"],
        "typed_links": [{"relation": "supports", "target": "MOC HiveMind"}],
        "tags": ["architecture"],
        "citation_anchor_ids": ["anchor:alpha"],
        "is_moc": False,
    }
    result = editor.apply(
        preview["preview_id"],
        content=content,
        idempotency_key="a" * 64,
        approval=None,
        now=NOW,
    )
    note = tmp_path / result["relative_path"]
    assert result["outcome"] == "APPLIED"
    assert note.read_text(encoding="utf-8") == content
    assert result["sha256"] == hashlib.sha256(content.encode()).hexdigest()
    assert editor.apply(
        preview["preview_id"],
        content=content,
        idempotency_key="a" * 64,
        approval=None,
        now=NOW,
    ) == result


def test_update_requires_exact_expected_digest_and_separate_approval(tmp_path: Path) -> None:
    editor = _editor(tmp_path)
    first = "# Alpha\n"
    create = editor.preview(
        project_id="HiveMind",
        relative_path="alpha.md",
        content=first,
        expected_sha256=None,
        now=NOW,
    )
    created = editor.apply(
        create["preview_id"], content=first, idempotency_key="b" * 64, approval=None, now=NOW
    )
    second = "# Alpha\n\nCorrected.\n"
    update = editor.preview(
        project_id="HiveMind",
        relative_path="alpha.md",
        content=second,
        expected_sha256=created["sha256"],
        now=NOW,
    )
    with pytest.raises(ProtocolError, match="approval"):
        editor.apply(
            update["preview_id"], content=second, idempotency_key="c" * 64, approval=None, now=NOW
        )
    approval = editor.approve(
        update["preview_id"],
        actor_id="Owner",
        authorization_ref="attended:m32-edit",
        now=NOW,
    )
    applied = editor.apply(
        update["preview_id"],
        content=second,
        idempotency_key="c" * 64,
        approval=approval,
        now=NOW,
    )
    assert applied["outcome"] == "APPLIED"
    assert (tmp_path / applied["relative_path"]).read_text(encoding="utf-8") == second


def test_stale_preview_content_approval_or_idempotency_binding_refuses(tmp_path: Path) -> None:
    editor = _editor(tmp_path)
    first = editor.preview(
        project_id="HiveMind", relative_path="alpha.md", content="# A\n", expected_sha256=None, now=NOW
    )
    editor.apply(first["preview_id"], content="# A\n", idempotency_key="d" * 64, approval=None, now=NOW)
    update = editor.preview(
        project_id="HiveMind",
        relative_path="alpha.md",
        content="# B\n",
        expected_sha256=hashlib.sha256(b"# A\n").hexdigest(),
        now=NOW,
    )
    approval = editor.approve(
        update["preview_id"], actor_id="Owner", authorization_ref="attended:m32-edit", now=NOW
    )
    (tmp_path / "prime" / "knowledge" / "HiveMind" / "alpha.md").write_bytes(b"changed")
    with pytest.raises(ProtocolError):
        editor.apply(update["preview_id"], content="# B\n", idempotency_key="e" * 64, approval=approval, now=NOW)
    with pytest.raises(ProtocolError):
        editor.apply(update["preview_id"], content="# different\n", idempotency_key="e" * 64, approval=approval, now=NOW)


@pytest.mark.parametrize(
    "relative_path",
    ["../escape.md", "/absolute.md", "not-markdown.txt", "a/../../escape.md", ".hive/secret.md"],
)
def test_editor_refuses_unsafe_or_non_markdown_paths(tmp_path: Path, relative_path: str) -> None:
    editor = _editor(tmp_path)
    with pytest.raises(ProtocolError):
        editor.preview(
            project_id="HiveMind",
            relative_path=relative_path,
            content="# unsafe\n",
            expected_sha256=None,
            now=NOW,
        )


def test_moc_detection_and_no_implicit_source_deletion(tmp_path: Path) -> None:
    editor = _editor(tmp_path)
    source = tmp_path / "sources" / "sentinel.md"
    source.write_bytes(b"source")
    content = "---\ntype: moc\n---\n# MOC HiveMind\n\n- contains [[Alpha]]\n"
    preview = editor.preview(
        project_id="HiveMind",
        relative_path="mocs/MOC HiveMind.md",
        content=content,
        expected_sha256=None,
        now=NOW,
    )
    assert preview["parsed"]["is_moc"] is True
    editor.apply(preview["preview_id"], content=content, idempotency_key="f" * 64, approval=None, now=NOW)
    assert source.read_bytes() == b"source"


def test_editor_refuses_credential_material_before_preview_or_portable_write(
    tmp_path: Path,
) -> None:
    editor = _editor(tmp_path)
    credential = "api_" + "key=examplevalue12345"
    with pytest.raises(ProtocolError) as refusal:
        editor.preview(
            project_id="HiveMind",
            relative_path="credentials.md",
            content=f"# Credentials\n\n{credential}\n",
            expected_sha256=None,
            now=NOW,
        )
    assert refusal.value.code == "ADAPTER_CREDENTIAL_VALUE_DENIED"
    assert credential not in refusal.value.detail
    persisted = b"".join(
        path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    assert credential.encode("utf-8") not in persisted


@pytest.mark.parametrize("fault_point", ["journal-written", "note-written", "receipt-written"])
def test_edit_recovers_crash_and_replays_one_receipt(tmp_path: Path, fault_point: str) -> None:
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    editor = _editor(tmp_path, fault_hook=fault)
    content = "# Recoverable\n"
    preview = editor.preview(
        project_id="HiveMind", relative_path="recover.md", content=content, expected_sha256=None, now=NOW
    )
    with pytest.raises(RuntimeError):
        editor.apply(preview["preview_id"], content=content, idempotency_key="1" * 64, approval=None, now=NOW)
    recovered_editor = KnowledgeEditor(tmp_path, editor.authority)
    recovered = recovered_editor.apply(
        preview["preview_id"], content=content, idempotency_key="1" * 64, approval=None, now=NOW
    )
    replayed = recovered_editor.apply(
        preview["preview_id"], content=content, idempotency_key="1" * 64, approval=None, now=NOW
    )
    assert recovered == replayed
    assert len(list((tmp_path / ".hive" / "receipts").glob("knowledge-edit-*.json"))) == 1


def test_update_recovers_an_exact_started_journal_after_authorization_expiry(
    tmp_path: Path,
) -> None:
    editor = _editor(tmp_path)
    original = "# Original\n"
    created_preview = editor.preview(
        project_id="HiveMind",
        relative_path="recover-update.md",
        content=original,
        expected_sha256=None,
        now=NOW,
    )
    created = editor.apply(
        created_preview["preview_id"],
        content=original,
        idempotency_key="2" * 64,
        approval=None,
        now=NOW,
    )
    replacement = "# Replacement\n"
    update_preview = editor.preview(
        project_id="HiveMind",
        relative_path="recover-update.md",
        content=replacement,
        expected_sha256=created["sha256"],
        now=NOW,
        ttl=timedelta(minutes=2),
    )
    approval = editor.approve(
        update_preview["preview_id"],
        actor_id="Owner",
        authorization_ref="attended:m32-edit",
        now=NOW,
        ttl=timedelta(minutes=1),
    )
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == "note-written" and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        KnowledgeEditor(tmp_path, editor.authority, fault_hook=fault).apply(
            update_preview["preview_id"],
            content=replacement,
            idempotency_key="3" * 64,
            approval=approval,
            now=NOW,
        )

    recovered = KnowledgeEditor(tmp_path, editor.authority).apply(
        update_preview["preview_id"],
        content=replacement,
        idempotency_key="3" * 64,
        approval=approval,
        now=NOW + timedelta(minutes=3),
    )
    assert recovered["outcome"] == "APPLIED"
    assert (tmp_path / recovered["relative_path"]).read_text(encoding="utf-8") == replacement
    assert len(list((tmp_path / ".hive" / "receipts").glob("knowledge-edit-*.json"))) == 2


def test_update_recovery_refuses_a_different_valid_approval(tmp_path: Path) -> None:
    editor = _editor(tmp_path)
    original = "# Original\n"
    created_preview = editor.preview(
        project_id="HiveMind",
        relative_path="bound-update.md",
        content=original,
        expected_sha256=None,
        now=NOW,
    )
    created = editor.apply(
        created_preview["preview_id"],
        content=original,
        idempotency_key="7" * 64,
        approval=None,
        now=NOW,
    )
    replacement = "# Replacement\n"
    update_preview = editor.preview(
        project_id="HiveMind",
        relative_path="bound-update.md",
        content=replacement,
        expected_sha256=created["sha256"],
        now=NOW,
    )
    first_approval = editor.approve(
        update_preview["preview_id"],
        actor_id="Owner",
        authorization_ref="attended:first-approval",
        now=NOW,
    )
    (
        tmp_path
        / ".hive"
        / "receipts"
        / f"knowledge-approval-edit-{update_preview['preview_id'][5:]}.json"
    ).unlink()
    second_approval = editor.approve(
        update_preview["preview_id"],
        actor_id="Owner",
        authorization_ref="attended:second-approval",
        now=NOW,
    )
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == "journal-written" and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        KnowledgeEditor(tmp_path, editor.authority, fault_hook=fault).apply(
            update_preview["preview_id"],
            content=replacement,
            idempotency_key="8" * 64,
            approval=first_approval,
            now=NOW,
        )

    with pytest.raises(ProtocolError) as refusal:
        KnowledgeEditor(tmp_path, editor.authority).apply(
            update_preview["preview_id"],
            content=replacement,
            idempotency_key="8" * 64,
            approval=second_approval,
            now=NOW,
        )
    assert refusal.value.code == "KNOWLEDGE_EDIT_JOURNAL_INVALID"
