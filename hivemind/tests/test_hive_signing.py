from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import (
    ProtocolError,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.product import workspace as workspace_module
from hive_protocol.product.cli import main
from hive_protocol.product.integrity import (
    EXPORT_SIGNATURE_MEMBER,
    EXPORT_SIGNATURE_STATUS_SELF_SIGNED_UNTRUSTED,
    EXPORT_SIGNATURE_STATUS_VERIFIED,
    full_public_key_id,
    index_trusted_keys,
    public_key_pem,
    sign_integrity_document,
    trusted_workspace_keys,
    workspace_private_dir,
)
from hive_protocol.product.workspace import (
    EXPORT_ARCHIVE_ROOT,
    HiveWorkspace,
)


def _workspace(tmp_path: Path) -> HiveWorkspace:
    return HiveWorkspace.create(tmp_path / "hive")


def _seed(workspace: HiveWorkspace, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.md").write_bytes(b"# Note\n\nPortable body.\n")
    workspace.import_content(source)


def _rewrite_archive(bundle: Path, rewriter) -> None:
    with tarfile.open(bundle, "r:gz") as archive:
        members = []
        for member in archive.getmembers():
            payload = archive.extractfile(member).read() if member.isfile() else None
            members.append((member, payload))
    members = rewriter(members)
    with tarfile.open(bundle, "w:gz") as archive:
        for member, payload in members:
            if payload is not None:
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            else:
                archive.addfile(member)


def test_public_key_id_full_and_legacy_verify(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    legacy = public_key_id(public)
    full = public_key_id(public, full=True)
    assert legacy.startswith("ed25519:")
    assert full.startswith("ed25519:")
    assert len(legacy) == len("ed25519:") + 24
    assert len(full) == len("ed25519:") + 64
    assert full.split(":", 1)[1].startswith(legacy.split(":", 1)[1])
    assert full.startswith(legacy)

    truncated_map = {legacy: public}
    full_signed = sign_integrity_document({"schema_version": "test.v1", "n": 1}, key)
    assert full_signed["signature"]["key_id"] == full
    verify_document(full_signed, truncated_map)

    legacy_signed = sign_document({"schema_version": "test.v1", "n": 2}, key)
    assert legacy_signed["signature"]["key_id"] == legacy
    verify_document(legacy_signed, {full: public})
    expanded = index_trusted_keys({legacy: public})
    assert full in expanded and legacy in expanded


def test_product_receipts_are_signed_and_rebuild_rejects_forgery(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    receipts = list(workspace.receipts.glob("*.json"))
    assert receipts
    receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert receipt["signature"]["algorithm"] == "Ed25519"
    assert receipt["signature"]["key_id"] == full_public_key_id(
        list(trusted_workspace_keys(workspace.root).values())[0]
    )
    assert workspace.rebuild_index()["outcome"] == "INDEX_REBUILT"

    forged = dict(receipt)
    forged["signature"] = dict(receipt["signature"])
    forged["signature"]["value"] = ("A" * len(receipt["signature"]["value"]))
    receipts[0].write_text(json.dumps(forged, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="PRODUCT_RECEIPT_SIGNATURE_INVALID|SIGNATURE_INVALID"):
        workspace.rebuild_index()


def test_rebuild_index_rejects_forged_cognition_receipt(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    trusted = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    public_dir = workspace.root / ".hive" / "keys" / "cognition"
    public_dir.mkdir(parents=True, exist_ok=True)
    (public_dir / "proposer.public.pem").write_bytes(public_key_pem(trusted.public_key()).encode())
    (public_dir / "proposer.public.pem").chmod(0o644)

    unsigned = {
        "schema_version": "hive.memory-candidate-receipt.v1",
        "operation_id": "c" * 64,
        "candidate_id": "candidate:test",
        "outcome": "STAGED",
        "recorded_at": "2026-11-14T00:00:00Z",
    }
    signed = sign_document(unsigned, trusted)
    path = workspace.receipts / "cognition-proposal-forged.json"
    path.write_text(json.dumps(signed, sort_keys=True) + "\n", encoding="utf-8")
    assert workspace.rebuild_index()["outcome"] == "INDEX_REBUILT"

    mutated = dict(signed)
    mutated["signature"] = dict(signed["signature"])
    mutated["outcome"] = "TAMPERED"
    path.write_text(json.dumps(mutated, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="COGNITION_RECEIPT_SIGNATURE_INVALID|SIGNATURE_INVALID"):
        workspace.rebuild_index()

    lookalike = {
        **unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": public_key_id(other.public_key()),
            "value": "A" * 86,
        },
    }
    path.write_text(json.dumps(lookalike, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="COGNITION_RECEIPT_SIGNATURE_INVALID|UNKNOWN_SIGNING_KEY"):
        workspace.rebuild_index()


def test_export_omits_private_keys_and_signs_manifest(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _seed(workspace, tmp_path)
    private_dir = workspace_private_dir(workspace.root)
    assert (private_dir / "workspace.private.pem").is_file()

    bundle = tmp_path / "portable.tar.gz"
    workspace.export(bundle)
    with tarfile.open(bundle, "r:gz") as archive:
        names = [member.name for member in archive.getmembers()]
    assert f"{EXPORT_ARCHIVE_ROOT}/{EXPORT_SIGNATURE_MEMBER}" in names
    assert all(".hive/keys/" not in name for name in names)
    assert all(not name.endswith(".private.pem") for name in names)

    inspected = HiveWorkspace.inspect_export(bundle)
    assert inspected["signature_key_id"].startswith("ed25519:")
    public_path = private_dir / "workspace.public.pem"
    trusted = {full_public_key_id(__import__(
        "hive_protocol.core", fromlist=["load_public_key"]
    ).load_public_key(public_path)): None}
    # Use the helper instead of a dummy map.
    from hive_protocol.core import load_public_key

    key = load_public_key(public_path)
    trusted = {full_public_key_id(key): key}
    HiveWorkspace.inspect_export(bundle, trusted_keys=trusted, require_signature=True)
    reopened = HiveWorkspace.reopen_export(
        bundle, tmp_path / "reopened", trusted_keys=trusted, require_signature=True
    )
    assert reopened.search_exact("Portable body")


def test_rewritten_manifest_and_hashes_fail_when_signature_required(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _seed(workspace, tmp_path)
    bundle = tmp_path / "tampered.tar.gz"
    workspace.export(bundle)
    from hive_protocol.core import load_public_key

    key = load_public_key(workspace_private_dir(workspace.root) / "workspace.public.pem")
    trusted = {full_public_key_id(key): key}

    def rewriter(members):
        updated = []
        for member, payload in members:
            relative = member.name.removeprefix(f"{EXPORT_ARCHIVE_ROOT}/")
            if relative.endswith(".md") and payload is not None:
                payload = payload + b"\ntampered\n"
            if relative == "manifest.json":
                manifest = json.loads(payload)
                for entry in manifest["files"]:
                    if entry["path"].endswith(".md"):
                        entry["sha256"] = workspace_module._sha256_bytes(
                            # will be rewritten to match the tampered payload below
                            b""
                        )
                # Recompute hashes after we know tampered bytes: do a two-pass below.
                updated.append((member, payload))
            else:
                updated.append((member, payload))
        payloads = {
            member.name.removeprefix(f"{EXPORT_ARCHIVE_ROOT}/"): payload
            for member, payload in updated
            if payload is not None
        }
        # apply tamper + matching hashes
        result = []
        manifest = None
        for member, payload in updated:
            relative = member.name.removeprefix(f"{EXPORT_ARCHIVE_ROOT}/")
            if relative.endswith(".md") and payload is not None and not payload.endswith(b"\ntampered\n"):
                payload = payload + b"\ntampered\n"
            if relative == "manifest.json":
                manifest = json.loads(payload)
            result.append([member, payload])
        for member, payload in result:
            relative = member.name.removeprefix(f"{EXPORT_ARCHIVE_ROOT}/")
            if relative.endswith(".md") and payload is not None:
                payloads[relative] = payload
        for entry in manifest["files"]:
            entry["sha256"] = workspace_module._sha256_bytes(payloads[entry["path"]])
            entry["size_bytes"] = len(payloads[entry["path"]])
        for item in result:
            relative = item[0].name.removeprefix(f"{EXPORT_ARCHIVE_ROOT}/")
            if relative == "manifest.json":
                item[1] = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return [(member, payload) for member, payload in result]

    _rewrite_archive(bundle, rewriter)
    # Hash list was rewritten to match, so an unsigned check would pass; signature must not.
    with pytest.raises(ProtocolError, match="EXPORT_SIGNATURE_MISMATCH|EXPORT_SIGNATURE_INVALID"):
        HiveWorkspace.reopen_export(
            bundle, tmp_path / "target-rewrite", trusted_keys=trusted, require_signature=True
        )


def test_wrong_key_and_unsigned_export_fail_closed_when_required(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _seed(workspace, tmp_path)
    bundle = tmp_path / "signed.tar.gz"
    workspace.export(bundle)

    other = Ed25519PrivateKey.generate()
    wrong = {full_public_key_id(other.public_key()): other.public_key()}
    with pytest.raises(ProtocolError, match="EXPORT_SIGNATURE_INVALID|UNKNOWN_SIGNING_KEY"):
        HiveWorkspace.reopen_export(
            bundle, tmp_path / "wrong-key", trusted_keys=wrong, require_signature=True
        )

    def strip_sig(members):
        return [
            (member, payload)
            for member, payload in members
            if member.name != f"{EXPORT_ARCHIVE_ROOT}/{EXPORT_SIGNATURE_MEMBER}"
        ]

    unsigned = tmp_path / "unsigned.tar.gz"
    unsigned.write_bytes(bundle.read_bytes())
    _rewrite_archive(unsigned, strip_sig)
    # Legacy unsigned bundles still reopen when a signature is not required.
    HiveWorkspace.reopen_export(unsigned, tmp_path / "legacy")
    with pytest.raises(ProtocolError, match="EXPORT_SIGNATURE_MISSING|EXPORT_SIGNATURE_TRUST_REQUIRED"):
        HiveWorkspace.reopen_export(
            unsigned, tmp_path / "legacy-required", require_signature=True
        )
    with pytest.raises(ProtocolError, match="EXPORT_SIGNATURE_MISSING|EXPORT_SIGNATURE_TRUST_REQUIRED"):
        HiveWorkspace.reopen_export(
            unsigned,
            tmp_path / "legacy-required-key",
            trusted_keys=wrong,
            require_signature=True,
        )


def _cli_inspect(bundle: Path, *extra: str, capsys) -> dict:
    argv = ["inspect", "--bundle", str(bundle), *extra]
    assert main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    return payload


def test_inspect_embedded_key_is_self_signed_untrusted(tmp_path: Path, capsys) -> None:
    workspace = _workspace(tmp_path)
    _seed(workspace, tmp_path)
    bundle = tmp_path / "portable.tar.gz"
    workspace.export(bundle)

    inspected = HiveWorkspace.inspect_export(bundle)
    assert inspected["signature_status"] == EXPORT_SIGNATURE_STATUS_SELF_SIGNED_UNTRUSTED
    assert inspected["signature_status_text"] == "self-signed (untrusted key)"
    assert "verified" not in inspected["signature_status_text"]

    emitted = _cli_inspect(bundle, capsys=capsys)
    assert emitted["signature_status"] == EXPORT_SIGNATURE_STATUS_SELF_SIGNED_UNTRUSTED
    assert emitted["signature_status_text"] == "self-signed (untrusted key)"
    assert "verified" not in emitted["signature_status_text"]
    assert "verified" not in json.dumps(emitted)


def test_inspect_trusted_key_is_verified(tmp_path: Path, capsys) -> None:
    workspace = _workspace(tmp_path)
    _seed(workspace, tmp_path)
    bundle = tmp_path / "portable.tar.gz"
    workspace.export(bundle)
    from hive_protocol.core import load_public_key

    public_path = workspace_private_dir(workspace.root) / "workspace.public.pem"
    key = load_public_key(public_path)
    trusted = {full_public_key_id(key): key}

    inspected = HiveWorkspace.inspect_export(
        bundle, trusted_keys=trusted, require_signature=True
    )
    assert inspected["signature_status"] == EXPORT_SIGNATURE_STATUS_VERIFIED
    assert inspected["signature_status_text"] == "verified"

    emitted = _cli_inspect(
        bundle, "--require-signature", "--trusted-key", str(public_path), capsys=capsys
    )
    assert emitted["signature_status"] == EXPORT_SIGNATURE_STATUS_VERIFIED
    assert emitted["signature_status_text"] == "verified"
