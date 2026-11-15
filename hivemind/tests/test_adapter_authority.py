from __future__ import annotations

import copy
import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

import hive_protocol.core as core_module
import hive_protocol.product.agent_adapter as agent_adapter_module

from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.core import (
    ProtocolError,
    generate_keypair,
    load_private_key,
    public_key_id,
    sign_document,
)
from hive_protocol.product.agent_adapter import (
    ADAPTER_OPERATOR_IDENTITY,
    _adapter_private_key,
    adapter_invocation_context,
    adapter_status,
    product_adapter_services,
)
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import read_json


def _request(
    services,
    *,
    signing_key=None,
    sender: dict[str, str] | None = None,
    project_id: str = "HiveMind",
    authorization_ref: str = "attended-cli:hivemind",
) -> dict:
    key = signing_key or services.request_key
    now = datetime.now(timezone.utc)
    text = "independent authority evidence"
    request = AdapterRequest(
        request_id=str(uuid4()),
        adapter_id="nukotech.hive.local-capture",
        adapter_version=services.manifests["nukotech.hive.local-capture"]["version"],
        sender=dict(sender or ADAPTER_OPERATOR_IDENTITY),
        project_id=project_id,
        capability_id="capture.text",
        data_classification="PROJECT_PRIVATE",
        authorization_ref=authorization_ref,
        evidence_sha256=[hashlib.sha256(text.encode("utf-8")).hexdigest()],
        payload={"kind": "text", "text": text, "title": "Authority"},
        nonce=uuid4().hex,
        expires_at=(now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    )
    return sign_document(request.as_dict(), key)


def _file_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def test_valid_signature_cannot_self_authorize_changed_project(tmp_path: Path) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    services = product_adapter_services(vault)
    forged_identity = {
        **ADAPTER_OPERATOR_IDENTITY,
        "persona_id": "request-chosen-persona",
        "surface_id": "request-chosen-surface",
        "project_id": "OtherProject",
    }
    signed = _request(
        services,
        sender=forged_identity,
        project_id="OtherProject",
        authorization_ref="request-chosen:authorization",
    )

    context = adapter_invocation_context(services, signed)
    with pytest.raises(ProtocolError, match="ADAPTER_PROJECT_DENIED"):
        services.runtime.plan(signed, context)


def test_trusted_signing_key_without_grant_cannot_invoke(tmp_path: Path) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    services = product_adapter_services(vault)
    key_root = tmp_path / "other-key"
    private_path, _, _ = generate_keypair(key_root, "ungranted")
    ungranted_key = load_private_key(private_path)
    services.runtime.trusted_request_keys[
        public_key_id(ungranted_key.public_key())
    ] = ungranted_key.public_key()
    signed = _request(services, signing_key=ungranted_key)

    with pytest.raises(ProtocolError, match="ADAPTER_AUTHORITY_GRANT_MISSING"):
        adapter_invocation_context(services, signed)


def test_adapter_status_is_a_read_only_projection(tmp_path: Path) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    before = _file_tree(vault)

    status = adapter_status(vault)

    assert [item["adapter_id"] for item in status] == [
        "nukotech.hive.bounded-research",
        "nukotech.hive.local-capture",
    ]
    assert _file_tree(vault) == before


def test_attended_grant_refuses_credential_value_before_persistence(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    services = product_adapter_services(vault)
    private_path, _, _ = generate_keypair(tmp_path / "credential-key", "request")
    request_key = load_private_key(private_path)
    signer_key_id = public_key_id(request_key.public_key())
    identity = {
        **ADAPTER_OPERATOR_IDENTITY,
        "app_actor": "Authorization: Bearer abcdefghijklmnop",
    }
    before = sorted(services.authority.root.glob("*.json"))

    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        services.authority.ensure_attended_grant(
            signer_key_id=signer_key_id,
            identity=identity,
            project_id="HiveMind",
            authorization_ref="attended-cli:hivemind",
            manifests=services.manifests,
            policy_signing_key=services.approver_key,
        )

    assert sorted(services.authority.root.glob("*.json")) == before


def test_adapter_status_reads_existing_revocation_without_writing(tmp_path: Path) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    services = product_adapter_services(vault)
    services.registry.revoke(
        "nukotech.hive.local-capture",
        reason="test revocation",
        authorization_ref="test:attended",
    )
    before = _file_tree(vault)

    status = adapter_status(vault)

    capture = next(
        item for item in status if item["adapter_id"] == "nukotech.hive.local-capture"
    )
    assert capture["revoked"] is True
    assert _file_tree(vault) == before


def test_existing_attended_grant_must_match_requested_exact_scope(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    services = product_adapter_services(vault)
    signer_key_id = public_key_id(services.request_key.public_key())
    grant_path = services.authority._path(signer_key_id)
    before = read_json(grant_path)
    narrowed = copy.deepcopy(services.manifests)
    narrowed["nukotech.hive.local-capture"]["required_permissions"] = []

    with pytest.raises(ProtocolError, match="ADAPTER_AUTHORITY_GRANT_MISMATCH"):
        services.authority.ensure_attended_grant(
            signer_key_id=signer_key_id,
            identity=ADAPTER_OPERATOR_IDENTITY,
            project_id="HiveMind",
            authorization_ref="attended-cli:hivemind",
            manifests=narrowed,
            policy_signing_key=services.approver_key,
        )

    assert read_json(grant_path) == before


def test_product_services_reject_symlinked_hive_ancestor_before_key_writes(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "hive"
    vault.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (vault / ".hive").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ProtocolError, match="ADAPTER_RUNTIME_ROOT_BOUNDARY"):
        product_adapter_services(vault)

    assert list(outside.iterdir()) == []


def test_product_services_reject_nested_key_root_symlink_before_key_writes(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    outside = tmp_path / "outside-keys"
    outside.mkdir()
    (vault / ".hive" / "keys").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ProtocolError, match="PRIVATE_KEY_BOUNDARY"):
        product_adapter_services(vault)

    assert list(outside.iterdir()) == []


def test_adapter_key_bootstrap_is_serialized(
    tmp_path: Path, monkeypatch
) -> None:
    key_root = tmp_path / "keys" / "application-adapters"
    original = agent_adapter_module.generate_keypair
    calls = 0
    calls_lock = threading.Lock()

    def slow_generate(directory: Path, label: str):
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.1)
        return original(directory, label)

    monkeypatch.setattr(agent_adapter_module, "generate_keypair", slow_generate)
    with ThreadPoolExecutor(max_workers=2) as executor:
        keys = list(
            executor.map(
                lambda _: _adapter_private_key(key_root, "attended-request"),
                range(2),
            )
        )

    assert calls == 1
    assert public_key_id(keys[0].public_key()) == public_key_id(keys[1].public_key())
    assert (key_root / "attended-request.private.pem").stat().st_mode & 0o777 == 0o600


def test_generate_keypair_creates_private_key_with_secure_exclusive_open(
    tmp_path: Path, monkeypatch
) -> None:
    opened: list[tuple[str, int, int]] = []
    original_open = core_module.os.open

    def tracked_open(path, flags, mode=0o777, *args, **kwargs):
        opened.append((os.fspath(path), flags, mode))
        return original_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(core_module.os, "open", tracked_open)
    private_path, _, _ = generate_keypair(tmp_path / "secure-keys", "runtime")

    private_open = next(item for item in opened if item[0] == str(private_path))
    assert private_open[2] == 0o600
    assert private_open[1] & os.O_EXCL
    assert private_open[1] & getattr(os, "O_NOFOLLOW", 0)
