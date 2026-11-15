from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import hive_protocol.adapters.security as adapter_security
import hive_protocol.core as hive_core
import hive_protocol.product.agent_adapter as agent_adapter
import hive_protocol.storage as hive_storage
from hive_protocol.adapters.security import _VALUE_PATTERNS, reject_credential_values
from hive_protocol.core import ProtocolError
from hive_protocol.product.api import OperatorAPI
from hive_protocol.product.shell_contracts import route_for
from hive_protocol.product.shell_service import ShellService
from hive_protocol.product.workspace import HiveWorkspace


SESSION_DIGEST = "d" * 64
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def _request(
    action: str,
    input_document: dict,
    *,
    expected_version: str,
    key: str,
) -> dict:
    return {
        "schema_version": "hive.operator-request.v1",
        "request_id": str(uuid4()),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "action": action,
        "expected_version": expected_version,
        "idempotency_key": key,
        "input": input_document,
    }


def _dispatch(api: OperatorAPI, path: str, request: dict):
    return api.dispatch_mutation(
        "POST",
        path,
        request,
        session_digest=SESSION_DIGEST,
        idempotency_key=request["idempotency_key"],
        expected_version=request["expected_version"],
    )


def _document(result) -> dict:
    return result.response.as_dict()


def _shell(tmp_path: Path, *, fault_hook=None, now=NOW):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    workspace.configure_provider("retrieval-only")
    service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=now,
        capture_research_fault_hook=fault_hook,
    )
    api = OperatorAPI(
        workspace.root,
        service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    return workspace, service, api


def _portable_tree(workspace: HiveWorkspace) -> dict[str, bytes]:
    ignored = (".hive/runtime/", ".hive/keys/", ".hive/application-adapters/")
    return {
        path.relative_to(workspace.root).as_posix(): path.read_bytes()
        for path in sorted(workspace.root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and not path.relative_to(workspace.root).as_posix().startswith(ignored)
        and path.name != "intelligence.sqlite3"
    }


def _preview_input(text: str = "Grounded shell evidence.\n") -> dict:
    payload = text.encode("utf-8")
    return {
        "kind": "text",
        "filename": "evidence.md",
        "title": "Grounded evidence",
        "channel": "MARKDOWN",
        "media_type": "text/markdown",
        "privacy_class": "PROJECT_PRIVATE",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "text": text,
    }


def _preview_and_admit(workspace: HiveWorkspace, api: OperatorAPI):
    before = _portable_tree(workspace)
    preview_request = _request(
        "capture.preview",
        _preview_input(),
        expected_version="ABSENT",
        key="capture-preview-0001",
    )
    preview = _dispatch(api, "/api/v1/capture/preview", preview_request)
    assert preview.status == 200
    preview_document = _document(preview)
    assert preview_document["outcome"] == "APPLIED"
    assert preview_document["data"]["requires_approval"] is True
    assert preview_document["data"]["upload_ref"].startswith(
        ".hive/runtime/operator-shell/uploads/"
    )
    assert _portable_tree(workspace) == before

    admit_request = _request(
        "capture.admit",
        {
            "preview_id": preview_document["data"]["preview_id"],
            "preview_digest": preview_document["object_version"],
        },
        expected_version=preview_document["object_version"],
        key="capture-admit-00001",
    )
    admitted = _dispatch(api, "/api/v1/capture/admit", admit_request)
    assert admitted.status == 200
    admitted_document = _document(admitted)
    assert admitted_document["outcome"] == "APPLIED"
    assert admitted_document["changed"] is True
    assert admitted_document["data"]["domain_outcome"] == "APPLIED"
    assert len(admitted_document["data"]["source_ids"]) == 1
    return preview_document, admitted_document


_PINNED_SEED = "issue-23-pinned-adapter-signing"
# Per-label key seed overrides (label -> seed text); empty means the default.
_PINNED_KEY_SEEDS: dict[str, str] = {}
_PINNED_MACHINE_ID = "pinned-test-machine"
_REAL_DATETIME = datetime
_REAL_UTC_NOW = hive_storage.utc_now
_REAL_UUID4 = uuid4


class _PinnedDateTimeMeta(type):
    def __instancecheck__(cls, instance) -> bool:
        return isinstance(instance, _REAL_DATETIME)

    def __subclasscheck__(cls, subclass) -> bool:
        return issubclass(subclass, _REAL_DATETIME)


class _PinnedDateTime(datetime, metaclass=_PinnedDateTimeMeta):
    """datetime whose now() is the fixed shell clock (NOW)."""

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return NOW.astimezone(tz) if tz is not None else NOW.replace(tzinfo=None)


@pytest.fixture
def pinned_adapter_signing(monkeypatch: pytest.MonkeyPatch):
    """Make every adapter signature in the capture flow deterministic (#23).

    The capture flow signs adapter grants, requests, and plans with Ed25519
    keys generated fresh per workspace, over documents that carry wall-clock
    times, UUIDs, and the host name. The resulting base64url signature values
    pass through reject_credential_values, and roughly 1 in 112,000 random
    signatures contains a credential-shaped run such as "sk-" or "ghp_"
    followed by 16 or more token characters, which is correctly refused with
    ADAPTER_CREDENTIAL_VALUE_DENIED. Pinning the keys, clock, UUIDs, and
    machine identity makes the signatures fixed values that
    test_pinned_capture_signatures_are_deterministic_and_credential_free proves
    do not match any credential pattern. The guard itself is unchanged.
    """

    def generate_keypair(directory: Path, label: str):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        seed_text = _PINNED_KEY_SEEDS.get(label, f"{_PINNED_SEED}:{label}")
        seed = hashlib.sha256(seed_text.encode("utf-8")).digest()
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        private_path = directory / f"{label}.private.pem"
        public_path = directory / f"{label}.public.pem"
        hive_core._secure_create(
            private_path,
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            mode=0o600,
        )
        hive_core._secure_create(
            public_path,
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            mode=0o644,
        )
        return private_path, public_path, hive_core.public_key_id(private_key.public_key())

    counter = [itertools.count()]

    def pinned_uuid4() -> UUID:
        digest = hashlib.sha256(f"{_PINNED_SEED}:uuid:{next(counter[0])}".encode("utf-8"))
        return UUID(bytes=digest.digest()[:16], version=4)

    def restart() -> None:
        counter[0] = itertools.count()

    pinned_utc_now = NOW.isoformat().replace("+00:00", "Z")
    for name, module in list(sys.modules.items()):
        if not name.startswith("hive_protocol") or module is None:
            continue
        if getattr(module, "datetime", None) is _REAL_DATETIME:
            monkeypatch.setattr(module, "datetime", _PinnedDateTime)
        if getattr(module, "utc_now", None) is _REAL_UTC_NOW:
            monkeypatch.setattr(module, "utc_now", lambda: pinned_utc_now)
        if getattr(module, "uuid4", None) is _REAL_UUID4:
            monkeypatch.setattr(module, "uuid4", pinned_uuid4)
    monkeypatch.setattr(sys.modules[__name__], "uuid4", pinned_uuid4)
    monkeypatch.setattr(agent_adapter, "generate_keypair", generate_keypair)
    monkeypatch.setitem(
        agent_adapter.ADAPTER_OPERATOR_IDENTITY, "machine_id", _PINNED_MACHINE_ID
    )
    return restart


# An Ed25519 signature is 64 bytes, which is 86 unpadded base64url characters.
_SIGNATURE_SHAPE = re.compile(r"[A-Za-z0-9_-]{86}")


class _RecordingPattern:
    """Delegates to a credential pattern and records each value it scans."""

    def __init__(self, pattern: re.Pattern[str], seen: list[str]) -> None:
        self._pattern = pattern
        self._seen = seen

    def search(self, value: str):
        self._seen.append(value)
        return self._pattern.search(value)


@pytest.mark.usefixtures("pinned_adapter_signing")
def test_capture_preview_and_separate_exact_admission_are_browser_safe(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)

    preview, admitted = _preview_and_admit(workspace, api)

    upload = workspace.root / preview["data"]["upload_ref"]
    assert upload.is_file() and not upload.is_symlink()
    assert upload.read_bytes() == b"Grounded shell evidence.\n"
    assert admitted["technical_evidence"]
    assert list(workspace.assets.rglob("*"))
    assert list(workspace.provenance.glob("*.json"))


def test_pinned_capture_flow_scans_no_verified_signature_values(
    tmp_path: Path, pinned_adapter_signing, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = []
    for name in ("first", "second"):
        pinned_adapter_signing()
        scanned: list[str] = []
        monkeypatch.setattr(
            adapter_security,
            "_VALUE_PATTERNS",
            tuple(_RecordingPattern(pattern, scanned) for pattern in _VALUE_PATTERNS),
        )
        workspace, _, api = _shell(tmp_path / name)
        _preview_and_admit(workspace, api)
        runs.append({value for value in scanned if _SIGNATURE_SHAPE.fullmatch(value)})

    # Every adapter signature in this flow verifies, so none is pattern-scanned.
    assert runs[0] == runs[1] == set()


def test_credential_shaped_signature_values_are_still_denied(tmp_path: Path) -> None:
    # Built at runtime so no credential-shaped literal lives in the source.
    shaped = "s" + "k-" + "Q" * 83
    signed_shape = {
        "schema_version": "hive.adapter-attended-grant.v1",
        "signature": {"algorithm": "Ed25519", "key_id": "ed25519:" + "0" * 24, "value": shaped},
    }
    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        reject_credential_values(signed_shape, location="adapter attended grant")

    workspace, _, api = _shell(tmp_path)
    request = _request(
        "capture.preview",
        _preview_input(f"Evidence with {shaped} inside.\n"),
        expected_version="ABSENT",
        key="capture-preview-shaped-0001",
    )
    refused = _dispatch(api, "/api/v1/capture/preview", request)

    assert refused.status == 400
    assert _document(refused)["reason_code"] == "ADAPTER_CREDENTIAL_VALUE_DENIED"
    assert not list(workspace.provenance.glob("*.json"))


# Approver key seeds whose real Ed25519 signature over the pinned attended grant
# starts with a credential-looking prefix. Found by brute-force search over
# f"{_PINNED_SEED}:attended-approver:{n}"; if the grant content changes, the
# precondition assert below fails and the search must be re-run.
_PREFIXED_APPROVER_SEEDS = {
    "s" + "k-": f"{_PINNED_SEED}:attended-approver:227310",
    "g" + "hp_": f"{_PINNED_SEED}:attended-approver:3661075",
}


def _grant_with_prefixed_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str
):
    monkeypatch.setitem(
        _PINNED_KEY_SEEDS, "attended-approver", _PREFIXED_APPROVER_SEEDS[prefix]
    )
    workspace, _, api = _shell(tmp_path)
    preview = _dispatch(
        api,
        "/api/v1/capture/preview",
        _request(
            "capture.preview",
            _preview_input(),
            expected_version="ABSENT",
            key="capture-preview-prefixed-0001",
        ),
    )
    grants = list(
        (workspace.root / ".hive/application-adapters/policy/grants").rglob("*.json")
    )
    assert len(grants) == 1
    grant = json.loads(grants[0].read_text(encoding="utf-8"))
    approver = hive_core.load_public_key(
        workspace.root / ".hive/keys/application-adapters/attended-approver.public.pem"
    )
    keys = {hive_core.public_key_id(approver): approver}
    signature = grant["signature"]["value"]
    # Precondition: a real, verifying signature that looks like a credential.
    hive_core.verify_document(grant, keys)
    assert signature.startswith(prefix)
    assert any(pattern.search(signature) for pattern in _VALUE_PATTERNS)
    return workspace, api, preview, grant, keys, signature


def _denied(document, keys=None) -> None:
    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        reject_credential_values(document, location="test document", verified_by=keys)


@pytest.mark.usefixtures("pinned_adapter_signing")
@pytest.mark.parametrize("prefix", sorted(_PREFIXED_APPROVER_SEEDS))
def test_verified_signature_that_looks_like_a_credential_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    workspace, api, preview, grant, keys, _ = _grant_with_prefixed_signature(
        tmp_path, monkeypatch, prefix
    )

    assert preview.status == 200
    assert _document(preview)["outcome"] == "APPLIED"
    reject_credential_values(grant, location="adapter attended grant", verified_by=keys)
    # Callers that do not pass verified keys keep the full guard.
    _denied(grant)


@pytest.mark.usefixtures("pinned_adapter_signing")
@pytest.mark.parametrize("prefix", sorted(_PREFIXED_APPROVER_SEEDS))
def test_verified_signature_string_is_denied_anywhere_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    workspace, api, _, grant, keys, signature = _grant_with_prefixed_signature(
        tmp_path / "grant", monkeypatch, prefix
    )

    # Next to a verified grant, in a plain field or an unverified signature slot.
    _denied({"grant": grant, "note": signature}, keys)
    _denied({"grant": grant, "signature": {"value": signature}}, keys)
    _denied({"grant": grant, "items": [signature]}, keys)
    # In the operator request body of the preview endpoint.
    refused = _dispatch(
        api,
        "/api/v1/capture/preview",
        _request(
            "capture.preview",
            _preview_input(f"Evidence {signature}\n"),
            expected_version="ABSENT",
            key="capture-preview-prefixed-0002",
        ),
    )
    assert refused.status == 400
    assert _document(refused)["reason_code"] == "ADAPTER_CREDENTIAL_VALUE_DENIED"


@pytest.mark.usefixtures("pinned_adapter_signing")
@pytest.mark.parametrize("prefix", sorted(_PREFIXED_APPROVER_SEEDS))
def test_signature_that_fails_verification_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    _, _, _, grant, keys, _ = _grant_with_prefixed_signature(tmp_path, monkeypatch, prefix)
    key_id = next(iter(keys))
    other = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32).public_key()

    altered = json.loads(json.dumps(grant))
    altered["authorization_ref"] = "attended-cli:other"
    _denied(altered, keys)
    _denied(grant, {hive_core.public_key_id(other): other})
    _denied(grant, {key_id: other})
    _denied(grant, {})


@pytest.mark.usefixtures("pinned_adapter_signing")
def test_malformed_or_wrong_length_signature_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, _, grant, keys, signature = _grant_with_prefixed_signature(
        tmp_path, monkeypatch, "s" + "k-"
    )
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # Same 64 bytes under a lenient decoder, but not the canonical encoding.
    non_canonical = signature[:-1] + alphabet[alphabet.index(signature[-1]) ^ 1]

    for value in (
        signature + "A",  # 87 characters
        signature[:-2],  # decodes to 63 bytes
        signature + "==",  # padded
        signature + "A" * 86,  # decodes to 128 bytes
        non_canonical,
        # Whitespace around or inside the signature: never canonical base64url.
        *(
            variant
            for blank in (" ", "\t", "\n")
            for variant in (
                blank + signature,  # leading
                signature + blank,  # trailing
                signature[:43] + blank + signature[43:],  # internal
            )
        ),
    ):
        candidate = json.loads(json.dumps(grant))
        candidate["signature"]["value"] = value
        _denied(candidate, keys)


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"path": "/tmp/forbidden"}, "CAPTURE_BROWSER_PATH_DENIED"),
        ({"filename": "../escape.md"}, "CAPTURE_UPLOAD_FILENAME_INVALID"),
        ({"filename": "e\N{COMBINING ACUTE ACCENT}vidence.md"}, "CAPTURE_UPLOAD_FILENAME_INVALID"),
        ({"media_type": "application/pdf"}, "CAPTURE_CHANNEL_MEDIA_MISMATCH"),
        ({"privacy_class": "PRIME"}, "CAPTURE_PRIVACY_DENIED"),
        ({"authorization": "Bearer secret"}, "OPERATOR_TRANSPORT_SECRET_DENIED"),
    ],
)
def test_capture_refuses_paths_aliases_mismatches_and_credentials_before_staging(
    tmp_path: Path, change: dict, reason: str
) -> None:
    workspace, _, api = _shell(tmp_path)
    body = _preview_input()
    body.update(change)
    request = _request(
        "capture.preview",
        body,
        expected_version="ABSENT",
        key="capture-invalid-0001",
    )

    result = _dispatch(api, "/api/v1/capture/preview", request)

    assert result.status in {400, 403}
    assert _document(result)["reason_code"] == reason
    assert not (workspace.runtime / "operator-shell" / "uploads").exists()
    assert not list(workspace.provenance.glob("*.json"))


def test_capture_file_base64_bounds_hash_and_changed_bytes_are_refused(tmp_path: Path) -> None:
    workspace, _, api = _shell(tmp_path)
    payload = b"%PDF-1.7\noperator evidence"
    input_document = {
        "kind": "file",
        "filename": "evidence.pdf",
        "title": "PDF evidence",
        "channel": "PDF",
        "media_type": "application/pdf",
        "privacy_class": "PROJECT_PRIVATE",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "data_b64": base64.b64encode(payload).decode("ascii"),
    }
    preview_request = _request(
        "capture.preview",
        input_document,
        expected_version="ABSENT",
        key="capture-preview-file-0001",
    )
    preview = _document(_dispatch(api, "/api/v1/capture/preview", preview_request))
    upload = workspace.root / preview["data"]["upload_ref"]
    upload.write_bytes(b"changed after preview")
    admit_request = _request(
        "capture.admit",
        {
            "preview_id": preview["data"]["preview_id"],
            "preview_digest": preview["object_version"],
        },
        expected_version=preview["object_version"],
        key="capture-admit-file-00001",
    )

    refused = _dispatch(api, "/api/v1/capture/admit", admit_request)

    assert refused.status == 400
    assert _document(refused)["reason_code"] == "CAPTURE_UPLOAD_BYTES_CHANGED"
    assert not list(workspace.provenance.glob("*.json"))


def test_capture_base64_encoding_and_decoded_size_limits_fail_before_persistence(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    common = {
        "kind": "file",
        "filename": "bounded.pdf",
        "title": "Bounded PDF",
        "channel": "PDF",
        "media_type": "application/pdf",
        "privacy_class": "PROJECT_PRIVATE",
    }
    invalid = {
        **common,
        "sha256": hashlib.sha256(b"invalid").hexdigest(),
        "data_b64": "not-base64!",
    }
    invalid_request = _request(
        "capture.preview",
        invalid,
        expected_version="ABSENT",
        key="capture-invalid-base64-01",
    )
    invalid_result = _dispatch(api, "/api/v1/capture/preview", invalid_request)
    assert _document(invalid_result)["reason_code"] == "CAPTURE_UPLOAD_ENCODING"

    excessive = b"x" * (512 * 1024 + 1)
    oversized = {
        **common,
        "sha256": hashlib.sha256(excessive).hexdigest(),
        "data_b64": base64.b64encode(excessive).decode("ascii"),
    }
    oversized_request = _request(
        "capture.preview",
        oversized,
        expected_version="ABSENT",
        key="capture-decoded-limit-01",
    )
    oversized_result = _dispatch(api, "/api/v1/capture/preview", oversized_request)
    assert oversized_result.status == 413
    assert _document(oversized_result)["reason_code"] == "CAPTURE_UPLOAD_LIMIT"
    assert not (workspace.runtime / "operator-shell" / "uploads").exists()


def test_research_exact_source_set_search_ask_artifact_and_export(tmp_path: Path) -> None:
    workspace, _, api = _shell(tmp_path)
    _, admitted = _preview_and_admit(workspace, api)
    source_id = admitted["data"]["source_ids"][0]

    create_request = _request(
        "research.workspaces.create",
        {
            "workspace_id": "research:shell",
            "name": "Shell research",
            "privacy_class": "PROJECT_PRIVATE",
        },
        expected_version="ABSENT",
        key="research-workspace-0001",
    )
    created = _document(
        _dispatch(api, "/api/v1/research/workspaces/create", create_request)
    )
    assert created["outcome"] == "APPLIED"

    add_request = _request(
        "research.sources.add",
        {
            "workspace_id": "research:shell",
            "source_id": source_id,
            "retrieval_policy": {
                "exact_first": True,
                "semantic_allowed": False,
                "max_results": 10,
                "max_quote_bytes": 2048,
            },
        },
        expected_version="ABSENT",
        key="research-source-add-0001",
    )
    added = _document(_dispatch(api, "/api/v1/research/sources/add", add_request))
    source_set = added["object_version"]
    assert added["data"]["source_ids"] == [source_id]

    search_request = _request(
        "research.search",
        {
            "workspace_id": "research:shell",
            "source_set_digest": source_set,
            "query": "Grounded shell evidence",
            "limit": 5,
        },
        expected_version=source_set,
        key="research-search-00001",
    )
    searched = _document(_dispatch(api, "/api/v1/research/search", search_request))
    assert searched["outcome"] == "OK"
    assert searched["changed"] is False
    assert searched["data"]["status"] == "SEARCH_COMPLETE"
    assert searched["data"]["citations"]

    ask_request = _request(
        "research.ask",
        {
            "workspace_id": "research:shell",
            "source_set_digest": source_set,
            "question": "What evidence is grounded?",
            "limit": 5,
        },
        expected_version=source_set,
        key="research-ask-0000001",
    )
    asked = _document(_dispatch(api, "/api/v1/research/ask", ask_request))
    assert asked["outcome"] == "OK"
    assert asked["data"]["status"] in {"RETRIEVAL_ONLY", "NO_EVIDENCE"}
    assert asked["data"]["provider_called"] is False
    assert asked["reason_code"] is None

    artifact_request = _request(
        "research.artifacts.create",
        {
            "workspace_id": "research:shell",
            "source_set_digest": source_set,
            "artifact_type": "CITED_ANSWER",
            "title": "Grounded answer",
            "research_result": asked["data"],
        },
        expected_version=source_set,
        key="research-artifact-0001",
    )
    artifact = _document(
        _dispatch(api, "/api/v1/research/artifacts/create", artifact_request)
    )
    assert artifact["outcome"] == "APPLIED"
    assert artifact["data"]["artifact_id"].startswith("artifact:")

    export_request = _request(
        "research.export",
        {
            "workspace_id": "research:shell",
            "source_set_digest": source_set,
            "filename": "shell-research.tar.gz",
            "preview_digest": source_set,
        },
        expected_version=source_set,
        key="research-export-00001",
    )
    exported = _document(_dispatch(api, "/api/v1/research/export", export_request))
    assert exported["outcome"] == "APPLIED"
    assert exported["data"]["download_ref"].startswith(
        ".hive/runtime/operator-shell/downloads/"
    )
    bundle = workspace.root / exported["data"]["download_ref"]
    assert bundle.is_file()
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == exported["data"]["sha256"]


def test_research_refuses_stale_source_set_and_unsupported_artifact_citations(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    _, admitted = _preview_and_admit(workspace, api)
    source_id = admitted["data"]["source_ids"][0]
    create = _request(
        "research.workspaces.create",
        {
            "workspace_id": "research:closed",
            "name": "Closed research",
            "privacy_class": "PROJECT_PRIVATE",
        },
        expected_version="ABSENT",
        key="research-workspace-closed",
    )
    assert _dispatch(api, "/api/v1/research/workspaces/create", create).status == 200
    add = _request(
        "research.sources.add",
        {
            "workspace_id": "research:closed",
            "source_id": source_id,
            "retrieval_policy": {
                "exact_first": True,
                "semantic_allowed": False,
                "max_results": 10,
                "max_quote_bytes": 2048,
            },
        },
        expected_version="ABSENT",
        key="research-source-closed-01",
    )
    head = _document(_dispatch(api, "/api/v1/research/sources/add", add))[
        "object_version"
    ]

    stale = _request(
        "research.search",
        {
            "workspace_id": "research:closed",
            "source_set_digest": "a" * 64,
            "query": "evidence",
            "limit": 5,
        },
        expected_version="a" * 64,
        key="research-search-stale-01",
    )
    stale_result = _dispatch(api, "/api/v1/research/search", stale)
    assert stale_result.status in {400, 412}
    assert _document(stale_result)["reason_code"] in {
        "OPERATOR_VERSION_STALE",
        "RESEARCH_SOURCE_SET_STALE",
    }

    unsupported = _request(
        "research.artifacts.create",
        {
            "workspace_id": "research:closed",
            "source_set_digest": head,
            "artifact_type": "CITED_ANSWER",
            "title": "Invented answer",
            "research_result": {
                "status": "ANSWERED",
                "grounded": True,
                "answer": "Invented [cite:anchor:not-real]",
                "citations": [{"anchor_id": "anchor:not-real"}],
                "provider_called": False,
                "source_set_digest": head,
            },
        },
        expected_version=head,
        key="research-artifact-bad-01",
    )
    artifact = _dispatch(api, "/api/v1/research/artifacts/create", unsupported)
    assert artifact.status == 400
    assert _document(artifact)["reason_code"].startswith("RESEARCH_ARTIFACT_")
    assert not list(workspace.research.rglob("*.md"))


class CrashOnce:
    def __init__(self, stage: str) -> None:
        self.stage = stage

    def __call__(self, stage: str) -> None:
        if stage == self.stage:
            self.stage = ""
            raise RuntimeError("simulated crash")


def test_capture_admission_recovers_without_duplicate_effect(tmp_path: Path) -> None:
    crash = CrashOnce("capture.admit:after_adapter_result")
    workspace, service, api = _shell(tmp_path, fault_hook=crash)
    preview_request = _request(
        "capture.preview",
        _preview_input(),
        expected_version="ABSENT",
        key="capture-preview-crash-01",
    )
    preview = _document(_dispatch(api, "/api/v1/capture/preview", preview_request))
    admit_request = _request(
        "capture.admit",
        {
            "preview_id": preview["data"]["preview_id"],
            "preview_digest": preview["object_version"],
        },
        expected_version=preview["object_version"],
        key="capture-admit-crash-001",
    )

    first = _dispatch(api, "/api/v1/capture/admit", admit_request)
    assert first.status == 500
    receipts_before = list(workspace.receipts.glob("capture-operation-*.json"))
    assert len(receipts_before) == 1

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    api.service = recovered_service
    second = _dispatch(api, "/api/v1/capture/admit", admit_request)

    assert second.status == 200
    assert _document(second)["changed"] is False
    assert list(workspace.receipts.glob("capture-operation-*.json")) == receipts_before


def test_capture_preview_adopts_a_durable_upload_after_crash(tmp_path: Path) -> None:
    crash = CrashOnce("capture.preview:after_preview_record")
    workspace, _, api = _shell(tmp_path, fault_hook=crash)
    request = _request(
        "capture.preview",
        _preview_input(),
        expected_version="ABSENT",
        key="capture-preview-recovery-01",
    )

    first = _dispatch(api, "/api/v1/capture/preview", request)
    assert first.status == 500
    assert len(list((workspace.runtime / "operator-shell" / "uploads").rglob("*.md"))) == 1

    api.service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    replay = _dispatch(api, "/api/v1/capture/preview", request)

    assert replay.status == 200
    assert _document(replay)["changed"] is False
    previews = workspace.runtime / "operator-shell" / "capture-previews"
    assert len(list(previews.glob("*.json"))) == 1


def test_upload_hash_encoding_case_collision_and_symlink_roots_fail_closed(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    bad_hash = _preview_input()
    bad_hash["sha256"] = "0" * 64
    bad = _request(
        "capture.preview",
        bad_hash,
        expected_version="ABSENT",
        key="capture-bad-hash-0001",
    )
    result = _dispatch(api, "/api/v1/capture/preview", bad)
    assert _document(result)["reason_code"] == "CAPTURE_UPLOAD_HASH_MISMATCH"

    body = _preview_input()
    payload, metadata = service.capture_research._capture_bytes(body)
    from hive_protocol.core import document_digest

    preview_id = document_digest(
        {
            "project_id": "HiveMind",
            "metadata": metadata,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
    )
    collision = workspace.runtime / "operator-shell" / "uploads" / preview_id
    collision.mkdir(parents=True)
    (collision / "Evidence.md").write_bytes(payload)
    collision_request = _request(
        "capture.preview",
        body,
        expected_version="ABSENT",
        key="capture-case-collision-01",
    )
    collided = _dispatch(api, "/api/v1/capture/preview", collision_request)
    assert _document(collided)["reason_code"] == "CAPTURE_UPLOAD_CASE_COLLISION"
    assert not list(api.ledger_root.glob("*.json"))

    other_workspace, _, other_api = _shell(tmp_path / "other")
    shell_root = other_workspace.runtime / "operator-shell"
    shell_root.mkdir(parents=True, exist_ok=True)
    external = tmp_path / "external-uploads"
    external.mkdir()
    (shell_root / "uploads").symlink_to(external, target_is_directory=True)
    linked_request = _request(
        "capture.preview",
        _preview_input("linked root\n"),
        expected_version="ABSENT",
        key="capture-linked-root-001",
    )
    linked = _dispatch(other_api, "/api/v1/capture/preview", linked_request)
    assert _document(linked)["reason_code"] in {
        "CAPTURE_UPLOAD_BOUNDARY",
        "OPERATOR_RUNTIME_BOUNDARY",
    }
    assert list(external.iterdir()) == []


def test_research_export_adopts_exact_download_after_crash(tmp_path: Path) -> None:
    workspace, service, api = _shell(tmp_path)
    _, admitted = _preview_and_admit(workspace, api)
    create = _request(
        "research.workspaces.create",
        {
            "workspace_id": "research:export-recovery",
            "name": "Export recovery",
            "privacy_class": "PROJECT_PRIVATE",
        },
        expected_version="ABSENT",
        key="research-export-workspace",
    )
    assert _dispatch(api, "/api/v1/research/workspaces/create", create).status == 200
    add = _request(
        "research.sources.add",
        {
            "workspace_id": "research:export-recovery",
            "source_id": admitted["data"]["source_ids"][0],
            "retrieval_policy": {
                "exact_first": True,
                "semantic_allowed": False,
                "max_results": 10,
                "max_quote_bytes": 2048,
            },
        },
        expected_version="ABSENT",
        key="research-export-source-01",
    )
    source_set = _document(
        _dispatch(api, "/api/v1/research/sources/add", add)
    )["object_version"]
    service.capture_research.fault_hook = CrashOnce(
        "research.export:after_export_record"
    )
    export = _request(
        "research.export",
        {
            "workspace_id": "research:export-recovery",
            "source_set_digest": source_set,
            "filename": "recovered.tar.gz",
            "preview_digest": source_set,
        },
        expected_version=source_set,
        key="research-export-crash-01",
    )

    first = _dispatch(api, "/api/v1/research/export", export)
    assert first.status == 500
    downloads = list((workspace.runtime / "operator-shell" / "downloads").rglob("*.tar.gz"))
    assert len(downloads) == 1
    digest = hashlib.sha256(downloads[0].read_bytes()).hexdigest()

    api.service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered = _dispatch(api, "/api/v1/research/export", export)

    assert recovered.status == 200
    document = _document(recovered)
    assert document["changed"] is False
    assert document["data"]["sha256"] == digest
    assert len(list((workspace.runtime / "operator-shell" / "downloads").rglob("*.tar.gz"))) == 1


def test_expired_unadmitted_upload_is_removed_without_touching_canonical(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    preview_request = _request(
        "capture.preview",
        _preview_input(),
        expected_version="ABSENT",
        key="capture-preview-expire-01",
    )
    preview = _document(_dispatch(api, "/api/v1/capture/preview", preview_request))
    canonical_before = _portable_tree(workspace)
    upload = workspace.root / preview["data"]["upload_ref"]
    assert upload.is_file()

    service.capture_research.expire_unadmitted(NOW + timedelta(hours=2))

    assert not upload.exists()
    assert _portable_tree(workspace) == canonical_before
    route = route_for("POST", "/api/v1/capture/admit")
    request = _request(
        "capture.admit",
        {
            "preview_id": preview["data"]["preview_id"],
            "preview_digest": preview["object_version"],
        },
        expected_version=preview["object_version"],
        key="capture-admit-expired-01",
    )
    with pytest.raises(Exception):
        service.current_version(route, type("R", (), {"input": request["input"]})())
