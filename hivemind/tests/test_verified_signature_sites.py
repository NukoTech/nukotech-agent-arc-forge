"""Per-site tests for the verified-signature exemption of the credential guard.

Each site may skip pattern-scanning a signature.value only when that exact value
verifies, as a 64-byte Ed25519 signature over that exact document, with the keys
the site already uses for that document. The keys below are pinned: each seed was
found by brute-force search so that a real signature over the fixed document
starts with a credential-looking prefix. If the signed content changes, the
precondition in _prefixed() fails and the seed must be searched again.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from test_cognition_models import _candidate_document
from test_shell_capture_research import (
    _PINNED_KEY_SEEDS,
    _PINNED_SEED,
    NOW,
    _preview_and_admit,
    _shell,
    pinned_adapter_signing,  # noqa: F401  (fixture)
)
from test_workflow_definitions import _definition, _store
from test_workflow_models import _actor

from hive_protocol.adapters.lifecycle import AdapterLifecycle
from hive_protocol.adapters.runtime import AdapterRuntime
from hive_protocol.adapters.security import _VALUE_PATTERNS
from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.models import (
    MemoryCandidate,
    MemoryReviewDecision,
    cognition_document_digest,
)
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
    unsigned_document,
    verify_document,
)
from hive_protocol.product import agent_adapter
from hive_protocol.product.api import OperatorAPI
from hive_protocol.product.shell_contracts import OperatorResponse
from hive_protocol.storage import read_json
from hive_protocol.workflows.models import WorkflowDefinition

DENIED = "ADAPTER_CREDENTIAL_VALUE_DENIED"
SK = "s" + "k-"
GHP = "g" + "hp_"

# site -> (prefix, seed number); key = sha256(f"verified-signature-sites:{site}:{n}")
SITE_SEEDS = {
    "workflow-definition": (SK, 119750),
    "workflow-event-receipt": (SK, 202617),
    "cognition-review": (SK, 274811),
    "lifecycle-prior-result": (SK, 70110),
}
# The shell lifecycle lane test pins the product's attended-request key instead.
ATTENDED_REQUEST_SEED = (SK, 610682)


def site_key(site: str, number: int) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"verified-signature-sites:{site}:{number}".encode())
    return Ed25519PrivateKey.from_private_bytes(seed.digest())


def _keys(key: Ed25519PrivateKey) -> dict:
    return {public_key_id(key.public_key()): key.public_key()}


def _prefixed(document: dict, keys: dict, prefix: str) -> str:
    """Precondition: a real, verifying signature that looks like a credential."""

    verify_document(document, keys)
    value = document["signature"]["value"]
    assert value.startswith(prefix), "signed content changed; search a new seed"
    assert any(pattern.search(value) for pattern in _VALUE_PATTERNS)
    return value


def _cause_code(exc: BaseException) -> str | None:
    while exc is not None:
        if isinstance(exc, ProtocolError) and exc.code == DENIED:
            return DENIED
        exc = exc.__cause__
    return None


def _assert_denied(call) -> None:
    with pytest.raises(ProtocolError) as raised:
        call()
    assert _cause_code(raised.value) == DENIED, raised.value


# Deterministic signed documents (no clock, UUID, or host input).


def workflow_event(key: Ed25519PrivateKey) -> dict:
    payload = {"definition_verified": True}
    return sign_document(
        {
            "schema_version": "hive.workflow-event.v1",
            "event_id": "6f1d3c1e-4a8b-4c3d-9e2f-0a1b2c3d4e5f",
            "run_id": "0d9c8b7a-6f5e-4d3c-8b2a-1f0e9d8c7b6a",
            "workflow_sha256": "c" * 64,
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "sequence": 1,
            "event_type": "RUN_STARTED",
            "step_id": None,
            "attempt": None,
            "actor": _actor(key),
            "payload": payload,
            "payload_sha256": document_digest(payload),
            "previous_event_sha256": None,
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def cognition_review(key: Ed25519PrivateKey) -> dict:
    candidate = _candidate_document()
    candidate["source_event_ids"] = ["2b8f6e4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b"]
    candidate["candidate_id"] = MemoryCandidate.identity_for(candidate)
    unsigned = {
        "schema_version": "hive.memory-review-decision.v1",
        "decision_id": "review:placeholder",
        "candidate_id": candidate["candidate_id"],
        "candidate_sha256": cognition_document_digest(candidate),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
        "outcome": "APPROVED",
        "corrections": [],
        "reviewer": {
            "actor_id": "Owner",
            "authorization_ref": "attended-review:m32",
            "key_id": public_key_id(key.public_key()),
        },
        "reviewed_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
    }
    unsigned["decision_id"] = MemoryReviewDecision.identity_for(unsigned)
    return sign_document(unsigned, key)


def _pinned_capture_services(tmp_path: Path):
    workspace, service, api = _shell(tmp_path)
    _preview_and_admit(workspace, api)
    return workspace, service, agent_adapter.product_adapter_services(workspace.root)


# 1. workflows/models.py (through WorkflowDefinitionStore, which verifies with
#    its trusted keys right after from_dict).
def test_workflow_document_site_skips_only_its_verified_signature(tmp_path: Path) -> None:
    prefix, number = SITE_SEEDS["workflow-definition"]
    key = site_key("workflow-definition", number)
    document = _definition(key)
    value = _prefixed(document, _keys(key), prefix)

    _store(tmp_path / "trusted", key).preview(document)

    _assert_denied(lambda: WorkflowDefinition.from_dict(document))
    _assert_denied(lambda: _store(tmp_path / "other", site_key("other", 0)).preview(document))
    moved = copy.deepcopy(document)
    moved["description"] = value
    _assert_denied(lambda: WorkflowDefinition.from_dict(moved, verified_by=_keys(key)))


# 2. cognition/models.py (MemoryReviewDecision with the reviewer public keys).
def test_cognition_document_site_skips_only_its_verified_signature() -> None:
    prefix, number = SITE_SEEDS["cognition-review"]
    key = site_key("cognition-review", number)
    document = cognition_review(key)
    value = _prefixed(document, _keys(key), prefix)

    MemoryReviewDecision.from_dict(document, verified_by=_keys(key))

    _assert_denied(lambda: MemoryReviewDecision.from_dict(document))
    _assert_denied(
        lambda: MemoryReviewDecision.from_dict(document, verified_by=_keys(site_key("other", 0)))
    )
    moved = copy.deepcopy(document)
    moved["reviewer"]["authorization_ref"] = value
    _assert_denied(lambda: MemoryReviewDecision.from_dict(moved, verified_by=_keys(key)))


# 2b. cognition/store.py load_review (reviewer public keys of the authority).
def test_cognition_store_load_review_skips_only_its_verified_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, number = SITE_SEEDS["cognition-review"]
    key = site_key("cognition-review", number)
    document = cognition_review(key)
    _prefixed(document, _keys(key), prefix)
    authority = CognitionAuthority(tmp_path)
    store = CognitionStore(tmp_path, authority)
    store._prepare()
    token = document["candidate_id"].split(":", 1)[1]
    (store.reviews / f"{token}.json").write_text(json.dumps(document), encoding="utf-8")

    monkeypatch.setattr(authority, "reviewer_public_keys", _keys(key))
    review = store.load_review(document["candidate_id"])
    assert review.signature["value"] == document["signature"]["value"]

    monkeypatch.setattr(authority, "reviewer_public_keys", _keys(site_key("other", 0)))
    _assert_denied(lambda: store.load_review(document["candidate_id"]))
    monkeypatch.setattr(authority, "reviewer_public_keys", {})
    _assert_denied(lambda: store.load_review(document["candidate_id"]))


# 3. product/shell_service.py receipts (workflow receipt with workflow_keys).
def test_operator_receipt_site_skips_only_its_verified_signature(tmp_path: Path) -> None:
    prefix, number = SITE_SEEDS["workflow-event-receipt"]
    key = site_key("workflow-event-receipt", number)
    document = workflow_event(key)
    value = _prefixed(document, _keys(key), prefix)
    _, service, _ = _shell(tmp_path)
    path = tmp_path / "receipt.json"

    assert service._verify_receipt(document, path=path, workflow_keys=_keys(key)) == (
        "SIGNATURE_VERIFIED"
    )

    _assert_denied(lambda: service._verify_receipt(document, path=path, workflow_keys={}))
    _assert_denied(
        lambda: service._verify_receipt(
            document, path=path, workflow_keys=_keys(site_key("other", 0))
        )
    )
    moved = copy.deepcopy(document)
    moved["payload"] = {"note": value}
    moved["payload_sha256"] = document_digest(moved["payload"])
    _assert_denied(
        lambda: service._verify_receipt(moved, path=path, workflow_keys=_keys(key))
    )


# 4. adapters/lifecycle.py (prior result with the runtime result key).
@pytest.mark.usefixtures("pinned_adapter_signing")
def test_lifecycle_site_skips_only_its_verified_signature(tmp_path: Path) -> None:
    _, _, services = _pinned_capture_services(tmp_path / "flow")
    results = sorted(services.runtime.results.glob("*.json"))
    assert len(results) == 1
    template = unsigned_document(read_json(results[0]))
    prefix, number = SITE_SEEDS["lifecycle-prior-result"]
    key = site_key("lifecycle-prior-result", number)
    document = sign_document(template, key)
    value = _prefixed(document, _keys(key), prefix)

    def lifecycle_with(signing_key: Ed25519PrivateKey, name: str) -> AdapterLifecycle:
        runtime = AdapterRuntime(
            tmp_path / name,
            services.registry,
            services.runtime.trusted_request_keys,
            services.runtime.trusted_approver_keys,
            signing_key,
            trusted_approver_identities=services.runtime.trusted_approver_identities,
        )
        return AdapterLifecycle(runtime)

    prior = lifecycle_with(key, "trusted")._signed_prior_result(document)
    assert prior.outcome == "APPLIED"

    _assert_denied(
        lambda: lifecycle_with(site_key("other", 0), "other")._signed_prior_result(document)
    )
    moved = copy.deepcopy(document)
    moved["detail"]["note"] = value
    _assert_denied(lambda: lifecycle_with(key, "moved")._signed_prior_result(moved))


# 5. product/shell_lanes/lifecycle.py (stored adapter request with the
#    runtime's trusted request keys; the product's own pinned request key).
@pytest.mark.usefixtures("pinned_adapter_signing")
def test_shell_lifecycle_lane_site_skips_only_its_verified_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, number = ATTENDED_REQUEST_SEED
    monkeypatch.setitem(
        _PINNED_KEY_SEEDS, "attended-request", f"{_PINNED_SEED}:attended-request:{number}"
    )
    workspace, service, services = _pinned_capture_services(tmp_path)
    stored = sorted((workspace.root / ".hive/application-adapters/requests").glob("*.json"))
    assert len(stored) == 1
    document = read_json(stored[0])
    value = _prefixed(document, services.runtime.trusted_request_keys, prefix)
    lane = service.settings_lifecycle
    normalized = {
        "adapter_id": document["adapter_id"],
        "capability_id": document["capability_id"],
        "payload": document["payload"],
        "evidence_sha256": document["evidence_sha256"],
    }
    request = SimpleNamespace(project_id=document["project_id"])

    def validate(candidate: dict):
        return lane._validate_recoverable_adapter_request(
            services, request, document["nonce"], normalized, candidate
        )

    # The real request passes the guard, verification, and grant resolution;
    # it then stops only at the lane's own operator-request binding check.
    with pytest.raises(ProtocolError, match="does not bind the operator request"):
        validate(document)

    tampered = copy.deepcopy(document)
    tampered["expires_at"] = "2026-09-01T12:09:00Z"
    _assert_denied(lambda: validate(tampered))
    with monkeypatch.context() as patched:
        patched.setattr(
            services.runtime, "trusted_request_keys", _keys(site_key("other", 0))
        )
        _assert_denied(lambda: validate(document))
        patched.setattr(services.runtime, "trusted_request_keys", {})
        _assert_denied(lambda: validate(document))
    moved = copy.deepcopy(document)
    moved["payload"]["title"] = value
    _assert_denied(lambda: validate(moved))


# 6. product/shell_contracts.py stays fully guarded: operator documents have no
#    verification key at this layer, so even a verified signature is scanned.
def test_operator_document_site_stays_fully_guarded() -> None:
    prefix, number = SITE_SEEDS["workflow-definition"]
    key = site_key("workflow-definition", number)
    document = _definition(key)
    _prefixed(document, _keys(key), prefix)

    _assert_denied(
        lambda: OperatorResponse.from_dict(
            {
                "schema_version": "hive.operator-response.v1",
                "request_id": "7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f",
                "outcome": "READ",
                "reason_code": None,
                "object_version": "ABSENT",
                "changed": False,
                "data": {"definition": document},
                "technical_evidence": [],
            }
        )
    )


# 7. product/api.py stays fully guarded: replay records are not signed and the
#    API has no verification key for anything embedded in them.
def test_operator_replay_record_site_stays_fully_guarded() -> None:
    prefix, number = SITE_SEEDS["workflow-definition"]
    key = site_key("workflow-definition", number)
    document = _definition(key)
    value = _prefixed(document, _keys(key), prefix)

    _assert_denied(lambda: OperatorAPI._validate_record({"signature": document["signature"]}))
    _assert_denied(lambda: OperatorAPI._validate_record({"note": value}))


# AdapterRuntime's public accessors return public keys only, as copies.
@pytest.mark.usefixtures("pinned_adapter_signing")
def test_runtime_key_accessors_return_public_key_copies(tmp_path: Path) -> None:
    _, _, services = _pinned_capture_services(tmp_path)
    runtime = services.runtime
    runtime_public = runtime.signing_key.public_key()
    internal = runtime.signature_keys()

    own = runtime.verification_keys()
    union = runtime.signature_keys()
    assert own == {runtime.key_id: runtime_public}
    assert union == {
        **runtime.trusted_request_keys,
        **runtime.trusted_approver_keys,
        runtime.key_id: runtime_public,
    }
    for keys in (own, union):
        assert isinstance(keys, dict)
        assert keys
        assert all(isinstance(key, Ed25519PublicKey) for key in keys.values())
        assert not any(isinstance(key, Ed25519PrivateKey) for key in keys.values())

    # Mutating the returned maps leaves the runtime unchanged.
    stranger = site_key("other", 0).public_key()
    own.clear()
    own["stranger"] = stranger
    union.clear()
    union["stranger"] = stranger
    assert runtime.verification_keys() == {runtime.key_id: runtime_public}
    assert runtime.signature_keys() == internal
    assert runtime.signature_keys() is not runtime.signature_keys()


@pytest.mark.usefixtures("pinned_adapter_signing")
def test_runtime_sign_document_verifies_with_verification_keys(tmp_path: Path) -> None:
    _, _, services = _pinned_capture_services(tmp_path)
    runtime = services.runtime
    signed = runtime.sign_document({"kind": "runtime-sign-method", "n": 1})
    verify_document(signed, runtime.verification_keys())
    assert signed["kind"] == "runtime-sign-method"
    assert "signature" in signed


def test_production_modules_do_not_access_private_runtime_or_signing_key() -> None:
    """Production modules outside runtime.py must not touch private runtime state.

    Scans only hivemind/src/hive_protocol, and skips adapters/runtime.py, the
    module that owns AdapterRuntime. Tests are exempt and are not part of this
    scan. The check is AST-based: an attribute or getattr/setattr/delattr/hasattr
    on a runtime object (a name or alias bound to one, an attribute named
    'runtime', or AdapterRuntime itself) may not be signing_key or any
    non-dunder underscore-prefixed name.
    """

    root = Path(__file__).resolve().parents[1] / "src" / "hive_protocol"
    runtime_path = (root / "adapters" / "runtime.py").resolve()
    hits: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if path.resolve() == runtime_path:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for lineno, expr in _runtime_private_accesses(tree):
            rel = path.relative_to(root)
            hits.append(f"{rel}:{lineno}:{expr}")
    assert hits == []


_RUNTIME_NAMES = frozenset({"runtime", "AdapterRuntime"})


def _is_private_or_signing(attr: str) -> bool:
    if attr == "signing_key":
        return True
    return attr.startswith("_") and not (attr.startswith("__") and attr.endswith("__"))


class _RuntimeAccessChecker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.runtime_names: set[str] = set(_RUNTIME_NAMES)
        self.hits: list[tuple[int, str]] = []

    def _is_runtime_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id in self.runtime_names:
            return True
        if isinstance(node, ast.Attribute) and node.attr in _RUNTIME_NAMES:
            return True
        return False

    def _bind(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        if self._is_runtime_expr(value):
            self.runtime_names.add(target.id)
        elif target.id not in _RUNTIME_NAMES:
            self.runtime_names.discard(target.id)

    def _flag(self, node: ast.AST, expr: str) -> None:
        self.hits.append((getattr(node, "lineno", 0), expr))

    def _visit_scope(self, node: ast.AST, extra: set[str]) -> None:
        saved = set(self.runtime_names)
        self.runtime_names |= extra
        self.generic_visit(node)
        self.runtime_names = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scope(node, {arg.arg for arg in node.args.args if arg.arg in _RUNTIME_NAMES})

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scope(node, {arg.arg for arg in node.args.args if arg.arg in _RUNTIME_NAMES})

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scope(node, set())

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_scope(node, {arg.arg for arg in node.args.args if arg.arg in _RUNTIME_NAMES})

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        for target in node.targets:
            self._bind(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._bind(node.target, node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.generic_visit(node)
        self._bind(node.target, node.value)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self._is_runtime_expr(node.value) and _is_private_or_signing(node.attr):
            self._flag(node, ast.unparse(node))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "setattr", "delattr", "hasattr"}
            and len(node.args) >= 2
            and self._is_runtime_expr(node.args[0])
        ):
            attr = node.args[1]
            if isinstance(attr, ast.Constant) and isinstance(attr.value, str) and _is_private_or_signing(attr.value):
                self._flag(node, ast.unparse(node))
        self.generic_visit(node)


def _runtime_private_accesses(tree: ast.AST) -> list[tuple[int, str]]:
    checker = _RuntimeAccessChecker()
    checker.visit(tree)
    return checker.hits
