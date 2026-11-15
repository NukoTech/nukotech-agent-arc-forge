from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import multiprocessing
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.manifest import load_manifest
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.adapters.policy import InvocationContext
from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.adapters.runtime import AdapterRuntime
from hive_protocol.core import ProtocolError, sign_document


IDENTITY = {
    "persona_id": "Director",
    "surface_id": "LeadA",
    "machine_id": "hive-lab-host",
    "project_id": "HiveMind",
    "app_actor": "hive-builda-app",
}


@dataclass
class AdapterCase:
    root: Path
    runtime: AdapterRuntime
    registry: AdapterRegistry
    adapter: Any
    manifest: dict[str, Any]
    context: InvocationContext
    request_key: Ed25519PrivateKey
    valid_capability: str
    valid_payload: dict[str, Any]
    authorization_ref: str
    source_digest_refusal: Callable[[], None]
    prompt_injection: Callable[[], None]
    export_reopen: Callable[[], None]
    rollback_uninstall: Callable[[], None]
    unrelated_sentinel: Callable[[], None]
    symlink_escape: Callable[[], None]

    def request(
        self,
        *,
        request_id: str = "conformance-request-001",
        nonce: str = "conformance-request-nonce-001",
        capability_id: str | None = None,
        payload: dict[str, Any] | None = None,
        sender: dict[str, str] | None = None,
        project_id: str = "HiveMind",
        data_classification: str = "PROJECT_PRIVATE",
        expires_at: str | None = None,
        key: Ed25519PrivateKey | None = None,
    ) -> dict[str, Any]:
        selected_payload = copy.deepcopy(payload or self.valid_payload)
        if selected_payload.get("kind") == "text":
            evidence_sha256 = [
                hashlib.sha256(selected_payload["text"].encode("utf-8")).hexdigest()
            ]
        elif selected_payload.get("kind") == "file" and Path(
            selected_payload["path"]
        ).is_file():
            evidence_sha256 = [
                hashlib.sha256(Path(selected_payload["path"]).read_bytes()).hexdigest()
            ]
        else:
            evidence_text = selected_payload.get(
                "query", selected_payload.get("question")
            )
            evidence_sha256 = (
                [
                    hashlib.sha256(str(evidence_text).encode("utf-8")).hexdigest()
                ]
                if evidence_text is not None
                else ["a" * 64]
            )
        expiry = expires_at or (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat().replace("+00:00", "Z")
        return sign_document(
            AdapterRequest(
                request_id=request_id,
                adapter_id=self.manifest["adapter_id"],
                adapter_version=self.manifest["version"],
                sender=copy.deepcopy(sender or IDENTITY),
                project_id=project_id,
                capability_id=capability_id or self.valid_capability,
                data_classification=data_classification,
                authorization_ref=self.authorization_ref,
                evidence_sha256=evidence_sha256,
                payload=selected_payload,
                nonce=nonce,
                expires_at=expiry,
            ).as_dict(),
            key or self.request_key,
        )


class AdapterConformanceSuite:
    """The frozen application-adapter acceptance matrix, reused without skips."""

    def test_valid_plan_and_apply(self, adapter_case: AdapterCase) -> None:
        request = adapter_case.request()
        plan = adapter_case.runtime.plan(request, adapter_case.context)
        result = adapter_case.runtime.invoke(
            request, plan, adapter_case.context, approval_document=None
        )
        assert result["outcome"] in {"APPLIED", "NO_OP"}
        assert result["adapter_id"] == adapter_case.manifest["adapter_id"]

    @pytest.mark.parametrize(
        ("dimension", "code"),
        [
            ("project", "ADAPTER_PROJECT_DENIED"),
            ("identity", "ADAPTER_IDENTITY_DENIED"),
            ("capability", "ADAPTER_CAPABILITY_DENIED"),
            ("permission", "ADAPTER_PERMISSION_DENIED"),
            ("data_class", "ADAPTER_DATA_CLASS_DENIED"),
        ],
    )
    def test_wrong_authority_is_refused(
        self, adapter_case: AdapterCase, dimension: str, code: str
    ) -> None:
        changes: dict[str, Any]
        if dimension == "project":
            changes = {"project_id": "WrongProject"}
        elif dimension == "identity":
            changes = {
                "identity": {**adapter_case.context.identity, "surface_id": "LeadB"}
            }
        elif dimension == "capability":
            changes = {"granted_capabilities": frozenset()}
        elif dimension == "permission":
            changes = {"granted_permissions": frozenset()}
        else:
            changes = {"allowed_data_classifications": frozenset()}
        context = dataclasses.replace(adapter_case.context, **changes)
        with pytest.raises(ProtocolError, match=code):
            adapter_case.runtime.plan(adapter_case.request(), context)

    def test_source_digest_mismatch_is_refused(self, adapter_case: AdapterCase) -> None:
        adapter_case.source_digest_refusal()

    def test_untrusted_signer_is_refused(self, adapter_case: AdapterCase) -> None:
        with pytest.raises(ProtocolError, match="UNKNOWN_SIGNING_KEY"):
            adapter_case.runtime.plan(
                adapter_case.request(key=Ed25519PrivateKey.generate()),
                adapter_case.context,
            )

    def test_expired_request_is_refused(self, adapter_case: AdapterCase) -> None:
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
        with pytest.raises(ProtocolError, match="ADAPTER_REQUEST_EXPIRED"):
            adapter_case.runtime.plan(
                adapter_case.request(expires_at=expired), adapter_case.context
            )

    def test_reused_nonce_is_refused(self, adapter_case: AdapterCase) -> None:
        nonce = "conformance-shared-nonce-001"
        first = adapter_case.request(request_id="nonce-request-001", nonce=nonce)
        first_plan = adapter_case.runtime.plan(first, adapter_case.context)
        adapter_case.runtime.invoke(
            first, first_plan, adapter_case.context, approval_document=None
        )
        second = adapter_case.request(request_id="nonce-request-002", nonce=nonce)
        second_plan = adapter_case.runtime.plan(second, adapter_case.context)
        with pytest.raises(ProtocolError, match="REPLAY_NONCE"):
            adapter_case.runtime.invoke(
                second, second_plan, adapter_case.context, approval_document=None
            )

    def test_revoked_adapter_is_refused(self, adapter_case: AdapterCase) -> None:
        adapter_case.registry.revoke(
            adapter_case.manifest["adapter_id"],
            reason="conformance revocation",
            authorization_ref="decision:conformance",
        )
        with pytest.raises(ProtocolError, match="ADAPTER_REVOKED"):
            adapter_case.runtime.plan(adapter_case.request(), adapter_case.context)

    def test_missing_dependency_is_refused(self, adapter_case: AdapterCase) -> None:
        manifest = copy.deepcopy(adapter_case.manifest)
        manifest["adapter_id"] = f"{manifest['adapter_id']}.dependency-test"
        manifest["dependencies"] = [
            {
                "name": "missing-conformance-dependency",
                "version": "1.0.0",
                "sha256": "0" * 64,
                "license": "MIT",
            }
        ]
        registry = AdapterRegistry(
            adapter_case.root / "dependency-runtime",
            adapter_case.root / "dependency-policy",
            os_name="linux",
            architecture="aarch64",
            runtime="python>=3.11",
            available_dependencies={},
        )
        with pytest.raises(ProtocolError, match="ADAPTER_DEPENDENCY_UNAVAILABLE"):
            registry.register(adapter_case.adapter, manifest)

    def test_offline_behavior_is_truthful(self, adapter_case: AdapterCase) -> None:
        assert adapter_case.manifest["offline_behavior"] == "SUPPORTED"
        request = adapter_case.request(request_id="offline-request-001")
        plan = adapter_case.runtime.plan(request, adapter_case.context)
        assert plan["network_destinations"] == []
        result = adapter_case.runtime.invoke(
            request, plan, adapter_case.context, approval_document=None
        )
        assert result["outcome"] == "APPLIED"

    def test_degraded_health_is_reported_not_hidden(
        self, adapter_case: AdapterCase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unavailable() -> dict[str, Any]:
            raise RuntimeError("injected unavailable dependency")

        monkeypatch.setattr(adapter_case.adapter, "health", unavailable)
        health = adapter_case.registry.list_status()[0]["health"]
        assert health["status"] == "DEGRADED"
        assert health["reason"] == "RuntimeError"

    def test_prompt_injection_remains_inert(self, adapter_case: AdapterCase) -> None:
        adapter_case.prompt_injection()

    def test_plaintext_credential_pattern_is_refused(
        self, adapter_case: AdapterCase
    ) -> None:
        manifest = copy.deepcopy(adapter_case.manifest)
        manifest["credential_references"] = ["plaintext:customer-secret"]
        with pytest.raises(ProtocolError, match="ADAPTER_DOCUMENT_SCHEMA_INVALID"):
            load_manifest(manifest)

    def test_undeclared_egress_is_refused(
        self, adapter_case: AdapterCase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = adapter_case.adapter.plan

        def unsafe_plan(payload: dict[str, Any]) -> dict[str, Any]:
            planned = original(payload)
            planned["network_destinations"] = ["https://egress.example.invalid"]
            return planned

        monkeypatch.setattr(adapter_case.adapter, "plan", unsafe_plan)
        with pytest.raises(ProtocolError, match="ADAPTER_EGRESS_DENIED"):
            adapter_case.runtime.plan(adapter_case.request(), adapter_case.context)

    def test_export_and_reopen_are_scoped(self, adapter_case: AdapterCase) -> None:
        adapter_case.export_reopen()

    def test_rollback_and_uninstall_preserve_canonical_state(
        self, adapter_case: AdapterCase
    ) -> None:
        adapter_case.rollback_uninstall()

    def test_unrelated_sentinel_is_preserved(self, adapter_case: AdapterCase) -> None:
        adapter_case.unrelated_sentinel()

    def test_symlink_escape_is_refused(self, adapter_case: AdapterCase) -> None:
        adapter_case.symlink_escape()

    def test_concurrent_invoke_applies_exactly_once(self, adapter_case: AdapterCase) -> None:
        request = adapter_case.request(request_id="concurrent-request-001")
        plan = adapter_case.runtime.plan(request, adapter_case.context)

        def invoke(outcomes) -> None:
            try:
                outcome = adapter_case.runtime.invoke(
                    request, plan, adapter_case.context, approval_document=None
                )["outcome"]
            except ProtocolError as exc:
                outcome = exc.code
            outcomes.put(outcome)

        process_context = multiprocessing.get_context("fork")
        outcomes = process_context.Queue()
        processes = [
            process_context.Process(target=invoke, args=(outcomes,))
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0
        values = [outcomes.get(timeout=2) for _ in processes]
        assert sorted(values) == ["APPLIED", "REPLAY_MESSAGE_ID"]

    def test_fresh_process_verifies_signed_result(self, adapter_case: AdapterCase) -> None:
        request = adapter_case.request(request_id="fresh-process-request-001")
        plan = adapter_case.runtime.plan(request, adapter_case.context)
        result = adapter_case.runtime.invoke(
            request, plan, adapter_case.context, approval_document=None
        )
        public_path = adapter_case.root / "runtime-public.pem"
        public_path.write_bytes(
            adapter_case.runtime.signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        result_path = adapter_case.runtime.results / f"{result['result_id']}.json"
        script = (
            "import json,sys; "
            "from cryptography.hazmat.primitives import serialization; "
            "from hive_protocol.core import public_key_id,verify_document; "
            "key=serialization.load_pem_public_key(open(sys.argv[1],'rb').read()); "
            "doc=json.load(open(sys.argv[2],encoding='utf-8')); "
            "verify_document(doc,{public_key_id(key):key})"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, str(public_path), str(result_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr

    def test_replay_is_refused(self, adapter_case: AdapterCase) -> None:
        request = adapter_case.request(request_id="replay-request-001")
        plan = adapter_case.runtime.plan(request, adapter_case.context)
        adapter_case.runtime.invoke(
            request, plan, adapter_case.context, approval_document=None
        )
        with pytest.raises(ProtocolError, match="REPLAY_MESSAGE_ID"):
            adapter_case.runtime.invoke(
                request, plan, adapter_case.context, approval_document=None
            )
