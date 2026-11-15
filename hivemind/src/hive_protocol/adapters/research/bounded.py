"""Tenant-, workspace-, and project-bounded local research adapter."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.lifecycle_state import LifecycleOperationStore
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.ask import AskHive
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.retrieval import LocalRetriever
from hive_protocol.storage import atomic_write_json, read_json


RESEARCH_SIDE_EFFECTS = ["workspace:receipt"]
RESEARCH_ARTIFACT_SIDE_EFFECTS = [
    "workspace:research-artifact",
    "workspace:receipt",
]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class BoundedResearchAdapter:
    """Queries only one configured research scope and never broadens it."""

    def __init__(
        self,
        retriever: LocalRetriever,
        ask_hive: AskHive | None = None,
        *,
        tenant_id: str,
        workspace_id: str,
        project_id: str,
        state_root: Path,
        state_signing_key: Ed25519PrivateKey,
        max_results: int = 20,
        research_query_service: Any | None = None,
        artifact_store: Any | None = None,
        portable_service: Any | None = None,
    ) -> None:
        if not tenant_id.strip() or not workspace_id.strip() or not project_id.strip():
            raise ProtocolError(
                "RESEARCH_SCOPE_REQUIRED",
                "research tenant, workspace, and project are required",
            )
        if max_results < 1 or max_results > 100:
            raise ValueError("max_results must be between 1 and 100")
        raw_state = state_root.expanduser()
        for candidate in [raw_state, *raw_state.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "RESEARCH_STATE_BOUNDARY",
                    "research state path may not contain symlinks",
                )
        self.retriever = retriever
        self.ask_hive = ask_hive or AskHive(retriever)
        if self.ask_hive.retriever is not retriever:
            raise ProtocolError(
                "RESEARCH_RETRIEVER_MISMATCH",
                "Ask Hive must use the adapter's exact retriever",
            )
        self.tenant_id = tenant_id
        self.workspace_id = workspace_id
        self.project_id = project_id
        self.state_root = raw_state.resolve(strict=False)
        self.max_results = max_results
        self.research_query_service = research_query_service
        if (
            research_query_service is not None
            and research_query_service.retriever is not retriever
        ):
            raise ProtocolError(
                "RESEARCH_RETRIEVER_MISMATCH",
                "source-set query service must use the adapter's exact retriever",
            )
        self.artifact_store = artifact_store
        if artifact_store is not None:
            artifact_workspace = artifact_store.store.open_workspace(workspace_id)
            if (
                artifact_workspace.tenant_id != tenant_id
                or artifact_workspace.project_id != project_id
                or (
                    research_query_service is not None
                    and artifact_store.store is not research_query_service.store
                )
            ):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_STORE_MISMATCH",
                    "artifact store must use the adapter's exact research scope",
                )
        self.portable_service = portable_service
        if portable_service is not None:
            portable_workspace = portable_service.store.open_workspace(workspace_id)
            if (
                portable_workspace.tenant_id != tenant_id
                or portable_workspace.project_id != project_id
                or (
                    research_query_service is not None
                    and portable_service.store is not research_query_service.store
                )
                or (
                    artifact_store is not None
                    and portable_service.store is not artifact_store.store
                )
            ):
                raise ProtocolError(
                    "RESEARCH_PORTABLE_STORE_MISMATCH",
                    "portable service must use the adapter's exact research scope",
                )
        self.state_signing_key = state_signing_key
        self.state_key_id = public_key_id(state_signing_key.public_key())
        self.trusted_state_keys = {
            self.state_key_id: state_signing_key.public_key()
        }
        self.lifecycle_operations = LifecycleOperationStore(
            self.state_root / "lifecycle-operations",
            "nukotech.hive.bounded-research",
            signing_key=state_signing_key,
            trusted_state_keys=self.trusted_state_keys,
        )

    def _write_state_record(self, path: Path, document: dict[str, Any]) -> None:
        signed = sign_document(document, self.state_signing_key)
        verify_document(signed, self.trusted_state_keys)
        atomic_write_json(path, signed, mode=0o600)

    def _read_state_record(self, path: Path) -> dict[str, Any]:
        try:
            document = read_json(path)
            verify_document(document, self.trusted_state_keys)
            signature = document.get("signature")
            if (
                not isinstance(signature, dict)
                or signature.get("key_id") != self.state_key_id
            ):
                raise ProtocolError(
                    "ADAPTER_OPERATION_KEY_MISMATCH",
                    "research state signer changed",
                )
            return document
        except ProtocolError as exc:
            if exc.code == "ADAPTER_OPERATION_KEY_MISMATCH":
                raise
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_MISMATCH",
                "research state record is not authentic",
            ) from exc

    def _ensure_state_root(self) -> None:
        if self.state_root.is_symlink():
            raise ProtocolError(
                "RESEARCH_STATE_BOUNDARY", "research state root is a symlink"
            )
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            self.state_root.is_symlink()
            or not self.state_root.is_dir()
            or self.state_root.resolve() != self.state_root
        ):
            raise ProtocolError(
                "RESEARCH_STATE_BOUNDARY", "research state root changed identity"
            )
        os.chmod(self.state_root, 0o700)

    def _operation_path(self, operation_key: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", operation_key):
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_INVALID",
                "research operation key must be an exact SHA-256",
            )
        self._ensure_state_root()
        operations = self.state_root / "operations"
        if operations.is_symlink():
            raise ProtocolError(
                "RESEARCH_STATE_BOUNDARY", "research operations root is a symlink"
            )
        operations.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(operations, 0o700)
        return operations / f"{operation_key}.json"

    def _begin_operation(
        self, operation_key: str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        path = self._operation_path(operation_key)
        payload_digest = document_digest(payload)
        if path.exists():
            document = self._read_state_record(path)
            if (
                set(document)
                != {
                    "schema_version",
                    "operation_key",
                    "payload_digest",
                    "state",
                    "result",
                    "signature",
                }
                or
                document.get("schema_version") != "hive.research-operation.v1"
                or document.get("operation_key") != operation_key
                or document.get("payload_digest") != payload_digest
                or document.get("state") not in {"PREPARED", "TERMINAL"}
                or (
                    document.get("state") == "TERMINAL"
                    and not isinstance(document.get("result"), dict)
                )
            ):
                raise ProtocolError(
                    "ADAPTER_OPERATION_KEY_MISMATCH",
                    "research operation record does not match its payload",
                )
            return (
                copy.deepcopy(document["result"])
                if document["state"] == "TERMINAL"
                else None
            )
        self._write_state_record(
            path,
            {
                "schema_version": "hive.research-operation.v1",
                "operation_key": operation_key,
                "payload_digest": payload_digest,
                "state": "PREPARED",
                "result": None,
            },
        )
        return None

    def _finish_operation(
        self, operation_key: str, payload: dict[str, Any], result: dict[str, Any]
    ) -> None:
        self._write_state_record(
            self._operation_path(operation_key),
            {
                "schema_version": "hive.research-operation.v1",
                "operation_key": operation_key,
                "payload_digest": document_digest(payload),
                "state": "TERMINAL",
                "result": copy.deepcopy(result),
            },
        )

    def recover(self, operation_key: str) -> dict[str, Any] | None:
        path = self._operation_path(operation_key)
        if not path.exists():
            return None
        document = self._read_state_record(path)
        if (
            set(document)
            != {
                "schema_version",
                "operation_key",
                "payload_digest",
                "state",
                "result",
                "signature",
            }
            or
            document.get("schema_version") != "hive.research-operation.v1"
            or document.get("operation_key") != operation_key
            or document.get("state") not in {"PREPARED", "TERMINAL"}
        ):
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_MISMATCH",
                "research recovery record is invalid",
            )
        if document["state"] == "PREPARED":
            return None
        result = document.get("result")
        if not isinstance(result, dict):
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_MISMATCH",
                "research recovery result is invalid",
            )
        return copy.deepcopy(result)

    def _validate_payload(self, payload: Any) -> tuple[str, str, int, str | None]:
        if not isinstance(payload, dict):
            raise ProtocolError(
                "RESEARCH_PAYLOAD_INVALID", "research payload must be an object"
            )
        operation = payload.get("operation")
        if operation == "artifact":
            return self._validate_artifact_payload(payload)
        text_field = "query" if operation == "search" else "question"
        required = {"operation", "tenant_id", "workspace_id", text_field, "limit"}
        source_set_digest = payload.get("source_set_digest")
        if source_set_digest is not None:
            required.add("source_set_digest")
        if operation not in {"search", "ask"} or set(payload) != required:
            raise ProtocolError(
                "RESEARCH_PAYLOAD_INVALID",
                "research payload must be an exact search or ask request",
            )
        if (
            payload["tenant_id"] != self.tenant_id
            or payload["workspace_id"] != self.workspace_id
        ):
            raise ProtocolError(
                "RESEARCH_SCOPE_DENIED",
                "research payload does not match the configured tenant and workspace",
            )
        text = payload[text_field]
        limit = payload["limit"]
        if (
            not isinstance(text, str)
            or not text.strip()
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > self.max_results
        ):
            raise ProtocolError(
                "RESEARCH_PAYLOAD_INVALID",
                "research text and bounded result limit are required",
            )
        if source_set_digest is not None:
            if (
                not isinstance(source_set_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", source_set_digest) is None
                or self.research_query_service is None
            ):
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_INVALID",
                    "research source-set binding is invalid or unavailable",
                )
            self.research_query_service.store.verify_source_set(
                self.workspace_id, source_set_digest
            )
        return operation, text, limit, source_set_digest

    def _validate_artifact_payload(
        self, payload: dict[str, Any]
    ) -> tuple[str, str, int, str | None]:
        required = {
            "operation",
            "tenant_id",
            "workspace_id",
            "source_set_digest",
            "artifact_type",
            "title",
            "research_result",
        }
        if "generator_id" in payload:
            required.add("generator_id")
        if set(payload) != required or self.artifact_store is None:
            raise ProtocolError(
                "RESEARCH_PAYLOAD_INVALID",
                "research artifact payload is not exact or artifact persistence is unavailable",
            )
        if (
            payload["tenant_id"] != self.tenant_id
            or payload["workspace_id"] != self.workspace_id
        ):
            raise ProtocolError(
                "RESEARCH_SCOPE_DENIED",
                "research artifact does not match the configured scope",
            )
        source_set_digest = payload["source_set_digest"]
        if (
            not isinstance(source_set_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", source_set_digest) is None
            or not isinstance(payload["artifact_type"], str)
            or not isinstance(payload["title"], str)
            or not isinstance(payload["research_result"], dict)
            or (
                "generator_id" in payload
                and not isinstance(payload["generator_id"], str)
            )
        ):
            raise ProtocolError(
                "RESEARCH_PAYLOAD_INVALID", "research artifact payload is invalid"
            )
        self.artifact_store.store.verify_source_set(
            self.workspace_id, source_set_digest
        )
        if payload["research_result"].get("source_set_digest") != source_set_digest:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_SOURCE_SET_MISMATCH",
                "artifact result is bound to a different source set",
            )
        return "artifact", payload["title"], 0, source_set_digest

    def validate_request(self, request: AdapterRequest) -> None:
        if request.project_id != self.project_id:
            raise ProtocolError(
                "RESEARCH_PROJECT_DENIED",
                "request project does not match the research workspace project",
            )
        operation = request.payload.get("operation")
        expected = {
            "search": "research.search",
            "ask": "research.ask",
            "artifact": "research.artifact",
        }.get(operation)
        if expected is not None and request.capability_id != expected:
            raise ProtocolError(
                "ADAPTER_CAPABILITY_PAYLOAD_MISMATCH",
                "research operation exceeds the signed capability",
            )
        self._validate_payload(request.payload)

    def validate_evidence(self, request: AdapterRequest) -> None:
        operation, text, _, source_set_digest = self._validate_payload(request.payload)
        digest = (
            document_digest(request.payload["research_result"])
            if operation == "artifact"
            else hashlib.sha256(text.encode("utf-8")).hexdigest()
        )
        expected = [digest]
        if source_set_digest is not None:
            expected.append(source_set_digest)
        if request.evidence_sha256 != expected:
            raise ProtocolError(
                "ADAPTER_EVIDENCE_MISMATCH",
                "research evidence digest does not match the exact query bytes",
            )

    def health(self) -> dict[str, Any]:
        database = self.retriever.database
        if database.is_symlink() or not database.is_file():
            raise ProtocolError(
                "RESEARCH_DATABASE_BOUNDARY",
                "research retrieval database is absent or unsafe",
            )
        retrieval = self.retriever.capabilities()
        provider = self.ask_hive.provider
        if provider is None:
            model = {"available": False, "reason": "NO_PROVIDER_CONFIGURED"}
        else:
            capability = provider.chat_capability()
            model = {
                "available": bool(getattr(capability, "available", False)),
                "reason": str(getattr(capability, "reason", "UNKNOWN")),
            }
        self._ensure_state_root()
        probe = self.state_root / ".health-probe"
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, b"retrieval-only\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            if probe.is_file() and not probe.is_symlink():
                probe.unlink()
        return {
            "status": "HEALTHY",
            "evidence": [
                {
                    "tenant_id": self.tenant_id,
                    "workspace_id": self.workspace_id,
                    "project_id": self.project_id,
                    "retrieval": retrieval,
                    "model": model,
                    "state_writable": True,
                }
            ],
        }

    def plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        operation, _, _, _ = self._validate_payload(payload)
        return {
            "side_effects": list(
                RESEARCH_ARTIFACT_SIDE_EFFECTS
                if operation == "artifact"
                else RESEARCH_SIDE_EFFECTS
            ),
            "network_destinations": [],
            "requires_approval": False,
            "payload": copy.deepcopy(payload),
        }

    def apply(
        self, payload: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        existing = self._begin_operation(operation_key, payload)
        if existing is not None:
            return existing
        operation, text, limit, source_set_digest = self._validate_payload(payload)
        if operation == "artifact":
            if self.artifact_store is None:  # pragma: no cover - validated above
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_UNAVAILABLE", "artifact store is unavailable"
                )
            artifact = self.artifact_store.create_artifact(
                workspace_id=self.workspace_id,
                source_set_digest=source_set_digest,
                artifact_type=payload["artifact_type"],
                title=payload["title"],
                research_result=payload["research_result"],
                operation_key=operation_key,
                generator_id=payload.get("generator_id", "bounded-research"),
            )
            result = {
                "outcome": "APPLIED",
                "evidence_refs": [
                    {
                        "artifact_id": artifact["artifact_id"],
                        "artifact_digest": artifact["artifact_digest"],
                        "source_set_digest": artifact["source_set_digest"],
                    }
                ],
                "side_effects": list(RESEARCH_ARTIFACT_SIDE_EFFECTS),
                "resource_use": {
                    "artifacts": 1,
                    "provider_called": bool(
                        payload["research_result"]["provider_called"]
                    ),
                },
                "rollback_ref": artifact["rollback_ref"],
                "detail": copy.deepcopy(artifact),
            }
            self._finish_operation(operation_key, payload, result)
            return result
        if source_set_digest is not None and self.research_query_service is not None:
            if operation == "search":
                citations = self.research_query_service.search(
                    text,
                    workspace_id=self.workspace_id,
                    source_set_digest=source_set_digest,
                    limit=limit,
                )
                detail = {
                    "status": "SEARCH_COMPLETE" if citations else "NO_EVIDENCE",
                    "grounded": bool(citations),
                    "answer": None,
                    "citations": citations,
                    "provider_called": False,
                    "source_set_digest": source_set_digest,
                }
            else:
                detail = self.ask_hive.ask_research(
                    text,
                    query_service=self.research_query_service,
                    workspace_id=self.workspace_id,
                    source_set_digest=source_set_digest,
                    limit=limit,
                )
                citations = detail["citations"]
        elif operation == "search":
            citations = [
                hit.as_dict()
                for hit in self.retriever.search(
                    text,
                    tenant_id=self.tenant_id,
                    workspace_id=self.workspace_id,
                    limit=limit,
                )
            ]
            detail = {
                "status": "SEARCH_COMPLETE",
                "grounded": bool(citations),
                "answer": None,
                "citations": citations,
                "provider_called": False,
            }
        else:
            detail = self.ask_hive.ask(
                text,
                tenant_id=self.tenant_id,
                workspace_id=self.workspace_id,
                limit=limit,
            )
            citations = detail["citations"]
        result = {
            "outcome": "APPLIED",
            "evidence_refs": copy.deepcopy(citations),
            "side_effects": list(RESEARCH_SIDE_EFFECTS),
            "resource_use": {
                "citations": len(citations),
                "provider_called": bool(detail["provider_called"]),
            },
            "rollback_ref": None,
            "detail": copy.deepcopy(detail),
        }
        self._finish_operation(operation_key, payload, result)
        return result

    def _scope_rows(self, tenant_id: str, workspace_id: str) -> list[dict[str, Any]]:
        if tenant_id != self.tenant_id or workspace_id != self.workspace_id:
            raise ProtocolError(
                "RESEARCH_SCOPE_DENIED", "research export scope is not configured"
            )
        with sqlite3.connect(self.retriever.database) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT source_id, source_path, content, sha256, provenance_json
                FROM sources WHERE tenant_id=? AND workspace_id=? ORDER BY source_id
                """,
                (tenant_id, workspace_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def export(
        self, scope: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        existing = self.lifecycle_operations.begin("export", operation_key, scope)
        if existing is not None:
            return existing
        portable_keys = {
            "bundle",
            "workspace_id",
            "source_set_digest",
        }
        if isinstance(scope, dict) and frozenset(scope) in {
            frozenset(portable_keys),
            frozenset({*portable_keys, "root"}),
        }:
            if self.portable_service is None:
                raise ProtocolError(
                    "RESEARCH_EXPORT_SCOPE_INVALID",
                    "exact research portable export is unavailable",
                )
            if scope["workspace_id"] != self.workspace_id:
                raise ProtocolError(
                    "RESEARCH_SCOPE_DENIED",
                    "research portable export scope is not configured",
                )
            bundle = scope["bundle"]
            if not isinstance(bundle, str) or not Path(bundle).is_absolute():
                raise ProtocolError(
                    "RESEARCH_EXPORT_BOUNDARY",
                    "research portable bundle path must be absolute",
                )
            if "root" in scope:
                root = Path(scope["root"])
                if (
                    not root.is_absolute()
                    or root.is_symlink()
                    or not root.is_dir()
                    or root.resolve() != root
                    or Path(bundle).parent.resolve() != root
                ):
                    raise ProtocolError(
                        "RESEARCH_EXPORT_BOUNDARY",
                        "research portable bundle must remain inside its exact export root",
                    )
            portable = self.portable_service.export(
                workspace_id=self.workspace_id,
                source_set_digest=scope["source_set_digest"],
                output=Path(bundle),
            )
            exported_file = portable["artifact"]
            if "root" in scope:
                exported_file = Path(exported_file).relative_to(
                    Path(scope["root"])
                ).as_posix()
            result = {
                "outcome": "APPLIED",
                "files": [exported_file],
                "side_effects": ["workspace:export"],
                "resource_use": {
                    "files": portable["files"],
                    "artifacts": len(portable["artifact_ids"]),
                },
                "rollback_ref": None,
                "detail": copy.deepcopy(portable),
            }
            self.lifecycle_operations.finish(
                "export", operation_key, scope, result
            )
            return result
        if not isinstance(scope, dict) or set(scope) != {
            "root",
            "tenant_id",
            "workspace_id",
        }:
            raise ProtocolError(
                "RESEARCH_EXPORT_SCOPE_INVALID",
                "research export requires an exact root and configured scope",
            )
        root = Path(scope["root"])
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or str(root.resolve()) != scope["root"]
        ):
            raise ProtocolError(
                "RESEARCH_EXPORT_BOUNDARY", "research export root is unsafe"
            )
        rows = self._scope_rows(scope["tenant_id"], scope["workspace_id"])
        sources = {
            "schema_version": "hive.research-export-sources.v1",
            "tenant_id": self.tenant_id,
            "workspace_id": self.workspace_id,
            "sources": [
                {
                    "source_id": row["source_id"],
                    "source_path": row["source_path"],
                    "content": row["content"],
                    "sha256": row["sha256"],
                }
                for row in rows
            ],
        }
        provenance = {
            "schema_version": "hive.research-export-provenance.v1",
            "tenant_id": self.tenant_id,
            "workspace_id": self.workspace_id,
            "sources": [
                {
                    "source_id": row["source_id"],
                    "provenance": json.loads(row["provenance_json"]),
                }
                for row in rows
            ],
        }
        citations = {
            "schema_version": "hive.research-export-citations.v1",
            "tenant_id": self.tenant_id,
            "workspace_id": self.workspace_id,
            "citations": [
                {
                    "source_id": row["source_id"],
                    "source_path": row["source_path"],
                    "sha256": row["sha256"],
                    "quote": row["content"][:320],
                }
                for row in rows
            ],
        }
        documents = {
            "sources.json": sources,
            "provenance.json": provenance,
            "citations.json": citations,
        }
        for filename, document in documents.items():
            atomic_write_json(root / filename, document)
        manifest_entries = [
            {
                "path": filename,
                "sha256": _sha256_file(root / filename),
                "size_bytes": (root / filename).stat().st_size,
            }
            for filename in sorted(documents)
        ]
        atomic_write_json(
            root / "manifest.json",
            {
                "schema_version": "hive.research-export-manifest.v1",
                "tenant_id": self.tenant_id,
                "workspace_id": self.workspace_id,
                "files": manifest_entries,
            },
        )
        result = {
            "outcome": "APPLIED",
            "files": [*sorted(documents), "manifest.json"],
            "side_effects": ["workspace:export"],
            "resource_use": {"sources": len(rows), "files": 4},
            "rollback_ref": None,
            "detail": {"scope_verified": True},
        }
        self.lifecycle_operations.finish("export", operation_key, scope, result)
        return result

    def rollback(
        self, rollback_ref: str, *, operation_key: str
    ) -> dict[str, Any]:
        lifecycle_input = {"rollback_ref": rollback_ref}
        existing = self.lifecycle_operations.begin(
            "rollback", operation_key, lifecycle_input
        )
        if existing is not None:
            return existing
        if rollback_ref.startswith("research-artifact:"):
            if self.artifact_store is None:
                raise ProtocolError(
                    "RESEARCH_ROLLBACK_REFUSED",
                    "research artifact persistence is unavailable",
                )
            artifact_operation_key = rollback_ref.removeprefix(
                "research-artifact:"
            )
            artifact_result = self.artifact_store.rollback(artifact_operation_key)
            result = {
                "outcome": artifact_result["outcome"],
                "evidence_refs": [],
                "side_effects": list(RESEARCH_ARTIFACT_SIDE_EFFECTS),
                "resource_use": {
                    "removed": len(artifact_result["removed"]),
                    "restored": len(artifact_result["restored"]),
                },
                "rollback_ref": None,
                "detail": copy.deepcopy(artifact_result),
            }
            self.lifecycle_operations.finish(
                "rollback", operation_key, lifecycle_input, result
            )
            return result
        if rollback_ref != "research-derived:no-op":
            raise ProtocolError(
                "RESEARCH_ROLLBACK_REFUSED",
                "research rollback may address derived state only",
            )
        result = {
            "outcome": "NO_OP",
            "evidence_refs": [],
            "side_effects": [],
            "resource_use": {},
            "rollback_ref": None,
            "detail": {"canonical_sources_preserved": True},
        }
        self.lifecycle_operations.finish(
            "rollback", operation_key, lifecycle_input, result
        )
        return result

    def recover_lifecycle(
        self, operation: str, operation_key: str
    ) -> dict[str, Any] | None:
        return self.lifecycle_operations.recover(operation, operation_key)
