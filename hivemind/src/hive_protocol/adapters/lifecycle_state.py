"""Small durable idempotency store for adapter-owned lifecycle effects."""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.storage import atomic_write_json, read_json


_OPERATIONS = frozenset({"export", "rollback"})


class LifecycleOperationStore:
    """Persists PREPARED/TERMINAL lifecycle operation records."""

    def __init__(
        self,
        root: Path,
        adapter_id: str,
        *,
        signing_key: Ed25519PrivateKey,
        trusted_state_keys: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> None:
        raw = root.expanduser()
        for candidate in [raw, *raw.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_STATE_BOUNDARY",
                    "lifecycle operation path may not contain symlinks",
                )
        self.root = raw.resolve(strict=False)
        self.adapter_id = adapter_id
        self.signing_key = signing_key
        self.key_id = public_key_id(signing_key.public_key())
        self.trusted_state_keys = dict(
            trusted_state_keys or {self.key_id: signing_key.public_key()}
        )
        if self.key_id not in self.trusted_state_keys:
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_OPERATION_MISMATCH",
                "lifecycle state signer is not trusted",
            )

    def _path(self, operation: str, operation_key: str) -> Path:
        if operation not in _OPERATIONS or re.fullmatch(
            r"[0-9a-f]{64}", operation_key
        ) is None:
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_OPERATION_KEY_INVALID",
                "lifecycle operation and key are invalid",
            )
        if self.root.is_symlink():
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_STATE_BOUNDARY",
                "lifecycle operation root may not be a symlink",
            )
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            self.root.is_symlink()
            or self.root.resolve() != self.root
            or self.root.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_STATE_BOUNDARY",
                "lifecycle operation root changed identity",
            )
        os.chmod(self.root, 0o700)
        return self.root / f"{operation}-{operation_key}.json"

    def _read_record(self, path: Path) -> dict[str, Any]:
        try:
            document = read_json(path)
            verify_document(document, self.trusted_state_keys)
            signature = document.get("signature")
            if not isinstance(signature, dict) or signature.get("key_id") != self.key_id:
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_OPERATION_MISMATCH",
                    "lifecycle state signer changed",
                )
            return document
        except ProtocolError as exc:
            if exc.code == "ADAPTER_LIFECYCLE_OPERATION_MISMATCH":
                raise
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_OPERATION_MISMATCH",
                "lifecycle operation record is not authentic",
            ) from exc

    def _write_record(self, path: Path, document: dict[str, Any]) -> None:
        reject_credential_values(document, location="adapter lifecycle operation")
        signed = sign_document(document, self.signing_key)
        verify_document(signed, self.trusted_state_keys)
        atomic_write_json(path, signed, mode=0o600)

    def begin(
        self, operation: str, operation_key: str, operation_input: Any
    ) -> dict[str, Any] | None:
        path = self._path(operation, operation_key)
        input_digest = document_digest(operation_input)
        if path.exists():
            document = self._read_record(path)
            if (
                set(document)
                != {
                    "schema_version",
                    "adapter_id",
                    "operation",
                    "operation_key",
                    "input_digest",
                    "state",
                    "result",
                    "signature",
                }
                or
                document.get("schema_version")
                != "hive.adapter-lifecycle-operation.v1"
                or document.get("adapter_id") != self.adapter_id
                or document.get("operation") != operation
                or document.get("operation_key") != operation_key
                or document.get("input_digest") != input_digest
                or document.get("state") not in {"PREPARED", "TERMINAL"}
                or (
                    document.get("state") == "TERMINAL"
                    and not isinstance(document.get("result"), dict)
                )
            ):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_OPERATION_MISMATCH",
                    "lifecycle operation record does not match its exact input",
                )
            return (
                copy.deepcopy(document["result"])
                if document["state"] == "TERMINAL"
                else None
            )
        document = {
            "schema_version": "hive.adapter-lifecycle-operation.v1",
            "adapter_id": self.adapter_id,
            "operation": operation,
            "operation_key": operation_key,
            "input_digest": input_digest,
            "state": "PREPARED",
            "result": None,
        }
        self._write_record(path, document)
        return None

    def finish(
        self,
        operation: str,
        operation_key: str,
        operation_input: Any,
        result: dict[str, Any],
    ) -> None:
        document = {
            "schema_version": "hive.adapter-lifecycle-operation.v1",
            "adapter_id": self.adapter_id,
            "operation": operation,
            "operation_key": operation_key,
            "input_digest": document_digest(operation_input),
            "state": "TERMINAL",
            "result": copy.deepcopy(result),
        }
        self._write_record(self._path(operation, operation_key), document)

    def recover(
        self, operation: str, operation_key: str
    ) -> dict[str, Any] | None:
        path = self._path(operation, operation_key)
        if not path.exists():
            return None
        document = self._read_record(path)
        if (
            set(document)
            != {
                "schema_version",
                "adapter_id",
                "operation",
                "operation_key",
                "input_digest",
                "state",
                "result",
                "signature",
            }
            or
            document.get("schema_version")
            != "hive.adapter-lifecycle-operation.v1"
            or document.get("adapter_id") != self.adapter_id
            or document.get("operation") != operation
            or document.get("operation_key") != operation_key
            or document.get("state") not in {"PREPARED", "TERMINAL"}
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_OPERATION_MISMATCH",
                "lifecycle recovery record is invalid",
            )
        if document["state"] == "PREPARED":
            return None
        result = document.get("result")
        if not isinstance(result, dict):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_OPERATION_MISMATCH",
                "lifecycle recovery result is invalid",
            )
        return copy.deepcopy(result)
