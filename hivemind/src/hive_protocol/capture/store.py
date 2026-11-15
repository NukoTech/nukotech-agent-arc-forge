"""Authenticated private operation journals for crash-safe capture admission."""

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

from hive_protocol.core import (
    ProtocolError,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.storage import atomic_write_json, read_json


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STAGES = frozenset(
    {
        "PREPARED",
        "ORIGINAL_WRITTEN",
        "NORMALIZED_WRITTEN",
        "ROLLING_BACK",
        "TERMINAL",
        "ROLLED_BACK",
    }
)


class CaptureOperationStore:
    """Stores one signed, input-bound transaction document per operation key."""

    def __init__(
        self,
        root: Path,
        *,
        signing_key: Ed25519PrivateKey,
        trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> None:
        raw = root.expanduser()
        for candidate in [raw, *raw.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "CAPTURE_STATE_BOUNDARY",
                    "capture state path may not contain symlinks",
                )
        self.root = raw.resolve(strict=False)
        self.signing_key = signing_key
        self.key_id = public_key_id(signing_key.public_key())
        self.trusted_keys = dict(
            trusted_keys or {self.key_id: signing_key.public_key()}
        )
        if self.key_id not in self.trusted_keys:
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH", "capture journal signer is not trusted"
            )

    def ensure_root(self) -> None:
        if self.root.is_symlink():
            raise ProtocolError(
                "CAPTURE_STATE_BOUNDARY", "capture state root may not be a symlink"
            )
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            self.root.is_symlink()
            or not self.root.is_dir()
            or self.root.resolve() != self.root
            or self.root.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "CAPTURE_STATE_BOUNDARY",
                "capture state root is not an owned canonical directory",
            )
        os.chmod(self.root, 0o700)

    def path(self, operation_key: str) -> Path:
        if _SHA256.fullmatch(operation_key) is None:
            raise ProtocolError(
                "CAPTURE_OPERATION_KEY_INVALID",
                "capture operation key must be an exact SHA-256",
            )
        self.ensure_root()
        return self.root / f"capture-{operation_key}.json"

    def read(self, operation_key: str) -> dict[str, Any] | None:
        path = self.path(operation_key)
        if not path.exists():
            return None
        try:
            document = read_json(path)
            verify_document(document, self.trusted_keys)
        except ProtocolError as exc:
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH",
                "capture operation journal is not authentic",
            ) from exc
        signature = document.get("signature")
        if (
            not isinstance(signature, dict)
            or signature.get("key_id") != self.key_id
            or document.get("schema_version") != "hive.capture-operation.v2"
            or document.get("operation_key") != operation_key
            or document.get("stage") not in _STAGES
            or not isinstance(document.get("plan_digest"), str)
            or _SHA256.fullmatch(document["plan_digest"]) is None
            or not isinstance(document.get("transaction"), dict)
            or not isinstance(document.get("rollback"), list)
            or document.get("result") is not None
            and not isinstance(document.get("result"), dict)
        ):
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH",
                "capture operation journal shape changed",
            )
        return copy.deepcopy(document)

    def write(self, document: Mapping[str, Any]) -> None:
        operation_key = document.get("operation_key")
        if not isinstance(operation_key, str):
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH", "capture operation key is absent"
            )
        candidate = copy.deepcopy(dict(document))
        candidate.pop("signature", None)
        if candidate.get("stage") not in _STAGES:
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH", "capture operation stage is invalid"
            )
        signed = sign_document(candidate, self.signing_key)
        verify_document(signed, self.trusted_keys)
        atomic_write_json(self.path(operation_key), signed, mode=0o600)
