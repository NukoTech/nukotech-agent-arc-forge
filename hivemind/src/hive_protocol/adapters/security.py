"""Persistence-boundary checks for adapter credential values."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hive_protocol.core import (
    ProtocolError,
    b64url_decode_strict,
    b64url_encode,
    verify_document,
)


_REFERENCE = re.compile(
    r"^(?:keychain|secret-service|credential-manager|manual):[A-Za-z0-9._/:-]{1,240}$"
)
_SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:password|passwd|secret|token|api_?key|private_?key|credential_?value)(?:$|_)",
    re.IGNORECASE,
)
_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9+/=_-]{8,}"),
    re.compile(
        r"(?i)\b[A-Za-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]{8,}"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
)
_CREDENTIAL_STATES = frozenset({"AVAILABLE", "MISSING", "NOT_REQUIRED"})
# Canonical unpadded base64url of exactly 64 bytes (one Ed25519 signature).
_ED25519_SIGNATURE_VALUE = re.compile(r"[A-Za-z0-9_-]{86}")


def _deny(location: str) -> None:
    raise ProtocolError(
        "ADAPTER_CREDENTIAL_VALUE_DENIED",
        f"credential material is forbidden in {location}",
    )


def _verified_signature_value(
    document: dict[Any, Any],
    verified_by: Mapping[str, Ed25519PublicKey] | None,
) -> str | None:
    """Return document["signature"]["value"] only if it is a verified Ed25519 signature.

    The value must be canonical base64url that decodes to exactly 64 bytes and
    must pass verify_document over this exact document with a trusted key.
    Anything else, including any exception, returns None so the value is
    scanned as usual (fail closed).
    """

    if not verified_by:
        return None
    try:
        signature = document.get("signature")
        if not isinstance(signature, dict):
            return None
        value = signature.get("value")
        if not isinstance(value, str) or not _ED25519_SIGNATURE_VALUE.fullmatch(value):
            return None
        raw = b64url_decode_strict(value, expected_len=64)
        if len(raw) != 64 or b64url_encode(raw) != value:
            return None
        verify_document(document, verified_by)
    except Exception:
        return None
    return value


def reject_credential_values(
    value: Any,
    *,
    location: str,
    verified_by: Mapping[str, Ed25519PublicKey] | None = None,
) -> None:
    """Reject credential material before an adapter document is persisted.

    With ``verified_by`` (trusted public keys), the one string at
    ``signature.value`` of a dict is not pattern-scanned when that exact value
    verifies as a 64-byte Ed25519 signature over that exact dict. Random
    signature bytes can otherwise resemble a token prefix such as ``sk-``.
    Every other field, including the rest of the signature object, is checked.
    """

    def visit(current: Any, path: str, verified_value: str | None = None) -> None:
        if isinstance(current, dict):
            exempt = _verified_signature_value(current, verified_by)
            for key, child in current.items():
                if not isinstance(key, str):
                    visit(child, f"{path}.<non-string-key>")
                    continue
                child_path = f"{path}.{key}"
                normalized = key.lower().replace("-", "_")
                if normalized == "credential_references":
                    if (
                        not isinstance(child, list)
                        or not all(
                            isinstance(item, str) and _REFERENCE.fullmatch(item)
                            for item in child
                        )
                    ):
                        _deny(child_path)
                    continue
                if normalized == "credential_reference":
                    if not isinstance(child, str) or _REFERENCE.fullmatch(child) is None:
                        _deny(child_path)
                    continue
                if normalized == "credential_state":
                    if child not in _CREDENTIAL_STATES:
                        _deny(child_path)
                    continue
                if (
                    _SENSITIVE_KEY.search(normalized)
                    and child is not None
                    and child != ""
                    and child != []
                    and child != {}
                ):
                    _deny(child_path)
                if key == "value" and verified_value is not None and child is verified_value:
                    continue
                if key == "signature" and exempt is not None:
                    visit(child, child_path, exempt)
                    continue
                visit(child, child_path)
            return
        if isinstance(current, (list, tuple)):
            for index, child in enumerate(current):
                visit(child, f"{path}[{index}]")
            return
        if isinstance(current, str) and any(
            pattern.search(current) for pattern in _VALUE_PATTERNS
        ):
            _deny(path)

    visit(value, location)
