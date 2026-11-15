"""Fail-closed input checks for governed local capture normalization."""

from __future__ import annotations

import re

from hive_protocol.core import ProtocolError


_CONTAINER_MEDIA_TYPES = frozenset(
    {
        "application/gzip",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "application/x-tar",
        "application/zip",
    }
)
_CONTAINER_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
)
_PROMPT_INJECTION = (
    re.compile(r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b"),
    re.compile(r"(?i)\bsystem\s+instruction\b"),
    re.compile(r"(?i)<\|(?:system|assistant|developer)\|>"),
    re.compile(r"(?i)\b(?:reveal|exfiltrate)\b.{0,80}\b(?:secret|credential|token)\b"),
)


def enforce_container_boundary(payload: bytes, media_type: str) -> None:
    if media_type.lower() in _CONTAINER_MEDIA_TYPES or any(
        payload.startswith(signature) for signature in _CONTAINER_SIGNATURES
    ):
        raise ProtocolError(
            "CAPTURE_CONTAINER_DENIED",
            "archive and compressed-container capture requires a separate bounded extractor",
        )


def enforce_media_signature(payload: bytes, media_type: str) -> None:
    declared = media_type.lower()
    signatures = {
        "application/pdf": b"%PDF-",
        "image/png": b"\x89PNG\r\n\x1a\n",
        "image/jpeg": b"\xff\xd8\xff",
    }
    observed = next(
        (kind for kind, signature in signatures.items() if payload.startswith(signature)),
        None,
    )
    expected = signatures.get(declared)
    if (observed is not None and observed != declared) or (
        expected is not None and not payload.startswith(expected)
    ):
        raise ProtocolError(
            "CAPTURE_MEDIA_TYPE_MISMATCH",
            "capture bytes do not match the declared media type",
        )


def prompt_injection_flags(text: str) -> list[str]:
    return (
        ["PROMPT_INJECTION_INDICATOR"]
        if any(pattern.search(text) for pattern in _PROMPT_INJECTION)
        else []
    )
