"""Immutable canonical objects for governed capture and citation anchors."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, document_digest


_SCHEMA_NAMES = frozenset(
    {
        "capture-envelope.v1.schema.json",
        "source-record.v1.schema.json",
    }
)
_ANCHOR_KEYS = frozenset(
    {
        "anchor_id",
        "source_id",
        "source_sha256",
        "normalized_sha256",
        "quote",
        "quote_sha256",
        "char_start",
        "char_end",
        "byte_start",
        "byte_end",
        "locator",
    }
)


def validate_capture_document(
    schema_name: str, document: Mapping[str, Any]
) -> None:
    """Validate one closed M3.1 capture document without mutating its caller."""

    if schema_name not in _SCHEMA_NAMES:
        raise ProtocolError(
            "CAPTURE_DOCUMENT_SCHEMA_UNKNOWN",
            "unsupported capture document schema",
        )
    candidate = copy.deepcopy(dict(document))
    reject_credential_values(candidate, location="capture document")
    schema = json.loads(
        files("hive_protocol.schemas")
        .joinpath(schema_name)
        .read_text(encoding="utf-8")
    )
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            candidate
        ),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ProtocolError(
            "CAPTURE_DOCUMENT_SCHEMA_INVALID",
            f"{location}: {first.message}",
        )


def capture_document_digest(document: Mapping[str, Any]) -> str:
    return document_digest(document)


def _body(document: Mapping[str, Any], version: str) -> dict[str, Any]:
    if document.get("schema_version") != version:
        raise ProtocolError(
            "CAPTURE_DOCUMENT_VERSION", "unsupported capture document version"
        )
    body = copy.deepcopy(dict(document))
    body.pop("schema_version")
    return body


@dataclass(frozen=True)
class CitationAnchor:
    anchor_id: str
    source_id: str
    source_sha256: str
    normalized_sha256: str
    quote: str
    quote_sha256: str
    char_start: int
    char_end: int
    byte_start: int
    byte_end: int
    locator: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "locator", copy.deepcopy(self.locator))

    def as_dict(self) -> dict[str, Any]:
        return {
            "anchor_id": self.anchor_id,
            "source_id": self.source_id,
            "source_sha256": self.source_sha256,
            "normalized_sha256": self.normalized_sha256,
            "quote": self.quote,
            "quote_sha256": self.quote_sha256,
            "char_start": self.char_start,
            "char_end": self.char_end,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "locator": copy.deepcopy(self.locator),
        }

    @classmethod
    def from_text(
        cls,
        *,
        source_id: str,
        source_sha256: str,
        normalized_text: str,
        char_start: int,
        char_end: int,
        locator: Mapping[str, Any],
    ) -> "CitationAnchor":
        if (
            not isinstance(char_start, int)
            or isinstance(char_start, bool)
            or not isinstance(char_end, int)
            or isinstance(char_end, bool)
            or char_start < 0
            or char_end <= char_start
            or char_end > len(normalized_text)
        ):
            raise ProtocolError(
                "CAPTURE_ANCHOR_MISMATCH", "citation character range is invalid"
            )
        quote = normalized_text[char_start:char_end]
        normalized_sha256 = hashlib.sha256(
            normalized_text.encode("utf-8")
        ).hexdigest()
        byte_start = len(normalized_text[:char_start].encode("utf-8"))
        byte_end = len(normalized_text[:char_end].encode("utf-8"))
        body = {
            "source_id": source_id,
            "source_sha256": source_sha256,
            "normalized_sha256": normalized_sha256,
            "quote": quote,
            "quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
            "char_start": char_start,
            "char_end": char_end,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "locator": copy.deepcopy(dict(locator)),
        }
        anchor_id = f"anchor:{document_digest(body)}"
        return cls(anchor_id=anchor_id, **body)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "CitationAnchor":
        candidate = copy.deepcopy(dict(document))
        reject_credential_values(candidate, location="citation anchor")
        if set(candidate) != _ANCHOR_KEYS:
            raise ProtocolError(
                "CAPTURE_ANCHOR_MISMATCH", "citation anchor fields changed"
            )
        return cls(**candidate)

    def verify(self, normalized_text: str) -> None:
        if not isinstance(normalized_text, str):
            raise ProtocolError(
                "CAPTURE_ANCHOR_MISMATCH", "normalized citation text is invalid"
            )
        encoded = normalized_text.encode("utf-8")
        if (
            hashlib.sha256(encoded).hexdigest() != self.normalized_sha256
            or not isinstance(self.char_start, int)
            or isinstance(self.char_start, bool)
            or not isinstance(self.char_end, int)
            or isinstance(self.char_end, bool)
            or self.char_start < 0
            or self.char_end <= self.char_start
            or self.char_end > len(normalized_text)
            or normalized_text[self.char_start : self.char_end] != self.quote
            or hashlib.sha256(self.quote.encode("utf-8")).hexdigest()
            != self.quote_sha256
            or len(normalized_text[: self.char_start].encode("utf-8"))
            != self.byte_start
            or len(normalized_text[: self.char_end].encode("utf-8"))
            != self.byte_end
            or encoded[self.byte_start : self.byte_end]
            != self.quote.encode("utf-8")
        ):
            raise ProtocolError(
                "CAPTURE_ANCHOR_MISMATCH",
                "citation anchor does not match normalized text",
            )
        expected = self.as_dict()
        anchor_id = expected.pop("anchor_id")
        if anchor_id != f"anchor:{document_digest(expected)}":
            raise ProtocolError(
                "CAPTURE_ANCHOR_MISMATCH", "citation anchor ID changed"
            )


@dataclass(frozen=True)
class CaptureEnvelope:
    capture_id: str
    tenant_id: str
    project_id: str
    privacy_class: str
    channel: str
    source_owner: str
    acquired_at: str
    rights_assertion: str
    original_sha256: str
    original_size_bytes: int
    media_type: str
    parser: dict[str, Any]
    transformations: list[dict[str, Any]]
    risk_flags: list[str]
    admission_state: str
    destination: str
    source_record_id: str | None
    receipt_ref: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "parser", copy.deepcopy(self.parser))
        object.__setattr__(
            self, "transformations", copy.deepcopy(self.transformations)
        )
        object.__setattr__(self, "risk_flags", list(self.risk_flags))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.capture-envelope.v1",
            "capture_id": self.capture_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "privacy_class": self.privacy_class,
            "channel": self.channel,
            "source_owner": self.source_owner,
            "acquired_at": self.acquired_at,
            "rights_assertion": self.rights_assertion,
            "original_sha256": self.original_sha256,
            "original_size_bytes": self.original_size_bytes,
            "media_type": self.media_type,
            "parser": copy.deepcopy(self.parser),
            "transformations": copy.deepcopy(self.transformations),
            "risk_flags": list(self.risk_flags),
            "admission_state": self.admission_state,
            "destination": self.destination,
            "source_record_id": self.source_record_id,
            "receipt_ref": self.receipt_ref,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "CaptureEnvelope":
        validate_capture_document("capture-envelope.v1.schema.json", document)
        return cls(**_body(document, "hive.capture-envelope.v1"))


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    tenant_id: str
    project_id: str
    privacy_class: str
    original_asset_path: str
    original_sha256: str
    original_size_bytes: int
    normalized_text_path: str | None
    normalized_sha256: str | None
    media_type: str
    parser: dict[str, Any]
    transformations: list[str]
    capture_ids: list[str]
    anchors: list[dict[str, Any]]
    created_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "parser", copy.deepcopy(self.parser))
        object.__setattr__(self, "transformations", list(self.transformations))
        object.__setattr__(self, "capture_ids", list(self.capture_ids))
        object.__setattr__(self, "anchors", copy.deepcopy(self.anchors))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.source-record.v1",
            "source_id": self.source_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "privacy_class": self.privacy_class,
            "original_asset_path": self.original_asset_path,
            "original_sha256": self.original_sha256,
            "original_size_bytes": self.original_size_bytes,
            "normalized_text_path": self.normalized_text_path,
            "normalized_sha256": self.normalized_sha256,
            "media_type": self.media_type,
            "parser": copy.deepcopy(self.parser),
            "transformations": list(self.transformations),
            "capture_ids": list(self.capture_ids),
            "anchors": copy.deepcopy(self.anchors),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "SourceRecord":
        validate_capture_document("source-record.v1.schema.json", document)
        body = _body(document, "hive.source-record.v1")
        normalized_path = body["normalized_text_path"]
        normalized_digest = body["normalized_sha256"]
        anchors = body["anchors"]
        if (normalized_path is None) != (normalized_digest is None) or (
            normalized_path is None and anchors
        ):
            raise ProtocolError(
                "CAPTURE_SOURCE_RECORD_INVALID",
                "normalized source path, digest, and anchors are inconsistent",
            )
        for anchor_document in anchors:
            anchor = CitationAnchor.from_dict(anchor_document)
            if (
                anchor.source_id != body["source_id"]
                or anchor.source_sha256 != body["original_sha256"]
                or anchor.normalized_sha256 != normalized_digest
            ):
                raise ProtocolError(
                    "CAPTURE_SOURCE_RECORD_INVALID",
                    "citation anchor is not bound to its source record",
                )
        return cls(**body)
