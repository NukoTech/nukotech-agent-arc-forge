from __future__ import annotations

import copy
import hashlib

import pytest

from hive_protocol.capture.models import (
    CaptureEnvelope,
    CitationAnchor,
    SourceRecord,
    capture_document_digest,
    validate_capture_document,
)
from hive_protocol.core import ProtocolError


NORMALIZED = "# Capture\n\nThe frozen parent is the rollback target.\n"
NORMALIZED_SHA = hashlib.sha256(NORMALIZED.encode("utf-8")).hexdigest()
ORIGINAL_SHA = hashlib.sha256(b"original capture bytes").hexdigest()


def anchor_document() -> dict:
    quote = "The frozen parent is the rollback target."
    start = NORMALIZED.index(quote)
    return CitationAnchor.from_text(
        source_id="source:alpha",
        source_sha256=ORIGINAL_SHA,
        normalized_text=NORMALIZED,
        char_start=start,
        char_end=start + len(quote),
        locator={"kind": "line", "line_start": 3, "line_end": 3},
    ).as_dict()


def capture_document() -> dict:
    return {
        "schema_version": "hive.capture-envelope.v1",
        "capture_id": "capture:alpha-001",
        "tenant_id": "tenant:local",
        "project_id": "HiveMind",
        "privacy_class": "PROJECT_PRIVATE",
        "channel": "MARKDOWN",
        "source_owner": "Owner",
        "acquired_at": "2026-08-31T22:00:00-05:00",
        "rights_assertion": "USER_PROVIDED",
        "original_sha256": ORIGINAL_SHA,
        "original_size_bytes": 22,
        "media_type": "text/markdown",
        "parser": {"parser_id": "builtin.markdown", "version": "1.0.0"},
        "transformations": [
            {
                "kind": "UTF8_NORMALIZATION",
                "input_sha256": ORIGINAL_SHA,
                "output_sha256": NORMALIZED_SHA,
            }
        ],
        "risk_flags": ["PROMPT_INJECTION_INDICATOR"],
        "admission_state": "ADMITTED_STAGING",
        "destination": "STAGING",
        "source_record_id": "source:alpha",
        "receipt_ref": "receipt:capture-alpha",
    }


def source_document() -> dict:
    return {
        "schema_version": "hive.source-record.v1",
        "source_id": "source:alpha",
        "tenant_id": "tenant:local",
        "project_id": "HiveMind",
        "privacy_class": "PROJECT_PRIVATE",
        "original_asset_path": "assets/asset-alpha/original.md",
        "original_sha256": ORIGINAL_SHA,
        "original_size_bytes": 22,
        "normalized_text_path": "sources/source-alpha/normalized.md",
        "normalized_sha256": NORMALIZED_SHA,
        "media_type": "text/markdown",
        "parser": {"parser_id": "builtin.markdown", "version": "1.0.0"},
        "transformations": ["UTF8_NORMALIZATION"],
        "capture_ids": ["capture:alpha-001"],
        "anchors": [anchor_document()],
        "created_at": "2026-08-31T22:00:01-05:00",
    }


def test_capture_envelope_round_trip_is_immutable_and_canonical() -> None:
    document = capture_document()
    model = CaptureEnvelope.from_dict(document)
    document["parser"]["parser_id"] = "mutated"
    document["risk_flags"].append("MUTATED")

    restored = model.as_dict()
    assert restored == capture_document()
    validate_capture_document("capture-envelope.v1.schema.json", restored)
    assert capture_document_digest(restored) == capture_document_digest(
        CaptureEnvelope.from_dict(restored).as_dict()
    )


def test_source_record_and_anchor_round_trip_and_verify_exact_text() -> None:
    document = source_document()
    record = SourceRecord.from_dict(document)
    document["anchors"][0]["locator"]["line_start"] = 99

    restored = record.as_dict()
    assert restored == source_document()
    validate_capture_document("source-record.v1.schema.json", restored)
    CitationAnchor.from_dict(restored["anchors"][0]).verify(NORMALIZED)


def test_anchor_rejects_quote_or_byte_offset_drift() -> None:
    anchor = anchor_document()
    anchor["quote"] = "The mutable child is the rollback target."
    anchor["quote_sha256"] = hashlib.sha256(anchor["quote"].encode()).hexdigest()
    with pytest.raises(ProtocolError, match="CAPTURE_ANCHOR_MISMATCH"):
        CitationAnchor.from_dict(anchor).verify(NORMALIZED)

    anchor = anchor_document()
    anchor["byte_end"] -= 1
    with pytest.raises(ProtocolError, match="CAPTURE_ANCHOR_MISMATCH"):
        CitationAnchor.from_dict(anchor).verify(NORMALIZED)


@pytest.mark.parametrize(
    ("schema_name", "document"),
    [
        ("capture-envelope.v1.schema.json", capture_document()),
        ("source-record.v1.schema.json", source_document()),
    ],
)
def test_capture_schemas_reject_unknown_fields(schema_name: str, document: dict) -> None:
    document["implied_admin"] = True
    with pytest.raises(ProtocolError, match="CAPTURE_DOCUMENT_SCHEMA_INVALID"):
        validate_capture_document(schema_name, document)


def test_capture_documents_reject_credential_shaped_metadata() -> None:
    document = capture_document()
    document["source_owner"] = "api_key=not-a-real-secret-value"
    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        CaptureEnvelope.from_dict(document)


def test_source_record_requires_normalized_fields_and_anchors_together() -> None:
    document = source_document()
    document["normalized_text_path"] = None
    with pytest.raises(ProtocolError, match="CAPTURE_SOURCE_RECORD_INVALID"):
        SourceRecord.from_dict(document)

    degraded = source_document()
    degraded["normalized_text_path"] = None
    degraded["normalized_sha256"] = None
    degraded["anchors"] = []
    validate_capture_document("source-record.v1.schema.json", degraded)
    assert SourceRecord.from_dict(degraded).as_dict() == degraded


def test_capture_validation_does_not_mutate_caller_document() -> None:
    document = source_document()
    original = copy.deepcopy(document)
    SourceRecord.from_dict(document)
    assert document == original
