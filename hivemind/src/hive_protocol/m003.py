"""M003 orchestration boundary for memory review, retrieval, and receipts."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .core import document_digest, load_private_key, load_public_key, sign_document, validate_document, verify_document
from .memory import promote_memory, retrieve_memory, stage_memory_proposals, validate_memory_proposals
from .storage import atomic_write_bytes, atomic_write_json, read_json, utc_now
from .turn import _load_marker, _process_namespace, _sha256_file, _trusted_key


def propose_turn(run_dir: Path) -> dict[str, Any]:
    return stage_memory_proposals(run_dir, _load_marker(run_dir), _process_namespace())


def review_turn(run_dir: Path) -> dict[str, Any]:
    return validate_memory_proposals(run_dir, _load_marker(run_dir), _process_namespace())


def promote_turn(run_dir: Path) -> dict[str, Any]:
    return promote_memory(run_dir, _load_marker(run_dir), _process_namespace())


def retrieve_next_turn(run_dir: Path) -> dict[str, Any]:
    process_namespace = _process_namespace()
    marker = _load_marker(run_dir)
    receipt_path = run_dir / "receipts" / "turn-receipt.json"
    receipt = read_json(receipt_path)
    validate_document(receipt, "turn-receipt")
    verify_document(receipt, _trusted_key(run_dir, "consumer", marker["consumer_key_id"]))
    state = read_json(run_dir / "state" / "task-state.json")
    if state.get("last_message_id") != marker["message_id"]:
        from .core import ProtocolError

        raise ProtocolError("NEXT_TURN_STATE_MISSING", "state does not reference the consumed message")
    if state.get("values", {}).get("organizational-turn.status") != "acknowledged":
        from .core import ProtocolError

        raise ProtocolError("NEXT_TURN_STATE_MISSING", "expected state change is not retrievable")
    if document_digest(state) != receipt["artifacts"]["state_sha256"]:
        from .core import ProtocolError

        raise ProtocolError("NEXT_TURN_STATE_DRIFT", "persisted state hash changed")

    memory_readback = retrieve_memory(run_dir, marker)
    receipt["retrieved_at"] = utc_now()
    receipt["proof"]["persists_next_turn"] = "VERIFIED"
    signed = sign_document(
        receipt,
        load_private_key(run_dir / "keys" / "consumer.private.pem"),
    )
    validate_document(signed, "turn-receipt")
    atomic_write_json(receipt_path, signed)

    lab_root = Path(marker["lab_root"])
    evidence_root = lab_root / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_root / f"{marker['run_id']}.turn-receipt.json"
    atomic_write_json(evidence_path, signed)
    consumer_public_source = run_dir / "keys" / "consumer.public.pem"
    load_public_key(consumer_public_source)
    consumer_public_path = evidence_root / f"{marker['run_id']}.consumer.public.pem"
    atomic_write_bytes(consumer_public_path, consumer_public_source.read_bytes())
    retrieval = {
        "schema_version": "hive.next-turn-retrieval.v1",
        "run_id": marker["run_id"],
        "message_id": marker["message_id"],
        "retrieved_at": signed["retrieved_at"],
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
        "receipt_sha256": document_digest(signed),
        "state_sha256": document_digest(state),
        "vault_note_sha256": signed["artifacts"]["vault_note_sha256"],
        "consumer_public_key_sha256": _sha256_file(consumer_public_path),
        **memory_readback,
    }
    atomic_write_json(evidence_root / f"{marker['run_id']}.retrieval.json", retrieval)
    return {"outcome": "RETRIEVED_NEXT_TURN", **retrieval}
