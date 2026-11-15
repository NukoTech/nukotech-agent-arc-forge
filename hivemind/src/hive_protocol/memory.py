"""Signed, proposal-only memory promotion for the disposable LAB adapter."""

from __future__ import annotations

import os
import re
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from .core import (
    ProtocolError,
    document_digest,
    load_private_key,
    load_public_key,
    require_assigned_persona,
    sign_document,
    validate_document,
    verify_document,
)
from .storage import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json, utc_now


BASE_NAMES = (
    "promotion-queue.base",
    "current-state.base",
    "durable-facts.base",
    "contradictions.base",
    "stale-review.base",
    "snapshots.base",
    "moc-coverage.base",
    "two-stage-pruning.base",
)
STAGING_BASE_NAMES = ("promotion-queue.base", "contradictions.base")
PRIME_BASE_NAMES = tuple(name for name in BASE_NAMES if name not in STAGING_BASE_NAMES)
EXPECTED_BASE_VIEWS = {
    "promotion-queue.base": {"Promotion queue"},
    "current-state.base": {"Current state"},
    "durable-facts.base": {"Durable facts"},
    "contradictions.base": {"Contradictions"},
    "stale-review.base": {"Stale review"},
    "snapshots.base": {"Agent and project snapshots"},
    "moc-coverage.base": {"MOC coverage"},
    "two-stage-pruning.base": {"Prune stage one", "Prune stage two quarantine"},
}


def _safe_id(value: str) -> str:
    if not value.isascii() or not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        raise ProtocolError("MEMORY_ID_DENIED", f"unsafe memory identifier: {value}")
    return value


def _safe_note_name(value: str) -> str:
    if not value.isascii() or not re.fullmatch(r"[A-Za-z0-9 ._-]+", value):
        raise ProtocolError("NOTE_NAME_DENIED", f"unsafe Obsidian note name: {value}")
    return value


def _safe_narrative(value: str) -> str:
    lowered = value.lower()
    if any(token in lowered for token in ("[[", "]]", "javascript:", "file://", "<script")):
        raise ProtocolError("OBSIDIAN_LINK_DENIED", "narrative contains an unreviewed link construct")
    return value


def _sha256_file(path: Path) -> str:
    import hashlib

    if path.is_symlink() or not path.is_file():
        raise ProtocolError("MISSING_ARTIFACT", f"expected regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def _trusted_key(run_dir: Path, label: str, key_id: str) -> dict[str, Any]:
    return {key_id: load_public_key(run_dir / "keys" / f"{label}.public.pem")}


def _frontmatter_note(metadata: dict[str, Any], title: str, body: str) -> bytes:
    _safe_note_name(title)
    rendered = yaml.safe_dump(
        metadata,
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
    )
    return f"---\n{rendered}---\n\n# {title}\n\n{body.rstrip()}\n".encode("utf-8")


def _read_frontmatter(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError("MEMORY_ARTIFACT_INVALID", f"not a regular Markdown file: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise ProtocolError("MEMORY_ARTIFACT_INVALID", f"frontmatter is absent: {path}")
    raw = text[4:].split("\n---\n", 1)[0]
    value = yaml.safe_load(raw)
    if not isinstance(value, dict):
        raise ProtocolError("MEMORY_ARTIFACT_INVALID", f"frontmatter root is not a mapping: {path}")
    return value


def _load_base(name: str) -> tuple[bytes, dict[str, Any]]:
    if name not in BASE_NAMES:
        raise ProtocolError("BASE_DENIED", f"unregistered Base: {name}")
    payload = files("hive_protocol").joinpath("bases", name).read_bytes()
    document = yaml.safe_load(payload.decode("utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("views"), list):
        raise ProtocolError("BASE_INVALID", f"invalid Base structure: {name}")
    view_names = {
        view.get("name") for view in document["views"] if isinstance(view, dict)
    }
    if view_names != EXPECTED_BASE_VIEWS[name]:
        raise ProtocolError("BASE_INVALID", f"unexpected view inventory: {name}")
    return payload, document


def _proposal_paths(staging_root: Path) -> list[Path]:
    root = staging_root / "_proposals"
    if root.is_symlink():
        raise ProtocolError("PROPOSAL_LANE_DENIED", "proposal root cannot be a symlink")
    paths = sorted(root.glob("*/*/*.json"))
    if not paths:
        raise ProtocolError("PROPOSAL_MISSING", "no staged memory proposals exist")
    if any(path.is_symlink() for path in paths):
        raise ProtocolError("PROPOSAL_LANE_DENIED", "proposal cannot be a symlink")
    return paths


def _validate_turn_inputs(
    run_dir: Path,
    marker: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    envelope = read_json(
        run_dir
        / "mailbox"
        / "inbox"
        / marker["recipient"]["surface"]
        / f"{marker['message_id']}.json"
    )
    acknowledgment = read_json(run_dir / "receipts" / "acknowledgment.json")
    delivery = read_json(run_dir / "receipts" / "delivery.json")
    state = read_json(run_dir / "state" / "task-state.json")
    validate_document(envelope, "work-envelope")
    require_assigned_persona(envelope["identity"])
    validate_document(acknowledgment, "acknowledgment")
    verify_document(envelope, _trusted_key(run_dir, "issuer", marker["issuer_key_id"]))
    verify_document(
        acknowledgment,
        _trusted_key(run_dir, "consumer", marker["consumer_key_id"]),
    )
    if acknowledgment["outcome"] != "APPLIED" or not acknowledgment["state"]["changed"]:
        raise ProtocolError("PROMOTION_INELIGIBLE", "only applied state changes are promotable")
    if acknowledgment["message_id"] != marker["message_id"]:
        raise ProtocolError("ACKNOWLEDGMENT_MISMATCH", "acknowledgment references another message")
    if acknowledgment["state"]["after_sha256"] != document_digest(state):
        raise ProtocolError("STATE_RECEIPT_MISMATCH", "acknowledgment does not match persisted state")
    if (
        delivery.get("message_id") != marker["message_id"]
        or delivery.get("envelope_sha256") != document_digest(envelope)
        or delivery.get("machine") != marker["recipient"]["machine"]
        or delivery.get("recipient_surface") != marker["recipient"]["surface"]
    ):
        raise ProtocolError("DELIVERY_RECEIPT_MISMATCH", "delivery receipt does not match the turn")
    return envelope, acknowledgment, delivery, state


def stage_memory_proposals(
    run_dir: Path,
    marker: dict[str, Any],
    process_namespace: str,
) -> dict[str, Any]:
    envelope, acknowledgment, _, _ = _validate_turn_inputs(run_dir, marker)
    capabilities = set(envelope["authority"]["capabilities"])
    if not {"vault:stage", "vault:propose"}.issubset(capabilities):
        raise ProtocolError("CAPABILITY_DENIED", "proposal capabilities are absent")
    if (run_dir / "vault-prime").exists():
        raise ProtocolError("DIRECT_PRIME_WRITE_DENIED", "PRIME exists before reviewed promotion")

    identity = envelope["identity"]
    identity_digest = document_digest(identity)
    source_digest = document_digest(acknowledgment)
    recorded_at = utc_now()
    after_value = acknowledgment["state"]["after"]
    definitions = (
        (
            "PERSONA",
            identity["persona"]["id"],
            "DURABLE_FACT",
            f"persona.{identity['persona']['id']}.organizational-turn.status",
            "The LAB organizational turn reached the acknowledged task state.",
        ),
        (
            "SURFACE",
            identity["surface"]["id"],
            "SNAPSHOT",
            f"surface.{identity['surface']['id']}.last-turn-state",
            "The lab surface consumed the work envelope and persisted its permitted state change.",
        ),
    )
    staging_root = run_dir / "vault-staging"
    results: list[dict[str, str]] = []
    for lane_kind, lane_owner, record_type, fact_key, narrative in definitions:
        proposal_id = str(uuid4())
        stable_id = f"memory:{proposal_id}"
        proposal = {
            "schema_version": "hive.memory-proposal.v1",
            "proposal_id": proposal_id,
            "message_id": marker["message_id"],
            "lane": {"kind": lane_kind, "owner_id": _safe_id(lane_owner)},
            "record": {
                "record_type": record_type,
                "stable_id": stable_id,
                "fact_key": _safe_id(fact_key),
                "value": after_value,
                "narrative": _safe_narrative(narrative),
                "source_ref": f"ack:{acknowledgment['ack_id']}",
                "source_sha256": source_digest,
                "occurred_at": acknowledgment["consumed_at"],
                "recorded_at": recorded_at,
                "confidence": 1.0,
                "target_moc": "MOC HiveMind",
                "status": "PROPOSED",
                "supersedes": None,
                "precondition_sha256": None,
            },
            "identity_context_sha256": identity_digest,
            "privacy": "non-private",
            "target": {
                "vault": "HiveVault",
                "tier": "PRIME_SHARED",
                "namespace": "hive/lab/m003",
            },
        }
        signed = sign_document(
            proposal,
            load_private_key(run_dir / "keys" / "consumer.private.pem"),
        )
        validate_document(signed, "memory-proposal")
        lane_root = staging_root / "_proposals" / lane_kind.lower() / lane_owner
        json_path = lane_root / f"{proposal_id}.json"
        note_path = lane_root / f"{proposal_id}.md"
        atomic_write_json(json_path, signed)
        metadata = {
            "type": "hive-memory-proposal",
            "status": "PROPOSED",
            "proposal_id": proposal_id,
            "record_type": record_type,
            "lane_kind": lane_kind,
            "lane_owner": lane_owner,
            "fact_key": fact_key,
            "recorded_at": recorded_at,
            "target_moc": "[[MOC HiveMind]]",
            "proposal_sha256": document_digest(signed),
        }
        atomic_write_bytes(
            note_path,
            _frontmatter_note(metadata, f"Proposal {proposal_id}", narrative),
        )
        results.append(
            {
                "proposal_id": proposal_id,
                "lane": f"{lane_kind}:{lane_owner}",
                "proposal_sha256": document_digest(signed),
            }
        )

    for name in STAGING_BASE_NAMES:
        base_payload, _ = _load_base(name)
        atomic_write_bytes(staging_root / "90-Bases" / name, base_payload)
    receipt = {
        "schema_version": "hive.proposal-staging.v1",
        "message_id": marker["message_id"],
        "staged_at": recorded_at,
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
        "proposals": results,
        "prime_write": False,
    }
    atomic_write_json(run_dir / "receipts" / "proposal-staging.json", receipt)
    return {"outcome": "STAGED_PROPOSALS", **receipt}


def validate_memory_proposals(
    run_dir: Path,
    marker: dict[str, Any],
    process_namespace: str,
) -> dict[str, Any]:
    envelope, _, _, _ = _validate_turn_inputs(run_dir, marker)
    if "vault:promote" not in envelope["authority"]["capabilities"]:
        raise ProtocolError("CAPABILITY_DENIED", "promotion review capability is absent")
    staging_root = run_dir / "vault-staging"
    proposals: list[dict[str, Any]] = []
    proposal_digests: list[str] = []
    conflicts: list[dict[str, Any]] = []
    values_by_fact: dict[str, Any] = {}
    identity = envelope["identity"]
    for proposal_path in _proposal_paths(staging_root):
        proposal = read_json(proposal_path)
        validate_document(proposal, "memory-proposal")
        verify_document(
            proposal,
            _trusted_key(run_dir, "consumer", marker["consumer_key_id"]),
        )
        if proposal["message_id"] != marker["message_id"]:
            raise ProtocolError("PROPOSAL_MESSAGE_MISMATCH", "proposal references another turn")
        if proposal["identity_context_sha256"] != document_digest(identity):
            raise ProtocolError("PROPOSAL_IDENTITY_MISMATCH", "proposal identity binding differs")
        lane = proposal["lane"]
        expected_owner = (
            identity["persona"]["id"]
            if lane["kind"] == "PERSONA"
            else identity["surface"]["id"]
        )
        if lane["owner_id"] != expected_owner:
            raise ProtocolError("PROPOSAL_LANE_DENIED", "proposal lane owner is forged")
        if proposal["privacy"] != "non-private" or proposal["target"]["tier"] != "PRIME_SHARED":
            raise ProtocolError("PRIME_PRIVACY_DENIED", "only reviewed non-private shared knowledge is eligible")
        fact_key = _safe_id(proposal["record"]["fact_key"])
        current = values_by_fact.get(fact_key)
        if current is not None and current != proposal["record"]["value"]:
            conflicts.append(
                {
                    "fact_key": fact_key,
                    "reason_code": "CURRENT_VALUE_CONTRADICTS_PROPOSAL",
                    "current_sha256": None,
                    "expected_sha256": proposal["record"]["precondition_sha256"],
                }
            )
        values_by_fact[fact_key] = proposal["record"]["value"]

        folder = "30-Durable-Facts" if proposal["record"]["record_type"] == "DURABLE_FACT" else "40-Snapshots"
        current_path = run_dir / "vault-prime" / folder / f"{fact_key}.md"
        expected_sha = proposal["record"]["precondition_sha256"]
        if current_path.exists():
            current_sha = _sha256_file(current_path)
            if expected_sha is None:
                conflicts.append(
                    {"fact_key": fact_key, "reason_code": "MISSING_PRECONDITION", "current_sha256": current_sha, "expected_sha256": None}
                )
            elif expected_sha != current_sha:
                conflicts.append(
                    {"fact_key": fact_key, "reason_code": "PRECONDITION_MISMATCH", "current_sha256": current_sha, "expected_sha256": expected_sha}
                )
        elif expected_sha is not None:
            conflicts.append(
                {"fact_key": fact_key, "reason_code": "PRECONDITION_MISMATCH", "current_sha256": None, "expected_sha256": expected_sha}
            )
        proposals.append(proposal)
        proposal_digests.append(document_digest(proposal))

    reviewed_at = utc_now()
    outcome = "CONFLICT" if conflicts else "APPROVED"
    decision = {
        "schema_version": "hive.promotion-decision.v1",
        "decision_id": str(uuid4()),
        "message_id": marker["message_id"],
        "reviewed_at": reviewed_at,
        "reviewer": {
            "worker_id": "Hive-reviewer-LAB-fixture",
            "grant_ref": "Owner sample authorization",
            "process_id": os.getpid(),
            "process_namespace": process_namespace,
        },
        "outcome": outcome,
        "proposal_sha256": sorted(proposal_digests),
        "conflicts": conflicts,
    }
    signed = sign_document(
        decision,
        load_private_key(run_dir / "keys" / "reviewer.private.pem"),
    )
    validate_document(signed, "promotion-decision")
    atomic_write_json(run_dir / "receipts" / "promotion-decision.json", signed)
    for index, conflict in enumerate(conflicts):
        metadata = {
            "type": "hive-contradiction",
            "status": "UNRESOLVED",
            "fact_key": conflict["fact_key"],
            "reason_code": conflict["reason_code"],
            "detected_at": reviewed_at,
            "proposal_id": proposals[min(index, len(proposals) - 1)]["proposal_id"],
        }
        atomic_write_bytes(
            staging_root / "_contradictions" / f"{decision['decision_id']}-{index}.md",
            _frontmatter_note(metadata, f"Contradiction {decision['decision_id']} {index}", "Promotion stopped pending explicit review."),
        )
    return {
        "outcome": outcome,
        "decision_id": decision["decision_id"],
        "proposal_count": len(proposals),
        "conflict_count": len(conflicts),
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
        "decision_sha256": document_digest(signed),
    }


def promote_memory(
    run_dir: Path,
    marker: dict[str, Any],
    process_namespace: str,
) -> dict[str, Any]:
    envelope, acknowledgment, delivery, state = _validate_turn_inputs(run_dir, marker)
    decision = read_json(run_dir / "receipts" / "promotion-decision.json")
    validate_document(decision, "promotion-decision")
    verify_document(
        decision,
        _trusted_key(run_dir, "reviewer", marker["reviewer_key_id"]),
    )
    if decision["outcome"] != "APPROVED" or decision["conflicts"]:
        raise ProtocolError("PROMOTION_CONFLICT", "review did not approve an uncontested promotion")

    staging_root = run_dir / "vault-staging"
    proposal_paths = _proposal_paths(staging_root)
    proposals = [read_json(path) for path in proposal_paths]
    for proposal in proposals:
        validate_document(proposal, "memory-proposal")
        verify_document(proposal, _trusted_key(run_dir, "consumer", marker["consumer_key_id"]))
    proposal_digests = sorted(document_digest(proposal) for proposal in proposals)
    if proposal_digests != decision["proposal_sha256"]:
        raise ProtocolError("PROMOTION_SET_DRIFT", "proposal set changed after review")

    prime_root = run_dir / "vault-prime"
    if prime_root.is_symlink():
        raise ProtocolError("PRIME_BOUNDARY", "PRIME root cannot be a symlink")
    artifacts: list[dict[str, str]] = []
    backlinks: list[str] = []
    promoted_at = utc_now()
    with exclusive_lock(run_dir / "locks" / "vault-promotion.lock"):
        for proposal, source_path in zip(proposals, proposal_paths, strict=True):
            record = proposal["record"]
            fact_key = _safe_id(record["fact_key"])
            target_folder = "30-Durable-Facts" if record["record_type"] == "DURABLE_FACT" else "40-Snapshots"
            target_path = prime_root / target_folder / f"{fact_key}.md"
            metadata = {
                "type": "hive-memory-record",
                "record_type": record["record_type"],
                "stable_id": record["stable_id"],
                "fact_key": fact_key,
                "value": record["value"],
                "status": "CURRENT",
                "privacy": proposal["privacy"],
                "lane_kind": proposal["lane"]["kind"],
                "lane_owner": proposal["lane"]["owner_id"],
                "occurred_at": record["occurred_at"],
                "recorded_at": record["recorded_at"],
                "promoted_at": promoted_at,
                "confidence": record["confidence"],
                "source_ref": record["source_ref"],
                "source_sha256": record["source_sha256"],
                "target_moc": "[[MOC HiveMind]]",
                "proposal_id": proposal["proposal_id"],
                "promotion_decision": decision["decision_id"],
            }
            body = f"{_safe_narrative(record['narrative'])}\n\n## Typed relationships\n\n- member_of [[MOC HiveMind]]"
            atomic_write_bytes(target_path, _frontmatter_note(metadata, fact_key, body))
            relative = str(target_path.relative_to(prime_root))
            artifacts.append({"path": relative, "sha256": _sha256_file(target_path)})
            backlinks.append(f"- contains [[{fact_key}]]")

            promoted_root = staging_root / "_promoted" / proposal["lane"]["kind"].lower() / proposal["lane"]["owner_id"]
            promoted_root.mkdir(parents=True, exist_ok=True)
            os.replace(source_path, promoted_root / source_path.name)
            source_note = source_path.with_suffix(".md")
            if source_note.is_file() and not source_note.is_symlink():
                os.replace(source_note, promoted_root / source_note.name)

        event_path = prime_root / "50-Events" / f"{marker['message_id']}-promotion.md"
        event_meta = {
            "type": "hive-memory-event",
            "record_type": "EVENT",
            "status": "APPEND_ONLY",
            "message_id": marker["message_id"],
            "occurred_at": promoted_at,
            "promotion_decision": decision["decision_id"],
            "target_moc": "[[MOC HiveMind]]",
        }
        atomic_write_bytes(event_path, _frontmatter_note(event_meta, f"Promotion {marker['message_id']}", "Reviewed memory proposals were promoted atomically in the disposable LAB vault."))
        artifacts.append({"path": str(event_path.relative_to(prime_root)), "sha256": _sha256_file(event_path)})

        moc_path = prime_root / "00-MOC" / "MOC HiveMind.md"
        moc_meta = {
            "type": "hive-moc",
            "moc_id": "MOC HiveMind",
            "coverage_status": "COMPLETE",
            "linked_records": len(backlinks),
            "last_verified_at": promoted_at,
        }
        moc_body = "## Typed backlinks\n\n" + "\n".join(backlinks)
        atomic_write_bytes(moc_path, _frontmatter_note(moc_meta, "MOC HiveMind", moc_body))
        artifacts.append({"path": str(moc_path.relative_to(prime_root)), "sha256": _sha256_file(moc_path)})

        base_paths: list[str] = []
        for name in PRIME_BASE_NAMES:
            payload, _ = _load_base(name)
            base_path = prime_root / "90-Bases" / name
            atomic_write_bytes(base_path, payload)
            relative = str(base_path.relative_to(prime_root))
            base_paths.append(f"PRIME/{relative}")
            artifacts.append({"path": relative, "sha256": _sha256_file(base_path)})
        for name in STAGING_BASE_NAMES:
            base_path = staging_root / "90-Bases" / name
            expected, _ = _load_base(name)
            if _sha256_file(base_path) != _sha256_bytes(expected):
                raise ProtocolError("BASE_INVALID", f"STAGING Base changed before promotion: {name}")
            base_paths.append(f"STAGING/90-Bases/{name}")

        receipt = {
            "schema_version": "hive.promotion-receipt.v1",
            "receipt_id": str(uuid4()),
            "message_id": marker["message_id"],
            "promoted_at": promoted_at,
            "promoter": {
                "worker_id": "HiveVault-promoter-LAB",
                "grant_ref": "Owner sample authorization",
                "process_id": os.getpid(),
                "process_namespace": process_namespace,
            },
            "decision_sha256": document_digest(decision),
            "proposal_sha256": proposal_digests,
            "artifacts": sorted(artifacts, key=lambda item: item["path"]),
            "bases": sorted(base_paths),
            "moc_backlinks": len(backlinks),
        }
        signed_promotion = sign_document(
            receipt,
            load_private_key(run_dir / "keys" / "promoter.private.pem"),
        )
        validate_document(signed_promotion, "promotion-receipt")
        atomic_write_json(run_dir / "receipts" / "promotion.json", signed_promotion)

        turn_receipt = {
            "schema_version": "hive.turn-receipt.v1",
            "receipt_id": str(uuid4()),
            "message_id": marker["message_id"],
            "recorded_at": promoted_at,
            "retrieved_at": None,
            "environment": envelope["authority"]["environment"],
            "privacy": "non-private",
            "artifacts": {
                "envelope_sha256": document_digest(envelope),
                "delivery_sha256": document_digest(delivery),
                "acknowledgment_sha256": document_digest(acknowledgment),
                "state_sha256": document_digest(state),
                "vault_note_sha256": artifacts[0]["sha256"],
                "promotion_sha256": document_digest(signed_promotion),
            },
            "proof": {
                "exists": "VERIFIED",
                "current": "VERIFIED",
                "wired": "VERIFIED",
                "running": "VERIFIED",
                "delivered": "VERIFIED",
                "consumed": "VERIFIED",
                "changed_behavior": "VERIFIED",
                "persists_next_turn": "PENDING",
            },
        }
        signed_turn = sign_document(
            turn_receipt,
            load_private_key(run_dir / "keys" / "consumer.private.pem"),
        )
        validate_document(signed_turn, "turn-receipt")
        atomic_write_json(run_dir / "receipts" / "turn-receipt.json", signed_turn)
    return {
        "outcome": "PROMOTED",
        "message_id": marker["message_id"],
        "proposal_count": len(proposals),
        "artifact_count": len(artifacts),
        "base_count": len(base_paths),
        "typed_backlinks": len(backlinks),
        "unreviewed_remaining": len(_proposal_paths(staging_root)) if (staging_root / "_proposals").exists() and list((staging_root / "_proposals").glob("*/*/*.json")) else 0,
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
        "receipt_sha256": document_digest(signed_turn),
        "promotion_sha256": document_digest(signed_promotion),
    }


def retrieve_memory(
    run_dir: Path,
    marker: dict[str, Any],
) -> dict[str, Any]:
    promotion = read_json(run_dir / "receipts" / "promotion.json")
    validate_document(promotion, "promotion-receipt")
    verify_document(
        promotion,
        _trusted_key(run_dir, "promoter", marker["promoter_key_id"]),
    )
    prime_root = run_dir / "vault-prime"
    for artifact in promotion["artifacts"]:
        path = prime_root / artifact["path"]
        if _sha256_file(path) != artifact["sha256"]:
            raise ProtocolError("NEXT_TURN_MEMORY_DRIFT", f"promoted artifact changed: {artifact['path']}")
    base_views = 0
    for scoped_base in promotion["bases"]:
        scope, base_relative = scoped_base.split("/", 1)
        name = Path(base_relative).name
        expected_payload, _ = _load_base(name)
        actual_root = prime_root if scope == "PRIME" else run_dir / "vault-staging"
        if scope not in {"PRIME", "STAGING"}:
            raise ProtocolError("BASE_SCOPE_INVALID", f"unknown Base scope: {scope}")
        actual_path = actual_root / base_relative
        if actual_path.read_bytes() != expected_payload:
            raise ProtocolError("NEXT_TURN_BASE_DRIFT", f"Base changed: {name}")
        _, parsed = _load_base(name)
        base_views += len(parsed["views"])
    moc_path = prime_root / "00-MOC" / "MOC HiveMind.md"
    moc = _read_frontmatter(moc_path)
    if moc.get("coverage_status") != "COMPLETE" or moc.get("linked_records") != promotion["moc_backlinks"]:
        raise ProtocolError("MOC_COVERAGE_MISSING", "MOC coverage does not match the promotion receipt")
    body = moc_path.read_text(encoding="utf-8")
    if body.count("- contains [[") != promotion["moc_backlinks"]:
        raise ProtocolError("BACKLINK_MISSING", "typed MOC backlink count differs")
    return {
        "promotion_sha256": document_digest(promotion),
        "promoted_artifacts_verified": len(promotion["artifacts"]),
        "bases_verified": len(promotion["bases"]),
        "base_views_verified": base_views,
        "backlinks_verified": promotion["moc_backlinks"],
    }


def validate_pruning_base() -> dict[str, Any]:
    _, document = _load_base("two-stage-pruning.base")
    names = [view["name"] for view in document["views"]]
    filters = str(document["views"][1].get("filters"))
    if "delete_eligible_at" not in filters or "deletion_receipt" not in filters:
        raise ProtocolError("PRUNING_POLICY_INVALID", "stage-two retention and receipt gates are absent")
    return {"views": names, "retention_days": 30, "automatic_delete": False}
