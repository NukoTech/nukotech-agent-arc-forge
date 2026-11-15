"""Source-set-isolated local retrieval with exact citation anchors."""

from __future__ import annotations

import copy
import re
from typing import Any

from hive_protocol.capture.models import CitationAnchor, SourceRecord
from hive_protocol.core import ProtocolError
from hive_protocol.retrieval import LocalRetriever, SearchHit, SourceDocument

from .workspace import BoundedResearchWorkspaceStore


_TOKENS = re.compile(r"[A-Za-z0-9_-]{2,}")


class ResearchQueryService:
    """Rebuild and query one exact source-set without trusting derived rows."""

    def __init__(
        self,
        store: BoundedResearchWorkspaceStore,
        retriever: LocalRetriever,
    ) -> None:
        self.store = store
        self.retriever = retriever

    def _records(
        self, workspace_id: str, source_set_digest: str
    ) -> tuple[Any, dict[str, tuple[SourceRecord, str]]]:
        source_set = self.store.verify_source_set(workspace_id, source_set_digest)
        records: dict[str, tuple[SourceRecord, str]] = {}
        for source in source_set.sources:
            record, _ = self.store.load_source_record_snapshot(
                workspace_id, source["source_record_digest"]
            )
            if record.source_id != source["source_id"]:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                    "source-set snapshot identity changed",
                )
            records[record.source_id] = (
                record,
                source["source_record_digest"],
            )
        return source_set, records

    def _index_records(
        self,
        workspace_id: str,
        source_set_digest: str,
        records: dict[str, tuple[SourceRecord, str]],
    ) -> None:
        research_workspace = self.store.open_workspace(workspace_id)
        index_workspace_id = f"{workspace_id}@{source_set_digest}"
        for record, record_digest in records.values():
            if record.normalized_text_path is None or record.normalized_sha256 is None:
                raise ProtocolError(
                    "RESEARCH_SOURCE_NOT_NORMALIZED",
                    "research source lacks normalized text",
                )
            normalized_path = self.store.workspace.root / record.normalized_text_path
            content = normalized_path.read_text(encoding="utf-8")
            self.retriever.index(
                SourceDocument(
                    tenant_id=research_workspace.tenant_id,
                    workspace_id=index_workspace_id,
                    source_id=record.source_id,
                    source_path=record.normalized_text_path,
                    content=content,
                    sha256=record.normalized_sha256,
                    provenance={
                        "kind": "research-source-record",
                        "source_set_digest": source_set_digest,
                        "source_record_digest": record_digest,
                        "original_asset_path": record.original_asset_path,
                        "capture_ids": list(record.capture_ids),
                    },
                )
            )

    @staticmethod
    def _anchor_for_hit(
        hit: SearchHit,
        record: SourceRecord,
        record_digest: str,
        query: str,
        max_quote_bytes: int,
        *,
        semantic: bool = False,
    ) -> dict[str, Any] | None:
        query_lower = query.lower()
        tokens = set(_TOKENS.findall(query_lower))
        candidates: list[tuple[int, int, CitationAnchor]] = []
        for raw_anchor in record.anchors:
            anchor = CitationAnchor.from_dict(raw_anchor)
            if len(anchor.quote.encode("utf-8")) > max_quote_bytes:
                continue
            quote_lower = anchor.quote.lower()
            exact = int(query_lower in quote_lower)
            overlap = len(tokens & set(_TOKENS.findall(quote_lower)))
            if exact or overlap or semantic:
                candidates.append((exact, overlap, anchor))
        if not candidates:
            return None
        candidates.sort(
            key=lambda item: (-item[0], -item[1], item[2].char_start, item[2].anchor_id)
        )
        exact, overlap, anchor = candidates[0]
        score = 1.0 if exact else hit.score if semantic else round(
            overlap / max(1, len(tokens)), 8
        )
        return {
            "anchor_id": anchor.anchor_id,
            "source_id": record.source_id,
            "source_record_digest": record_digest,
            "source_sha256": record.original_sha256,
            "normalized_sha256": record.normalized_sha256,
            "source_path": record.normalized_text_path,
            "quote": anchor.quote,
            "quote_sha256": anchor.quote_sha256,
            "locator": copy.deepcopy(anchor.locator),
            "exact": bool(exact),
            "score": score,
            "provenance": copy.deepcopy(hit.provenance),
        }

    def search(
        self,
        query: str,
        *,
        workspace_id: str,
        source_set_digest: str,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        if not isinstance(query, str) or not query.strip():
            raise ProtocolError("QUERY_REQUIRED", "research query may not be empty")
        source_set, records = self._records(workspace_id, source_set_digest)
        policy_limit = source_set.retrieval_policy["max_results"]
        effective_limit = policy_limit if limit is None else limit
        if (
            not isinstance(effective_limit, int)
            or isinstance(effective_limit, bool)
            or effective_limit < 1
            or effective_limit > policy_limit
        ):
            raise ProtocolError(
                "SEARCH_LIMIT", "research result limit exceeds the source-set policy"
            )
        self._index_records(workspace_id, source_set_digest, records)
        research_workspace = self.store.open_workspace(workspace_id)
        index_workspace_id = f"{workspace_id}@{source_set_digest}"
        allowed = frozenset(records)
        quote_limit = min(1000, source_set.retrieval_policy["max_quote_bytes"])
        raw_hits = self.retriever.search(
            query,
            tenant_id=research_workspace.tenant_id,
            workspace_id=index_workspace_id,
            limit=effective_limit,
            quote_limit=quote_limit,
            allowed_source_ids=allowed,
        )
        semantic_ids: set[str] = set()
        if (
            source_set.retrieval_policy["semantic_allowed"]
            and len(raw_hits) < effective_limit
            and self.retriever.capabilities()["semantic"].get("available") is True
        ):
            semantic = self.retriever.search_semantic(
                query,
                tenant_id=research_workspace.tenant_id,
                workspace_id=index_workspace_id,
                limit=effective_limit,
                quote_limit=quote_limit,
                allowed_source_ids=allowed,
            )
            present = {hit.source_id for hit in raw_hits}
            for hit in semantic:
                if hit.source_id not in present:
                    raw_hits.append(hit)
                    semantic_ids.add(hit.source_id)
                    present.add(hit.source_id)
                if len(raw_hits) >= effective_limit:
                    break
        results: list[dict[str, Any]] = []
        for hit in raw_hits:
            if hit.source_id not in records:
                raise ProtocolError(
                    "RESEARCH_INDEX_SCOPE_VIOLATION",
                    "retrieval returned a source outside the exact source set",
                )
            record, record_digest = records[hit.source_id]
            if (
                hit.sha256 != record.normalized_sha256
                or hit.provenance.get("source_set_digest") != source_set_digest
                or hit.provenance.get("source_record_digest") != record_digest
            ):
                raise ProtocolError(
                    "RESEARCH_INDEX_DRIFT",
                    "retrieval row does not match portable source truth",
                )
            citation = self._anchor_for_hit(
                hit,
                record,
                record_digest,
                query,
                source_set.retrieval_policy["max_quote_bytes"],
                semantic=hit.source_id in semantic_ids,
            )
            if citation is not None:
                results.append(citation)
        return results[:effective_limit]
