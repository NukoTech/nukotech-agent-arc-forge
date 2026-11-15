"""Tenant-scoped exact retrieval with an optional local semantic ranker."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Protocol

from .core import ProtocolError


class EmbeddingProvider(Protocol):
    def embed(self, text: str) -> list[float]: ...

    def embedding_capability(self) -> Any: ...


@dataclass(frozen=True)
class SourceDocument:
    tenant_id: str
    workspace_id: str
    source_id: str
    source_path: str
    content: str
    sha256: str
    provenance: dict[str, Any]


@dataclass(frozen=True)
class SearchHit:
    source_id: str
    source_path: str
    sha256: str
    quote: str
    exact: bool
    score: float
    provenance: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "quote": self.quote,
            "exact": self.exact,
            "score": self.score,
            "provenance": self.provenance,
        }


def content_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _require_scope(tenant_id: str, workspace_id: str) -> None:
    if not tenant_id.strip() or not workspace_id.strip():
        raise ProtocolError("SCOPE_REQUIRED", "tenant_id and workspace_id are required")


def _bounded_quote(content: str, query: str, limit: int) -> str:
    if limit < 32 or limit > 1000:
        raise ProtocolError("QUOTE_BOUNDARY", "quote limit must be between 32 and 1000 characters")
    position = content.find(query)
    if position < 0:
        position = 0
    before = max(0, position - max(0, (limit - len(query)) // 2))
    quote = content[before : before + limit]
    return quote.strip()


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    denominator = math.sqrt(sum(value * value for value in left)) * math.sqrt(
        sum(value * value for value in right)
    )
    if denominator == 0:
        return 0.0
    return sum(a * b for a, b in zip(left, right, strict=True)) / denominator


def _allowed_source_clause(
    allowed_source_ids: frozenset[str] | None,
) -> tuple[int, str]:
    if allowed_source_ids is None:
        return 0, "[]"
    if not all(isinstance(source_id, str) and source_id for source_id in allowed_source_ids):
        raise ProtocolError("SOURCE_FILTER_INVALID", "allowed source IDs are invalid")
    ordered = tuple(sorted(allowed_source_ids))
    return 1, json.dumps(ordered)


class LocalRetriever:
    """Index canonical text in SQLite; never cross tenant/workspace scope."""

    def __init__(self, database: Path, semantic_provider: EmbeddingProvider | None = None) -> None:
        if database.exists() and database.is_symlink():
            raise ProtocolError("DATABASE_BOUNDARY", "retrieval database may not be a symlink")
        database.parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        self.semantic_provider = semantic_provider
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    tenant_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    embedding_json TEXT,
                    PRIMARY KEY (tenant_id, workspace_id, source_id)
                );
                CREATE INDEX IF NOT EXISTS sources_scope
                    ON sources (tenant_id, workspace_id, source_id);
                """
            )

    def capabilities(self) -> dict[str, Any]:
        semantic = {"available": False, "reason": "NO_PROVIDER_CONFIGURED"}
        if self.semantic_provider is not None:
            capability = self.semantic_provider.embedding_capability()
            semantic = (
                capability.as_dict() if hasattr(capability, "as_dict") else dict(capability)
            )
        return {
            "exact_text": {"available": True, "engine": "sqlite"},
            "semantic": semantic,
        }

    def index(self, document: SourceDocument) -> None:
        _require_scope(document.tenant_id, document.workspace_id)
        if not document.source_id.strip() or not document.source_path.strip():
            raise ProtocolError("SOURCE_IDENTITY_REQUIRED", "source ID and path are required")
        if not document.provenance:
            raise ProtocolError("PROVENANCE_REQUIRED", "indexed text requires provenance")
        actual_hash = content_sha256(document.content)
        if actual_hash != document.sha256:
            raise ProtocolError("SOURCE_HASH_MISMATCH", "source content does not match sha256")
        embedding: list[float] | None = None
        if self.semantic_provider is not None:
            capability = self.semantic_provider.embedding_capability()
            if getattr(capability, "available", False):
                embedding = self.semantic_provider.embed(document.content)
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO sources (
                    tenant_id, workspace_id, source_id, source_path, content,
                    sha256, provenance_json, embedding_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, workspace_id, source_id) DO UPDATE SET
                    source_path=excluded.source_path,
                    content=excluded.content,
                    sha256=excluded.sha256,
                    provenance_json=excluded.provenance_json,
                    embedding_json=excluded.embedding_json
                """,
                (
                    document.tenant_id,
                    document.workspace_id,
                    document.source_id,
                    document.source_path,
                    document.content,
                    document.sha256,
                    json.dumps(document.provenance, sort_keys=True),
                    json.dumps(embedding) if embedding is not None else None,
                ),
            )

    def search_exact(
        self,
        query: str,
        *,
        tenant_id: str,
        workspace_id: str,
        limit: int = 10,
        quote_limit: int = 320,
        allowed_source_ids: frozenset[str] | None = None,
    ) -> list[SearchHit]:
        _require_scope(tenant_id, workspace_id)
        if not query:
            raise ProtocolError("QUERY_REQUIRED", "exact query may not be empty")
        if limit < 1 or limit > 100:
            raise ProtocolError("SEARCH_LIMIT", "search limit must be between 1 and 100")
        filter_enabled, allowed_json = _allowed_source_clause(allowed_source_ids)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT source_id, source_path, content, sha256, provenance_json
                FROM sources
                WHERE tenant_id=? AND workspace_id=? AND instr(content, ?) > 0
                  AND (?=0 OR source_id IN (SELECT value FROM json_each(?)))
                ORDER BY source_id
                LIMIT ?
                """,
                (tenant_id, workspace_id, query, filter_enabled, allowed_json, limit),
            ).fetchall()
        return [
            SearchHit(
                source_id=row["source_id"],
                source_path=row["source_path"],
                sha256=row["sha256"],
                quote=_bounded_quote(row["content"], query, quote_limit),
                exact=True,
                score=1.0,
                provenance=json.loads(row["provenance_json"]),
            )
            for row in rows
        ]

    def search(
        self,
        query: str,
        *,
        tenant_id: str,
        workspace_id: str,
        limit: int = 10,
        quote_limit: int = 320,
        allowed_source_ids: frozenset[str] | None = None,
    ) -> list[SearchHit]:
        """Return exact phrase hits first, then deterministic token-overlap hits."""

        exact = self.search_exact(
            query,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            limit=limit,
            quote_limit=quote_limit,
            allowed_source_ids=allowed_source_ids,
        )
        if len(exact) >= limit:
            return exact
        tokens = list(dict.fromkeys(re.findall(r"[A-Za-z0-9_-]{2,}", query.lower())))[:12]
        if not tokens:
            return exact
        filter_enabled, allowed_json = _allowed_source_clause(allowed_source_ids)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT source_id, source_path, content, sha256, provenance_json
                FROM sources
                WHERE tenant_id=? AND workspace_id=?
                  AND (?=0 OR source_id IN (SELECT value FROM json_each(?)))
                """,
                (tenant_id, workspace_id, filter_enabled, allowed_json),
            ).fetchall()
        scored = sorted(
            (
                (sum(token in row["content"].lower() for token in tokens), row)
                for row in rows
            ),
            key=lambda item: (-item[0], item[1]["source_id"]),
        )
        exact_ids = {hit.source_id for hit in exact}
        lexical = [
            SearchHit(
                source_id=row["source_id"],
                source_path=row["source_path"],
                sha256=row["sha256"],
                quote=_bounded_quote(row["content"], tokens[0], quote_limit),
                exact=False,
                score=round(overlap / len(tokens), 8),
                provenance=json.loads(row["provenance_json"]),
            )
            for overlap, row in scored
            if overlap > 0 and row["source_id"] not in exact_ids
        ]
        return (exact + lexical)[:limit]

    def search_semantic(
        self,
        query: str,
        *,
        tenant_id: str,
        workspace_id: str,
        limit: int = 10,
        quote_limit: int = 320,
        allowed_source_ids: frozenset[str] | None = None,
    ) -> list[SearchHit]:
        _require_scope(tenant_id, workspace_id)
        if not query:
            raise ProtocolError("QUERY_REQUIRED", "semantic query may not be empty")
        if self.semantic_provider is None:
            raise ProtocolError("SEMANTIC_UNAVAILABLE", "no local semantic provider is configured")
        capability = self.semantic_provider.embedding_capability()
        if not getattr(capability, "available", False):
            raise ProtocolError("SEMANTIC_UNAVAILABLE", getattr(capability, "reason", "unavailable"))
        query_vector = self.semantic_provider.embed(query)
        filter_enabled, allowed_json = _allowed_source_clause(allowed_source_ids)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT source_id, source_path, content, sha256, provenance_json, embedding_json
                FROM sources WHERE tenant_id=? AND workspace_id=? AND embedding_json IS NOT NULL
                  AND (?=0 OR source_id IN (SELECT value FROM json_each(?)))
                """,
                (tenant_id, workspace_id, filter_enabled, allowed_json),
            ).fetchall()
        ranked = sorted(
            (
                (_cosine(query_vector, json.loads(row["embedding_json"])), row)
                for row in rows
            ),
            key=lambda item: (-item[0], item[1]["source_id"]),
        )[:limit]
        return [
            SearchHit(
                source_id=row["source_id"],
                source_path=row["source_path"],
                sha256=row["sha256"],
                quote=_bounded_quote(row["content"], "", quote_limit),
                exact=False,
                score=round(score, 8),
                provenance=json.loads(row["provenance_json"]),
            )
            for score, row in ranked
        ]
