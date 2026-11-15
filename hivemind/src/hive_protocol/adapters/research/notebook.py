"""A small, local-only notebook seam with immutable provenance and receipts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from hive_protocol.core import ProtocolError


_OWNER_SCHEMA = "nukotech-hive-local-research-root/v1"
_PROVENANCE_SCHEMA = "nukotech-hive-local-research-source/v1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class LocalResearchNotebook:
    """Stores sources beneath one root; SQLite is a disposable/rebuildable projection."""

    def __init__(self, root: Path, *, signer: Callable[[bytes], str] | None = None) -> None:
        if root.exists() and root.is_symlink():
            raise ProtocolError("ROOT_SYMLINK_REFUSED", "notebook root may not be a symlink")
        self.root = root.resolve()
        self.owner_marker = self.root / ".hive-local-research-owned.json"
        self.sources = self.root / "sources"
        self.provenance = self.root / "provenance"
        self.queue = self.root / "offline-queue.jsonl"
        self.db = self.root / "index.sqlite3"
        self.signer = signer

        if self.root.exists() and not self.root.is_dir():
            raise ProtocolError("ROOT_OWNERSHIP_REFUSED", "notebook root must be a directory")
        if self.root.exists() and any(self.root.iterdir()):
            if not self.owner_marker.exists():
                raise ProtocolError(
                    "ROOT_OWNERSHIP_REFUSED",
                    "nonempty notebook root has no valid ownership marker",
                )
            self._validate_owner_marker()
        else:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.root, 0o700)
            self._write_owner_marker()

        if self.sources.is_symlink() or self.provenance.is_symlink():
            raise ProtocolError("ROOT_OWNERSHIP_MISMATCH", "notebook data paths may not be symlinks")
        self.sources.mkdir(parents=True, exist_ok=True)
        self.provenance.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _write_owner_marker(self) -> None:
        marker = {"schema": _OWNER_SCHEMA, "root": str(self.root)}
        self.owner_marker.write_bytes(_canonical(marker))
        os.chmod(self.owner_marker, 0o600)

    def _validate_owner_marker(self) -> None:
        if self.root.is_symlink() or self.owner_marker.is_symlink():
            raise ProtocolError("ROOT_OWNERSHIP_MISMATCH", "ownership path may not be a symlink")
        try:
            marker = json.loads(self.owner_marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError(
                "ROOT_OWNERSHIP_MISMATCH", "ownership marker is unreadable or invalid"
            ) from exc
        expected = {"schema": _OWNER_SCHEMA, "root": str(self.root)}
        if marker != expected:
            raise ProtocolError(
                "ROOT_OWNERSHIP_MISMATCH", "ownership marker does not bind this root"
            )

    def _init_db(self) -> None:
        with sqlite3.connect(self.db) as con:
            con.executescript("""
              CREATE TABLE IF NOT EXISTS source (sha256 TEXT PRIMARY KEY, project TEXT NOT NULL,
                privacy TEXT NOT NULL, origin TEXT NOT NULL, relative_path TEXT NOT NULL, text TEXT NOT NULL);
              CREATE VIRTUAL TABLE IF NOT EXISTS source_fts USING fts5(sha256 UNINDEXED, text);
            """)

    @staticmethod
    def _govern(project: str, privacy: str) -> None:
        if not project.strip() or privacy not in {"PROJECT_PRIVATE", "SURFACE_PRIVATE", "NON_PRIVATE"}:
            raise ProtocolError("PROJECT_PRIVACY_REQUIRED", "project and permitted privacy selection are mandatory")

    def _safe_source(self, candidate: Path) -> Path:
        if candidate.is_symlink():
            raise ProtocolError("SYMLINK_ESCAPE_REFUSED", "symlink sources are refused")
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(self.sources.resolve())
        except ValueError as exc:
            raise ProtocolError("SOURCE_BOUNDARY_REFUSED", "source must be inside notebook sources") from exc
        return resolved

    @staticmethod
    def _digest_directory(base: Path, prefix: str) -> Path:
        directory = base / prefix
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ProtocolError(
                "SYMLINK_ESCAPE_REFUSED", "digest directory must remain inside the notebook"
            )
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.resolve(strict=True).relative_to(base.resolve(strict=True))
        except ValueError as exc:
            raise ProtocolError(
                "SYMLINK_ESCAPE_REFUSED", "digest directory escaped the notebook"
            ) from exc
        return directory

    def capture_manual(self, text: str, *, project: str, privacy: str, title: str = "manual") -> dict:
        self._govern(project, privacy)
        if not isinstance(text, str) or not text.strip():
            raise ProtocolError("CAPTURE_EMPTY", "manual capture must contain text")
        data = text.encode("utf-8")
        return self._store(data, project=project, privacy=privacy, origin="manual", name=title)

    def ingest_local(self, path: Path, *, project: str, privacy: str) -> dict:
        self._govern(project, privacy)
        source = self._safe_source(path)
        return self._store(source.read_bytes(), project=project, privacy=privacy, origin="local", name=source.name)

    def watch_once(self, folder: Path, *, project: str, privacy: str) -> list[dict]:
        self._govern(project, privacy)
        if folder.is_symlink():
            raise ProtocolError("SYMLINK_ESCAPE_REFUSED", "watched folder may not be a symlink")
        folder = folder.resolve(strict=True)
        results = []
        for item in sorted(folder.iterdir()):
            if item.is_file() and not item.is_symlink():
                results.append(self._store(item.read_bytes(), project=project, privacy=privacy, origin="watched-folder", name=item.name))
        return results

    def _store(self, data: bytes, *, project: str, privacy: str, origin: str, name: str) -> dict:
        digest = _sha256(data)
        target = self._digest_directory(self.sources, digest[:2]) / digest
        metadata = self._digest_directory(self.provenance, digest[:2]) / f"{digest}.json"
        exists = target.exists()
        if exists:
            if target.is_symlink() or _sha256(target.read_bytes()) != digest:
                raise ProtocolError(
                    "PROVENANCE_HASH_MISMATCH", "stored source does not match its address"
                )
            provenance = self._load_provenance(metadata, digest)
        else:
            provenance = {
                "schema": _PROVENANCE_SCHEMA,
                "sha256": digest,
                "project": project,
                "privacy": privacy,
                "origin": origin,
                "name": name,
                "relative_path": str(target.relative_to(self.root)),
                "stored_at": datetime.now(timezone.utc).isoformat(),
            }
            target.write_bytes(data)
            os.chmod(target, 0o600)
            metadata.write_bytes(_canonical(provenance))
            os.chmod(metadata, 0o600)
        text = data.decode("utf-8", errors="replace")
        with sqlite3.connect(self.db) as con:
            indexed = con.execute(
                "SELECT 1 FROM source WHERE sha256=?", (digest,)
            ).fetchone() is not None
            if not indexed:
                con.execute(
                    "INSERT INTO source VALUES(?,?,?,?,?,?)",
                    (
                        digest,
                        provenance["project"],
                        provenance["privacy"],
                        provenance["origin"],
                        provenance["relative_path"],
                        text,
                    ),
                )
                con.execute("INSERT INTO source_fts VALUES(?,?)", (digest, text))
        result = dict(provenance)
        result["deduplicated"] = exists
        return result

    def _load_provenance(self, metadata: Path, digest: str) -> dict:
        if not metadata.exists() or metadata.is_symlink():
            raise ProtocolError(
                "PROVENANCE_RECORD_MISSING", "stored source has no durable provenance record"
            )
        try:
            metadata.resolve(strict=True).relative_to(self.provenance.resolve(strict=True))
        except ValueError as exc:
            raise ProtocolError(
                "SYMLINK_ESCAPE_REFUSED", "source provenance escaped the notebook"
            ) from exc
        try:
            record = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError(
                "PROVENANCE_RECORD_INVALID", "source provenance is unreadable or invalid"
            ) from exc
        required = {
            "schema",
            "sha256",
            "project",
            "privacy",
            "origin",
            "name",
            "relative_path",
            "stored_at",
        }
        if not isinstance(record, dict) or set(record) != required:
            raise ProtocolError("PROVENANCE_RECORD_INVALID", "source provenance schema is invalid")
        if not all(isinstance(record[field], str) for field in required):
            raise ProtocolError("PROVENANCE_RECORD_INVALID", "source provenance fields must be text")
        if record["schema"] != _PROVENANCE_SCHEMA:
            raise ProtocolError("PROVENANCE_RECORD_INVALID", "source provenance schema is invalid")
        if record["sha256"] != digest:
            raise ProtocolError("PROVENANCE_HASH_MISMATCH", "provenance does not bind the source")
        self._govern(record["project"], record["privacy"])
        return record

    def rebuild_index(self) -> None:
        if self.db.exists():
            self.db.unlink()
        self._init_db()
        for directory in self.sources.iterdir():
            if directory.is_symlink() or not directory.is_dir():
                raise ProtocolError(
                    "SYMLINK_ESCAPE_REFUSED", "source digest directory is invalid"
                )
        for item in sorted(self.sources.glob("*/*")):
            if item.is_file() and not item.is_symlink():
                data = item.read_bytes()
                digest = _sha256(data)
                if item.name != digest:
                    raise ProtocolError(
                        "PROVENANCE_HASH_MISMATCH", "source filename/hash mismatch"
                    )
                metadata = self.provenance / digest[:2] / f"{digest}.json"
                record = self._load_provenance(metadata, digest)
                text = data.decode("utf-8", errors="replace")
                with sqlite3.connect(self.db) as con:
                    con.execute(
                        "INSERT INTO source VALUES(?,?,?,?,?,?)",
                        (
                            digest,
                            record["project"],
                            record["privacy"],
                            record["origin"],
                            record["relative_path"],
                            text,
                        ),
                    )
                    con.execute("INSERT INTO source_fts VALUES(?,?)", (digest, text))

    def search(self, query: str) -> list[dict]:
        if not query.strip(): raise ProtocolError("QUERY_REQUIRED", "query is required")
        with sqlite3.connect(self.db) as con:
            rows = con.execute("SELECT s.sha256,s.project,s.privacy,s.origin,s.relative_path,s.text FROM source s JOIN source_fts f ON s.sha256=f.sha256 WHERE source_fts MATCH ? ORDER BY s.sha256", (query,)).fetchall()
        return [{"sha256": r[0], "project": r[1], "privacy": r[2], "origin": r[3], "path": r[4], "quote": r[5][:320]} for r in rows]

    def cite(self, sha256: str, quote: str) -> dict:
        with sqlite3.connect(self.db) as con:
            row = con.execute("SELECT text,relative_path FROM source WHERE sha256=?", (sha256,)).fetchone()
        if row is None or quote not in row[0]: raise ProtocolError("CITATION_MISMATCH", "citation must quote its ingested source")
        return {"source_sha256": sha256, "path": row[1], "quote": quote}

    def graph(self) -> dict:
        with sqlite3.connect(self.db) as con: rows = con.execute("SELECT sha256,text FROM source ORDER BY sha256").fetchall()
        edges = []
        for source, text in rows:
            for target in sorted(set(re.findall(r"\[\[([0-9a-f]{64})\]\]", text))):
                if any(target == candidate[0] for candidate in rows): edges.append({"from": source, "to": target})
        return {"nodes": [r[0] for r in rows], "edges": edges, "backlinks": {node: sorted(e["from"] for e in edges if e["to"] == node) for node, _ in rows}}

    def enqueue_offline(self, operation: dict) -> None:
        self.queue.parent.mkdir(parents=True, exist_ok=True)
        with self.queue.open("a", encoding="utf-8") as handle: handle.write(json.dumps(operation, sort_keys=True) + "\n")

    def export_pilot(self, destination: Path) -> Path:
        destination = destination.resolve()
        if "staging" not in destination.parts and "unreviewed" not in destination.parts:
            raise ProtocolError("STAGING_ONLY_EXPORT", "pilot exports are limited to staging/unreviewed")
        destination.mkdir(parents=True, exist_ok=True)
        manifest = {"sources": sorted(p.name for p in self.sources.glob("*/*") if p.is_file())}
        output = destination / "research-pilot-manifest.json"; output.write_bytes(_canonical(manifest)); return output

    def signed_receipt(self, event: str) -> dict:
        receipt = {"event": event, "root": str(self.root), "at": datetime.now(timezone.utc).isoformat(), "sources": len(list(self.sources.glob("*/*")))}
        if self.signer is None: raise ProtocolError("RECEIPT_SIGNER_UNAVAILABLE", "a Keychain-backed signer is required")
        receipt["signature"] = self.signer(_canonical(receipt)); return receipt

    def rollback_and_uninstall(self) -> None:
        if self.root.exists():
            self._validate_owner_marker()
            shutil.rmtree(self.root)
