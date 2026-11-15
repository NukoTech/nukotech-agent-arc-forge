import hashlib
import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from hive_protocol.core import ProtocolError
from hive_protocol.retrieval import LocalRetriever, SourceDocument


@dataclass(frozen=True)
class _Capability:
    available: bool = True
    reason: str = "AVAILABLE"

    def as_dict(self):
        return {"available": self.available, "reason": self.reason}


class _Embeddings:
    def embedding_capability(self):
        return _Capability()

    def embed(self, text):
        return [float("amber" in text.lower()), float(len(text) % 7)]


def _document(content="The launch color is amber.", tenant="tenant-a", source="note-1"):
    return SourceDocument(
        tenant, "alpha", source, f"notes/{source}.md", content,
        hashlib.sha256(content.encode()).hexdigest(), {"kind": "fixture", "revision": "1"}
    )


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_text_and_scope_are_deterministic(self):
        retrieval = LocalRetriever(self.root / "index.sqlite")
        retrieval.index(_document())
        retrieval.index(_document(tenant="tenant-b", source="secret"))
        hits = retrieval.search_exact("launch color", tenant_id="tenant-a", workspace_id="alpha")
        self.assertEqual([hit.source_id for hit in hits], ["note-1"])
        self.assertIn("launch color", hits[0].quote)
        self.assertEqual(
            retrieval.search_exact("launch color", tenant_id="tenant-c", workspace_id="alpha"), []
        )

    def test_lexical_and_optional_semantic_search(self):
        retrieval = LocalRetriever(self.root / "index.sqlite", _Embeddings())
        retrieval.index(_document())
        self.assertEqual(
            retrieval.search("What color launches?", tenant_id="tenant-a", workspace_id="alpha")[0].source_id,
            "note-1",
        )
        self.assertGreater(
            retrieval.search_semantic("amber", tenant_id="tenant-a", workspace_id="alpha")[0].score, 0
        )
        self.assertTrue(retrieval.capabilities()["semantic"]["available"])

    def test_hash_and_provenance_fail_closed(self):
        retrieval = LocalRetriever(self.root / "index.sqlite")
        bad = _document()
        with self.assertRaisesRegex(ProtocolError, "SOURCE_HASH_MISMATCH"):
            retrieval.index(SourceDocument(**{**bad.__dict__, "sha256": "0" * 64}))
        with self.assertRaisesRegex(ProtocolError, "PROVENANCE_REQUIRED"):
            retrieval.index(SourceDocument(**{**bad.__dict__, "provenance": {}}))

    def test_deterministic_demo_fixture(self):
        fixture_root = Path(__file__).parent / "fixtures" / "alpha-intelligence"
        content = (fixture_root / "canonical-note.md").read_text()
        expected = json.loads((fixture_root / "expected.json").read_text())
        retrieval = LocalRetriever(self.root / "demo.sqlite")
        retrieval.index(SourceDocument(
            "sample-lab", "hive-alpha", expected["expected_source_id"], "canonical-note.md",
            content, hashlib.sha256(content.encode()).hexdigest(),
            {"kind": "deterministic-demo", "revision": "1"}
        ))
        hits = retrieval.search_exact(
            expected["exact_query"], tenant_id="sample-lab", workspace_id="hive-alpha"
        )
        self.assertEqual([hit.source_id for hit in hits], [expected["expected_source_id"]])

    def test_sqlite_connections_close_deterministically_without_gc(self):
        database = self.root / "closed.sqlite"
        retrieval = LocalRetriever(database)

        for suffix in ("-shm", "-wal"):
            self.assertFalse(Path(f"{database}{suffix}").exists())

        retrieval.index(_document())
        retrieval.search_exact(
            "launch color",
            tenant_id="tenant-a",
            workspace_id="alpha",
        )
        retrieval.search(
            "launch",
            tenant_id="tenant-a",
            workspace_id="alpha",
        )

        for suffix in ("-shm", "-wal"):
            self.assertFalse(Path(f"{database}{suffix}").exists())


if __name__ == "__main__":
    unittest.main()
