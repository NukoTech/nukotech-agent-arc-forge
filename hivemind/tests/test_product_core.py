from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hive_protocol.core import ProtocolError
from hive_protocol.product import workspace as workspace_module
from hive_protocol.product.workspace import HiveWorkspace


def _archive_members(bundle: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    with tarfile.open(bundle, "r:gz") as archive:
        return [
            (
                member,
                archive.extractfile(member).read() if member.isfile() else None,
            )
            for member in archive.getmembers()
        ]


def _regular_member(name: str, payload: bytes) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    return member, payload


def _write_archive(
    bundle: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]
) -> None:
    with tarfile.open(bundle, "w:gz") as archive:
        for member, payload in members:
            archive.addfile(
                member,
                None if payload is None else io.BytesIO(payload),
            )


class ProductCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "plan.md").write_bytes(
            b"# Plan\n\nThe frozen rollback target is parent A.\n\n- depends_on [[Decision]]\n"
        )
        (self.source / "decision.md").write_bytes(
            b"# Decision\n\nUse portable Markdown.\n\n- supports [[Plan]]\n"
        )
        (self.source / "diagram.png").write_bytes(b"not-a-real-png-but-byte-portable")
        self.before = {path.name: path.read_bytes() for path in self.source.iterdir()}
        self.workspace = HiveWorkspace.create(self.root / "hive")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_import_preserves_source_searches_and_builds_typed_graph(self) -> None:
        first = self.workspace.import_content(self.source)
        second = self.workspace.import_content(self.source)
        self.assertEqual([item.stable_id for item in first], [item.stable_id for item in second])
        self.assertEqual(self.before, {path.name: path.read_bytes() for path in self.source.iterdir()})
        self.assertEqual(len(self.workspace.search_exact("rollback target")), 1)
        self.assertEqual(sum(1 for path in self.workspace.assets.rglob("*") if path.is_file()), 1)
        graph = self.workspace.graph()
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual({edge["relation"] for edge in graph["edges"]}, {"depends_on", "supports"})
        for item in first:
            imported = self.workspace.root / item.imported_relative_path
            self.assertEqual(imported.read_bytes(), (self.source / item.source_relative_path).read_bytes())

    def test_ask_is_truthfully_retrieval_only_without_model(self) -> None:
        self.workspace.import_content(self.source)
        with patch.object(self.workspace, "provider_status", return_value={"provider": "none", "available": False, "model": None}):
            result = self.workspace.ask("What is the rollback target?")
        self.assertEqual(result["outcome"], "RETRIEVAL_ONLY")
        self.assertTrue(result["citations"])
        with patch.object(self.workspace, "provider_status", return_value={"provider": "none", "available": False, "model": None}):
            absent = self.workspace.ask("Where is the zeppelin hangar?")
        self.assertEqual(absent["outcome"], "NO_EVIDENCE")
        self.assertIsNone(absent["answer"])

    def test_provider_configuration_can_force_offline_retrieval_only(self) -> None:
        result = self.workspace.configure_provider("retrieval-only", "ignored-model")
        self.assertEqual(result["provider"]["configured_mode"], "retrieval-only")
        self.assertFalse(result["provider"]["available"])
        config = json.loads(self.workspace.config_path.read_text(encoding="utf-8"))
        self.assertEqual(config["provider"], {"mode": "retrieval-only", "model": None})

    def test_snapshot_rollback_restores_exact_portable_sources(self) -> None:
        imported = self.workspace.import_content(self.source)
        checkpoint = self.workspace.snapshot("test parent")["commit"]
        before = {
            path.relative_to(self.workspace.sources).as_posix(): path.read_bytes()
            for path in self.workspace.sources.rglob("*")
            if path.is_file()
        }
        target = self.workspace.root / imported[0].imported_relative_path
        target.write_bytes(target.read_bytes() + b"\nmutation\n")
        result = self.workspace.rollback(checkpoint)
        after = {
            path.relative_to(self.workspace.sources).as_posix(): path.read_bytes()
            for path in self.workspace.sources.rglob("*")
            if path.is_file()
        }
        self.assertEqual(result["target"], checkpoint)
        self.assertEqual(before, after)
        self.assertEqual(len(self.workspace.search_exact("rollback target")), 1)

    def test_rollback_refuses_untracked_symlink_without_deleting_its_target(self) -> None:
        imported = self.workspace.import_content(self.source)
        self.workspace.research.mkdir()
        (self.workspace.research / "tracked.txt").write_text(
            "checkpoint", encoding="utf-8"
        )
        checkpoint = self.workspace.snapshot("symlink boundary")["commit"]
        target = self.workspace.root / imported[0].imported_relative_path
        link = self.workspace.research / "untracked-link"
        link.symlink_to(target)

        with self.assertRaisesRegex(ProtocolError, "ROLLBACK_PATH_DENIED"):
            self.workspace.rollback(checkpoint)

        self.assertTrue(target.is_file())
        self.assertTrue(link.is_symlink())

    def test_snapshot_refuses_symlinked_portable_content(self) -> None:
        external = self.root / "external-secret.txt"
        external.write_text("do not read or alter", encoding="utf-8")
        link = self.workspace.sources / "linked.md"
        link.symlink_to(external)

        with self.assertRaisesRegex(ProtocolError, "SYMLINK_DENIED"):
            self.workspace.snapshot("unsafe symlink checkpoint")

        self.assertEqual(external.read_text(encoding="utf-8"), "do not read or alter")
        self.assertTrue(link.is_symlink())

    def test_rollback_preflights_tracked_symlinks_before_mutation(self) -> None:
        external = self.root / "external-target.txt"
        external.write_text("preserve", encoding="utf-8")
        tracked = self.workspace.sources / "tracked.md"
        tracked.write_text("safe parent", encoding="utf-8")
        self.workspace.snapshot("safe parent")

        tracked.unlink()
        tracked.symlink_to(external)
        self.workspace._git("add", "sources/tracked.md")
        self.workspace._git("commit", "-m", "malicious symlink fixture")
        unsafe_checkpoint = self.workspace._git("rev-parse", "HEAD").stdout.strip()

        tracked.unlink()
        tracked.write_text("safe current", encoding="utf-8")
        self.workspace._git("add", "sources/tracked.md")
        self.workspace._git("commit", "-m", "safe current fixture")
        current_head = self.workspace._git("rev-parse", "HEAD").stdout.strip()

        with self.assertRaisesRegex(ProtocolError, "ROLLBACK_PATH_DENIED"):
            self.workspace.rollback(unsafe_checkpoint)

        self.assertEqual(
            self.workspace._git("rev-parse", "HEAD").stdout.strip(), current_head
        )
        self.assertEqual(tracked.read_text(encoding="utf-8"), "safe current")
        self.assertEqual(external.read_text(encoding="utf-8"), "preserve")

    def test_portable_export_reopens_with_verified_bytes(self) -> None:
        self.workspace.import_content(self.source)
        bundle = self.root / "portable.tar.gz"
        exported = self.workspace.export(bundle)
        reopened = HiveWorkspace.reopen_export(bundle, self.root / "reopened")
        self.assertEqual(exported["sha256"], __import__("hashlib").sha256(bundle.read_bytes()).hexdigest())
        self.assertTrue(reopened.search_exact("portable Markdown"))
        self.assertEqual(
            sorted(path.read_bytes() for path in self.workspace.sources.rglob("*") if path.is_file()),
            sorted(path.read_bytes() for path in reopened.sources.rglob("*") if path.is_file()),
        )
        self.assertEqual(
            sorted(path.read_bytes() for path in self.workspace.assets.rglob("*") if path.is_file()),
            sorted(path.read_bytes() for path in reopened.assets.rglob("*") if path.is_file()),
        )

    def test_export_refuses_oversized_or_in_hive_output_before_write(self) -> None:
        self.workspace.import_content(self.source)
        oversized = self.root / "oversized.tar.gz"
        with patch("hive_protocol.product.workspace.MAX_EXPORT_MEMBER_BYTES", 8):
            with self.assertRaisesRegex(ProtocolError, "EXPORT_LIMIT"):
                self.workspace.export(oversized)
        self.assertFalse(oversized.exists())

        in_hive = self.workspace.root / "self-export.tar.gz"
        with self.assertRaisesRegex(ProtocolError, "EXPORT_OUTPUT_BOUNDARY"):
            self.workspace.export(in_hive)
        self.assertFalse(in_hive.exists())

    def test_export_verifies_assembled_archive_before_publishing(self) -> None:
        self.workspace.import_content(self.source)
        portable_source = next(self.workspace.sources.rglob("*.md"))
        real_sha256_file = workspace_module._sha256_file

        def mismatched_inventory(path: Path) -> str:
            if path == portable_source:
                return "0" * 64
            return real_sha256_file(path)

        bundle = self.root / "raced-export.tar.gz"
        with patch(
            "hive_protocol.product.workspace._sha256_file",
            side_effect=mismatched_inventory,
        ):
            with self.assertRaisesRegex(ProtocolError, "EXPORT_HASH_MISMATCH"):
                self.workspace.export(bundle)
        self.assertFalse(bundle.exists())

    def test_reopen_rejects_archive_traversal(self) -> None:
        bundle = self.root / "bad.tar.gz"
        with tarfile.open(bundle, "w:gz") as archive:
            info = tarfile.TarInfo("../escape")
            payload = b"no"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with self.assertRaisesRegex(ProtocolError, "EXPORT_PATH_DENIED"):
            HiveWorkspace.reopen_export(bundle, self.root / "target")

    def test_reopen_rejects_duplicate_extra_wrong_root_links_and_limits(self) -> None:
        self.workspace.import_content(self.source)
        valid = self.root / "valid.tar.gz"
        self.workspace.export(valid)
        members = _archive_members(valid)
        manifest = next(
            payload
            for member, payload in members
            if member.name == "hive-export/manifest.json"
        )
        self.assertIsNotNone(manifest)

        link = tarfile.TarInfo("hive-export/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/tmp/escape"
        cases = (
            ("duplicate", [*members, members[0]], "EXPORT_DUPLICATE"),
            (
                "extra",
                [*members, _regular_member("hive-export/extra.txt", b"extra")],
                "EXPORT_FILE_SET_MISMATCH",
            ),
            (
                "wrong-root",
                [
                    *members,
                    _regular_member("other/manifest.json", manifest or b""),
                ],
                "EXPORT_PATH_DENIED",
            ),
            ("link", [*members, (link, None)], "EXPORT_MEMBER_DENIED"),
            (
                "case-collision",
                [
                    *members,
                    _regular_member(
                        "hive-export/" + members[0][0].name.removeprefix(
                            "hive-export/"
                        ).upper(),
                        members[0][1] or b"",
                    ),
                ],
                "EXPORT_CASE_COLLISION",
            ),
        )
        for label, bad_members, error in cases:
            bundle = self.root / f"bad-{label}.tar.gz"
            _write_archive(bundle, bad_members)
            target = self.root / f"target-{label}"
            with self.assertRaisesRegex(ProtocolError, error):
                HiveWorkspace.reopen_export(bundle, target)
            self.assertFalse(target.exists())

        with patch("hive_protocol.product.workspace.MAX_EXPORT_MEMBER_BYTES", 8):
            with self.assertRaisesRegex(ProtocolError, "EXPORT_LIMIT"):
                HiveWorkspace.reopen_export(valid, self.root / "target-limit")

        nonempty = self.root / "nonempty"
        nonempty.mkdir()
        sentinel = nonempty / "sentinel"
        sentinel.write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(ProtocolError, "REOPEN_TARGET_NOT_EMPTY"):
            HiveWorkspace.reopen_export(valid, nonempty)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
