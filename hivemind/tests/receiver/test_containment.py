from __future__ import annotations

import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from hive_protocol.core import ProtocolError
from hive_protocol.receiver import GovernedRoot, validate_identifier


class GovernedContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "governed"
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "sentinel").write_text("unowned", encoding="utf-8")
        self.fs = GovernedRoot(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_path_separators_dot_traversal_absolute_encoded_and_control_fail(self) -> None:
        invalid = (
            "../escape",
            "..",
            ".",
            "/absolute",
            "nested/../../escape",
            "nested\\..\\escape",
            "%2e%2e%2fescape",
            "safe%252f..%252fescape",
            "control\nname",
            "control\x00name",
        )
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ProtocolError):
                    validate_identifier(value, "test")

    def test_nested_symlink_escape_is_rejected(self) -> None:
        (self.root / "inbox").mkdir(mode=0o700)
        (self.root / "inbox" / "LeadA").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(ProtocolError):
            self.fs.write_json(("inbox", "LeadA", "message.json"), {"safe": True})
        self.assertFalse((self.outside / "message.json").exists())

    def test_destination_directory_substitution_is_rejected(self) -> None:
        (self.root / "inbox").mkdir(mode=0o700)
        (self.root / "inbox" / "LeadA").mkdir(mode=0o700)
        replacement = self.root / "replacement"
        replacement.mkdir(mode=0o700)

        def substitute() -> None:
            (self.root / "inbox" / "LeadA").rename(self.root / "inbox" / "LeadA-old")
            replacement.rename(self.root / "inbox" / "LeadA")

        with self.assertRaisesRegex(ProtocolError, "changed"):
            self.fs.write_json(
                ("inbox", "LeadA", "message.json"),
                {"safe": True},
                before_commit=substitute,
            )
        self.assertFalse((self.root / "inbox" / "LeadA" / "message.json").exists())

    def test_every_governed_state_root_rejects_symlink_components(self) -> None:
        for component in (
            "inbox",
            "unread",
            "quarantine",
            "cursors",
            "replay",
            "ack_receipts",
            "failure_receipts",
            "git_receipts",
        ):
            with self.subTest(component=component):
                path = self.root / component
                path.symlink_to(self.outside, target_is_directory=True)
                with self.assertRaises(ProtocolError):
                    self.fs.write_json((component, "message.json"), {"safe": True})
                path.unlink()
        self.assertEqual(sorted(path.name for path in self.outside.iterdir()), ["sentinel"])

    def test_symlink_and_hardlink_destinations_fail_closed(self) -> None:
        (self.root / "receipts").mkdir(mode=0o700)
        destination = self.root / "receipts" / "message.json"
        destination.symlink_to(self.outside / "sentinel")
        with self.assertRaises(ProtocolError):
            self.fs.write_json(("receipts", "message.json"), {"safe": True})
        destination.unlink()

        owned = self.root / "receipts" / "owned.json"
        owned.write_text("{}", encoding="utf-8")
        destination.hardlink_to(owned)
        with self.assertRaises(ProtocolError):
            self.fs.write_json(("receipts", "message.json"), {"safe": True})
        self.assertEqual((self.outside / "sentinel").read_text(encoding="utf-8"), "unowned")

    def test_concurrent_symlink_replacement_fails_before_commit(self) -> None:
        (self.root / "unread").mkdir(mode=0o700)
        (self.root / "unread" / "LeadC").mkdir(mode=0o700)
        attacker_finished = threading.Event()

        def attacker() -> None:
            (self.root / "unread" / "LeadC").rename(self.root / "unread" / "LeadC-old")
            (self.root / "unread" / "LeadC").symlink_to(self.outside, target_is_directory=True)
            attacker_finished.set()

        def race() -> None:
            thread = threading.Thread(target=attacker)
            thread.start()
            thread.join(timeout=2)
            self.assertTrue(attacker_finished.is_set())

        with self.assertRaises(ProtocolError):
            self.fs.write_json(
                ("unread", "LeadC", "message.json"),
                {"safe": True},
                before_commit=race,
            )
        self.assertFalse((self.outside / "message.json").exists())

    def test_post_check_pre_replace_renamed_destination_cannot_receive_commit(self) -> None:
        destination = self.root / "inbox" / "LeadA"
        destination.mkdir(parents=True, mode=0o700)
        target = destination / "message.json"
        original = b"external-target-original\n"
        target.write_bytes(original)
        escaped = self.outside / "renamed-LeadA"
        real_replace = os.replace
        bytes_observed_before_replace_returned: list[bytes] = []

        def rename_after_final_check(source, target_name, **kwargs):
            # write_json has completed its final containment check when it
            # invokes os.replace. Move the open destination directory outside
            # the governed root before allowing that syscall to continue.
            destination.rename(escaped)
            result = real_replace(source, target_name, **kwargs)
            bytes_observed_before_replace_returned.append(
                (escaped / "message.json").read_bytes()
            )
            return result

        with patch(
            "hive_protocol.receiver.containment.os.replace",
            side_effect=rename_after_final_check,
        ):
            with self.assertRaises(ProtocolError):
                self.fs.write_json(
                    ("inbox", "LeadA", "message.json"),
                    {"safe": True},
                )

        self.assertEqual(bytes_observed_before_replace_returned, [original])
        self.assertEqual((escaped / "message.json").read_bytes(), original)

    def test_post_check_renamed_ancestor_cannot_receive_commit(self) -> None:
        destination = self.root / "inbox" / "LeadA"
        destination.mkdir(parents=True, mode=0o700)
        target = destination / "message.json"
        original = b"ancestor-target-original\n"
        target.write_bytes(original)
        escaped = self.outside / "renamed-inbox"
        real_replace = os.replace
        observed: list[bytes] = []

        def rename_ancestor(source, target_name, **kwargs):
            (self.root / "inbox").rename(escaped)
            result = real_replace(source, target_name, **kwargs)
            observed.append((escaped / "LeadA" / "message.json").read_bytes())
            return result

        with patch(
            "hive_protocol.receiver.containment.os.replace",
            side_effect=rename_ancestor,
        ):
            with self.assertRaises(ProtocolError):
                self.fs.write_json(
                    ("inbox", "LeadA", "message.json"),
                    {"safe": True},
                )

        self.assertEqual(observed, [original])
        self.assertEqual((escaped / "LeadA" / "message.json").read_bytes(), original)

    def test_rejected_post_check_escape_restores_prior_logical_object(self) -> None:
        logical_path = ("inbox", "LeadA", "message.json")
        self.fs.write_json(logical_path, {"version": "before"})
        destination = self.root / "inbox" / "LeadA"
        escaped = self.outside / "renamed-LeadA-rollback"
        real_replace = os.replace

        def rename_destination(source, target_name, **kwargs):
            destination.rename(escaped)
            return real_replace(source, target_name, **kwargs)

        with patch(
            "hive_protocol.receiver.containment.os.replace",
            side_effect=rename_destination,
        ):
            with self.assertRaises(ProtocolError):
                self.fs.write_json(logical_path, {"version": "after"})

        escaped.rename(destination)
        self.assertEqual(self.fs.read_json(logical_path), {"version": "before"})

    def test_post_check_symlink_swap_cannot_receive_commit(self) -> None:
        destination = self.root / "inbox" / "LeadA"
        destination.mkdir(parents=True, mode=0o700)
        external_target = self.outside / "message.json"
        original = b"symlink-target-original\n"
        external_target.write_bytes(original)
        real_replace = os.replace
        observed: list[bytes] = []

        def swap_for_symlink(source, target_name, **kwargs):
            destination.rename(self.root / "inbox" / "LeadA-old")
            destination.symlink_to(self.outside, target_is_directory=True)
            result = real_replace(source, target_name, **kwargs)
            observed.append(external_target.read_bytes())
            return result

        with patch(
            "hive_protocol.receiver.containment.os.replace",
            side_effect=swap_for_symlink,
        ):
            with self.assertRaises(ProtocolError):
                self.fs.write_json(
                    ("inbox", "LeadA", "message.json"),
                    {"safe": True},
                )

        self.assertEqual(observed, [original])
        self.assertEqual(external_target.read_bytes(), original)

    def test_post_check_root_substitution_refuses_without_touching_replacement(self) -> None:
        logical_path = ("state", "cursors", "LeadA.json")
        self.fs.write_json(logical_path, {"version": "before"})
        original_files = {
            path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()
        }
        escaped = self.outside / "renamed-root"
        replacement = self.base / "replacement-root"
        replacement.mkdir(mode=0o700)
        replacement_sentinel = replacement / "sentinel"
        replacement_sentinel.write_bytes(b"replacement-original\n")
        real_replace = os.replace

        def substitute_root(source, target_name, **kwargs):
            self.root.rename(escaped)
            replacement.rename(self.root)
            return real_replace(source, target_name, **kwargs)

        with patch(
            "hive_protocol.receiver.containment.os.replace",
            side_effect=substitute_root,
        ):
            with self.assertRaisesRegex(ProtocolError, "governed root"):
                self.fs.write_json(logical_path, {"version": "after"})

        self.assertEqual((self.root / "sentinel").read_bytes(), b"replacement-original\n")
        self.assertEqual(
            {path.name: path.read_bytes() for path in escaped.iterdir() if path.is_file()},
            original_files,
        )

    def test_legitimate_flat_object_write_update_list_and_unlink(self) -> None:
        logical_path = ("unread", "LeadC", "message.json")
        self.fs.write_json(logical_path, {"version": 1})
        self.assertEqual(self.fs.read_json(logical_path), {"version": 1})
        self.fs.write_json(logical_path, {"version": 2})
        self.assertEqual(self.fs.read_json(logical_path), {"version": 2})
        self.assertEqual(self.fs.list_json(("unread", "LeadC")), ["message.json"])
        committed = [
            path for path in self.root.iterdir() if path.name.startswith("object-")
        ]
        self.assertEqual(len(committed), 1)
        self.assertTrue(committed[0].is_file())
        self.fs.unlink(logical_path)
        self.assertIsNone(self.fs.read_json(logical_path, optional=True))

    def test_legacy_nested_state_remains_readable_during_migration(self) -> None:
        legacy = self.root / "state" / "replay.json"
        legacy.parent.mkdir(mode=0o700)
        legacy.write_bytes(b'{"seen":["message-1"]}\n')

        self.assertEqual(
            self.fs.read_json(("state", "replay.json")),
            {"seen": ["message-1"]},
        )
        self.assertEqual(self.fs.list_json(("state",)), ["replay.json"])

    def test_update_keeps_prior_object_readable_until_atomic_replace(self) -> None:
        logical_path = ("unread", "LeadC", "message.json")
        self.fs.write_json(logical_path, {"version": "before"})
        replace_entered = threading.Event()
        allow_replace = threading.Event()
        writer_errors: list[BaseException] = []
        real_replace = os.replace

        def block_replace(source, target_name, **kwargs):
            replace_entered.set()
            if not allow_replace.wait(timeout=2):
                raise RuntimeError("test did not release atomic replace")
            return real_replace(source, target_name, **kwargs)

        def update() -> None:
            try:
                self.fs.write_json(logical_path, {"version": "after"})
            except BaseException as exc:
                writer_errors.append(exc)

        with patch(
            "hive_protocol.receiver.containment.os.replace",
            side_effect=block_replace,
        ):
            writer = threading.Thread(target=update)
            writer.start()
            self.assertTrue(replace_entered.wait(timeout=2))
            try:
                self.assertEqual(
                    self.fs.read_json(logical_path),
                    {"version": "before"},
                )
                self.assertEqual(
                    self.fs.list_json(("unread", "LeadC")),
                    ["message.json"],
                )
            finally:
                allow_replace.set()
                writer.join(timeout=2)

        self.assertFalse(writer.is_alive())
        self.assertEqual(writer_errors, [])
        self.assertEqual(self.fs.read_json(logical_path), {"version": "after"})

    def test_list_rejects_object_whose_name_does_not_bind_logical_path(self) -> None:
        logical_path = ("unread", "LeadC", "message.json")
        self.fs.write_json(logical_path, {"version": 1})
        committed = next(
            path for path in self.root.iterdir() if path.name.startswith("object-")
        )
        forged = self.root / f"object-{'0' * 64}.json"
        forged.write_bytes(committed.read_bytes())

        self.assertEqual(
            self.fs.list_json(("unread", "LeadC")),
            ["message.json"],
        )

    def test_rejected_escape_rolls_back_without_touching_unowned_state(self) -> None:
        (self.root / "quarantine").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(ProtocolError):
            self.fs.write_json(("quarantine", "escape.json"), {"unsafe": False})
        shutil.rmtree(self.root)
        self.assertEqual((self.outside / "sentinel").read_text(encoding="utf-8"), "unowned")
        self.assertFalse((self.outside / "escape.json").exists())


if __name__ == "__main__":
    unittest.main()
