from __future__ import annotations

import hashlib
import multiprocessing
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, public_key_id, verify_document
from hive_protocol.receiver import (
    DiscoveredWork,
    ExistingTransportAdapter,
    FileRouteDiscovery,
    GitHubAssignmentDiscovery,
    MachineAppIdentity,
    ReceiverMatrix,
    RuntimeAuthorityBinding,
    SingleWriterGitTransport,
    default_enrollments,
)


def _test_enrollments(builda_key_id: str = "ed25519:test-builda"):
    surfaces = ("LeadA", "BuildA", "LeadB", "BuildB", "LeadC", "BuildC", "LeadP", "BuildP")
    actors = {
        "LeadA": "hive-leada-app[bot]",
        "BuildA": "hive-builda-app[bot]",
        "LeadB": "hive-leadb-app[bot]",
        "BuildB": "hive-buildb-app[bot]",
        "LeadC": "hive-leadc-app[bot]",
        "BuildC": "hive-buildc-app[bot]",
        "LeadP": "hive-leadp-app[bot]",
        "BuildP": "hive-buildp-app[bot]",
    }
    return default_enrollments(
        {
                surface: RuntimeAuthorityBinding(
                    runtime_adapter=f"test-adapter-{surface.lower()}",
                    app_actor=actors[surface],
                    verification_key_id=(
                        builda_key_id
                        if surface == "BuildA"
                        else "ed25519:" + hashlib.sha256(surface.encode()).hexdigest()[:24]
                ),
            )
            for surface in surfaces
        }
    )


def _process_writer(root: str, sequence: int) -> None:
    identity = MachineAppIdentity("hive-builda-app[bot]", 1001, 2002)
    key = Ed25519PrivateKey.generate()
    authority = next(record for record in _test_enrollments() if record.surface_id == "BuildA")
    writer = SingleWriterGitTransport(Path(root) / "git-process", identity, key, authority)

    def operation(_identity):
        journal = Path(root) / "process-writer.log"
        with journal.open("a", encoding="utf-8") as handle:
            handle.write(f"start:{sequence}\n")
            handle.flush()
        time.sleep(0.02)
        with journal.open("a", encoding="utf-8") as handle:
            handle.write(f"finish:{sequence}\n")
            handle.flush()
        return {"actor": _identity.actor, "sequence": sequence}

    writer.execute(identity, operation)


class TransportAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.sender = Ed25519PrivateKey.generate()
        self.receipt = Ed25519PrivateKey.generate()
        self.enrollments = _test_enrollments(public_key_id(self.sender.public_key()))
        self.builda = next(record for record in self.enrollments if record.surface_id == "BuildA")
        self.matrix = ReceiverMatrix(
            self.base / "matrix",
            {public_key_id(self.sender.public_key()): self.sender.public_key()},
            self.receipt,
            enrollments=self.enrollments,
            max_attempts=2,
            github_app_actors={"hive-builda-app[bot]"},
        )
        self.adapter = ExistingTransportAdapter(
            self.base / "transport", self.matrix, self.sender, "BuildA"
        )
        self.app = MachineAppIdentity("hive-builda-app[bot]", 1001, 2002)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def work(self, *, surface="BuildA", mode="EVENT", dependencies=()):
        return DiscoveredWork(
            message_id=str(uuid4()),
            nonce=uuid4().hex,
            recipient_surface=surface,
            payload_sha256="a" * 64,
            source_channel="03 Reviews and Decisions",
            transport_kind="FILES_01_04",
            transport_actor="existing-local-filesystem",
            wake_mode=mode,
            dependency_ids=dependencies,
        )

    def test_event_wake_is_immediate(self) -> None:
        calls = []
        result = self.adapter.process(
            self.work(), lambda envelope, recipient, reason: not calls.append((envelope, recipient, reason))
        )
        self.assertEqual(result["wake_status"], "AWAKENED")
        self.assertEqual(calls[0][2], "EVENT")

    def test_dependency_wake_waits_then_wakes(self) -> None:
        work = self.work(mode="DEPENDENCY", dependencies=("artifact:A",))
        result = self.adapter.process(work, lambda *_: True, dependency_state={"artifact:A": False})
        self.assertEqual(result["wake_status"], "WAITING_DEPENDENCY")
        awakened = self.adapter.dependency_wake(
            {"artifact:A": True}, lambda _envelope, _recipient, reason: reason == "DEPENDENCY"
        )
        self.assertEqual(awakened, [work.message_id])

    def test_unwakeable_surface_is_durable_until_heartbeat(self) -> None:
        work = self.work(surface="LeadC")
        result = self.adapter.process(work, lambda *_: True, directly_wakeable=False)
        self.assertEqual(result["wake_status"], "DURABLE_UNREAD")
        unread_path = ("unread", "LeadC", f"{work.message_id}.json")
        self.assertIsNotNone(self.adapter.fs.read_json(unread_path))
        awakened = self.adapter.heartbeat_fallback(
            lambda _envelope, _recipient, reason: reason == "HEARTBEAT"
        )
        self.assertEqual(awakened, [work.message_id])
        self.assertIsNone(self.adapter.fs.read_json(unread_path, optional=True))
        wake_receipt = self.adapter.fs.read_json(
            ("wake_receipts", f"{work.message_id}.json")
        )
        self.assertIsNotNone(wake_receipt)
        verify_document(
            wake_receipt,
            {public_key_id(self.sender.public_key()): self.sender.public_key()},
        )

    def test_files_01_04_and_legacy_discovery_are_content_addressed(self) -> None:
        active_roots = {}
        for index, channel in enumerate(
            (
                "01 Research and Architecture",
                "02 LeadA Active Build",
                "03 Reviews and Decisions",
                "04 Verification and Release Receipts",
            )
        ):
            root = self.base / f"active-{index}"
            root.mkdir()
            (root / f"to-builda-{index}.md").write_text(f"bounded-{index}", encoding="utf-8")
            active_roots[channel] = root
        legacy = self.base / "legacy"
        legacy.mkdir()
        (legacy / "to-leadb.md").write_text("legacy", encoding="utf-8")
        source = FileRouteDiscovery()
        found = source.discover(
            {
                **active_roots,
                "peer_outbox/from_peers": legacy,
            },
            lambda path: "BuildA" if "builda" in path.name else "LeadB",
        )
        self.assertEqual([item.transport_kind for item in found], ["FILES_01_04"] * 4 + ["LEGACY_LANE"])
        self.assertEqual({item.recipient_surface for item in found}, {"BuildA", "LeadB"})
        first_channel = "01 Research and Architecture"
        self.assertEqual(
            source.discover({first_channel: active_roots[first_channel]}, lambda _: "BuildA")[0].message_id,
            found[0].message_id,
        )

    def test_github_discovery_requires_machine_app_and_exact_routes(self) -> None:
        with self.assertRaisesRegex(ProtocolError, "machine App"):
            MachineAppIdentity("example-human", 1, 1)
        source = GitHubAssignmentDiscovery(self.app)
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        work = source.discover(
            [
                {
                    "kind": "pull_request",
                    "number": 19,
                    "repository": "example-org/example-repo",
                    "updated_at": now,
                    "assigned": True,
                }
            ],
            "BuildA",
        )[0]
        self.assertEqual(work.source_channel, "github:pull_request")
        self.assertEqual(work.transport_actor, "hive-builda-app[bot]")
        self.assertEqual(self.adapter.process(work, lambda *_: True)["wake_status"], "AWAKENED")

    def test_single_writer_git_lock_serializes_concurrent_operations(self) -> None:
        writer = SingleWriterGitTransport(
            self.base / "git", self.app, self.sender, self.builda
        )
        active = 0
        maximum = 0
        guard = threading.Lock()
        actors = []

        def operation(identity):
            nonlocal active, maximum
            with guard:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.03)
            actors.append(identity.actor)
            with guard:
                active -= 1
            return {"actor": identity.actor, "result": "readback-pass"}

        threads = [
            threading.Thread(target=lambda: writer.execute(self.app, operation)) for _ in range(6)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(maximum, 1)
        self.assertEqual(actors, ["hive-builda-app[bot]"] * 6)
        git_receipt = writer.fs.read_json(("receipts", "last-git-write.json"))
        self.assertIsNotNone(git_receipt)
        verify_document(
            git_receipt,
            {public_key_id(self.sender.public_key()): self.sender.public_key()},
        )

    def test_single_writer_rejects_human_or_mismatched_readback(self) -> None:
        writer = SingleWriterGitTransport(
            self.base / "git-mismatch", self.app, self.sender, self.builda
        )
        called = False
        wrong = MachineAppIdentity("hive-other-app[bot]", 99, 100)

        def must_not_run(_identity):
            nonlocal called
            called = True
            return {"actor": self.app.actor}

        with self.assertRaisesRegex(ProtocolError, "before execution"):
            writer.execute(wrong, must_not_run)
        self.assertFalse(called)
        with self.assertRaisesRegex(ProtocolError, "readback"):
            writer.execute(self.app, lambda _identity: {"actor": "example-human"})

    def test_single_writer_lock_serializes_separate_processes(self) -> None:
        processes = [
            multiprocessing.Process(target=_process_writer, args=(str(self.base), sequence))
            for sequence in range(4)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=5)
            self.assertEqual(process.exitcode, 0)
        lines = (self.base / "process-writer.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 8)
        for index in range(0, len(lines), 2):
            self.assertTrue(lines[index].startswith("start:"))
            self.assertEqual(lines[index].removeprefix("start:"), lines[index + 1].removeprefix("finish:"))

    def test_transport_state_has_exact_rollback_boundary(self) -> None:
        sentinel = self.base / "sentinel"
        sentinel.write_text("unowned", encoding="utf-8")
        self.adapter.process(self.work(), lambda *_: False)
        import shutil
        shutil.rmtree(self.base / "transport")
        shutil.rmtree(self.base / "matrix")
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unowned")


if __name__ == "__main__":
    unittest.main()
