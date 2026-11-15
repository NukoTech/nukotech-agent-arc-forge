import unittest
from datetime import datetime, timezone

from hive_protocol.awareness import awareness_candidates


class AwarenessTests(unittest.TestCase):
    def test_all_awareness_kinds_are_proposals_only(self):
        events = [
            {"event_id": "one", "state": "OPEN", "type": "decision", "subject": "release",
             "value": "hold", "review_at": "2026-01-01T00:00:00Z", "topics": ["hive"],
             "related_source_ids": ["note-1"]},
            {"event_id": "two", "state": "DONE", "type": "observation", "subject": "release",
             "value": "ship", "topics": ["hive"]},
        ]
        candidates = awareness_candidates(
            events, now=datetime(2026, 8, 26, tzinfo=timezone.utc), stale_days=30
        )
        self.assertEqual(
            {item["kind"] for item in candidates},
            {"UNFINISHED", "CONTRADICTION", "STALE_DECISION", "REPEATED_TOPIC", "RELATED_CONTEXT"},
        )
        self.assertTrue(all(item["status"] == "PROPOSED" for item in candidates))
        self.assertTrue(all(item["external_action"] is False for item in candidates))


if __name__ == "__main__":
    unittest.main()
