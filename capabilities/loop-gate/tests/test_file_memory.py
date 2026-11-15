import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from file_memory.file_memory import FileMemory

class T(unittest.TestCase):
    def setUp(self): self.m = FileMemory(tempfile.mkdtemp())
    def test_write_recall(self):
        self.m.write("preferences", "report-time-zone", "Report times in America/Chicago")
        self.m.write("projects", "intake-desk", "Intake desk reads back the request log after intake")
        self.assertEqual(self.m.recall("request log readback")[0].key, "intake-desk")
    def test_supersede(self):
        self.m.write("profile", "server-ram", "The build server has 64GB", date="2026-10-01")
        self.m.write("profile", "server-ram", "The build server has 128GB unified memory", date="2026-11-01")
        plan = self.m.consolidate(today="2026-11-05")
        self.assertEqual([p["action"] for p in plan], ["supersede"])
        self.assertEqual([f.text for f in self.m.all()], ["The build server has 128GB unified memory"])
        self.assertEqual(len(self.m.all(include_inactive=True)), 2)  # tombstoned, not deleted
    def test_dedupe_and_forget(self):
        self.m.write("topics", "a", "Langfuse is on watch", date="2026-01-01")
        self.m.write("topics", "b", "langfuse IS on watch!", date="2026-01-02")
        self.m.write("topics", "c", "old topic", date="2025-01-01")
        plan = self.m.consolidate(max_age_days=180, today="2026-11-05")
        acts = sorted(p["action"] for p in plan)
        self.assertIn("dedupe", acts); self.assertIn("forget", acts)
    def test_dry_run(self):
        self.m.write("profile", "k", "v1", date="2026-01-01"); self.m.write("profile", "k", "v2", date="2026-02-01")
        self.m.consolidate(apply=False); self.assertEqual(len(self.m.all()), 2)
    def test_apply_context(self):
        self.m.write("preferences", "tz", "Use Central time")
        self.assertIn("Central", self.m.apply_context("central time"))

if __name__ == "__main__": unittest.main()
