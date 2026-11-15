import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loop_gate.loop_gate import Unit, LoopGate, GraphError, ACCEPTED, ESCALATED, BLOCKED, AWAITING_SIGNATURE
from loop_gate.packets import load_packets, to_units, PacketError, validate_packet

def ok(v): return lambda i, e: v
def is_int(o): assert isinstance(o, int), "not int"

class T(unittest.TestCase):
    def test_fanout_and_deps(self):
        r = LoopGate([Unit("a", ok(1), is_int), Unit("b", ok(2), is_int),
                      Unit("c", lambda i, e: i["a"] + i["b"], is_int, deps=["a", "b"])]).run()
        self.assertEqual(r["c"].output, 3); self.assertTrue(all(x.status == ACCEPTED for x in r.values()))
    def test_repair_once(self):
        r = LoopGate([Unit("a", lambda i, e: 5 if e else "bad", is_int)]).run()
        self.assertEqual((r["a"].status, r["a"].attempts), (ACCEPTED, 2))
    def test_same_error_twice_escalates_and_blocks(self):
        r = LoopGate([Unit("a", ok("x"), is_int), Unit("b", ok(1), is_int, deps=["a"])]).run()
        self.assertEqual(r["a"].status, ESCALATED); self.assertEqual(r["b"].status, BLOCKED)
    def test_irreversible_needs_signature(self):
        us = lambda: [Unit("a", ok(1), is_int), Unit("pay", ok(1), is_int, deps=["a"], kind="money")]
        self.assertEqual(LoopGate(us()).run()["pay"].status, AWAITING_SIGNATURE)
        self.assertEqual(LoopGate(us(), signatures={"pay"}).run()["pay"].status, ACCEPTED)
    def test_cycle_rejected(self):
        with self.assertRaises(GraphError):
            LoopGate([Unit("a", ok(1), is_int, deps=["b"]), Unit("b", ok(1), is_int, deps=["a"])])

def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

class Packets(unittest.TestCase):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "example_packets.json")
    canned = {"intake.request.001": {"record_id": "R-1", "due": "2026-11-20"},
              "verify.request.001": {"readback": {"due": "2026-11-20", "record_id": "R-1"}},
              "draft.report.001": {"total": 300.0, "sum_lines": 300.0},
              "deliver.report_send.001": {"sent_to": "requester"}}
    def test_examples_validate_and_gate_sends(self):
        ps = load_packets(self.path)
        h = lambda p, i, e: self.canned[p["unit_id"]]
        r = LoopGate(to_units(ps, {p["owner_bot"]: h for p in ps})).run()
        self.assertEqual(r["verify.request.001"].status, ACCEPTED)
        self.assertEqual(r["draft.report.001"].status, ACCEPTED)
        self.assertEqual(r["deliver.report_send.001"].status, AWAITING_SIGNATURE)
    def test_send_step_must_be_flagged(self):
        p = _load(self.path)[-1]; p["irreversible"] = False
        with self.assertRaises(PacketError): validate_packet(p)
    def test_every_money_unit_requires_irreversible(self):
        pay = dict(_load(self.path)[0], unit_id="pay.payment.001", loop_stage="report", irreversible=False)
        with self.assertRaises(PacketError): validate_packet(pay)
    def test_verification_readback_mismatch_escalates(self):
        ps = load_packets(self.path)[:2]
        out = dict(self.canned, **{"verify.request.001": {"readback": {"due": "2026-11-21", "record_id": "R-1"}}})
        r = LoopGate(to_units(ps, {"Intake Agent": lambda p, i, e: out[p["unit_id"]]})).run()
        self.assertEqual(r["verify.request.001"].status, ESCALATED)
    def test_check_required(self):
        p = _load(self.path)[0]; p["check"] = {"type": "vibes"}
        with self.assertRaises(PacketError): validate_packet(p)

if __name__ == "__main__": unittest.main()
