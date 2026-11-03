import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from relay.capture import build_bpf
from relay.demo_adapter import DemoAdapter, encode
from relay.devices import Devices
from relay.pipeline import Pipeline
from relay.reassembly import FlowBuffer, is_stream_probe, seq_delta

FLOW = ("198.51.100.7", 40000, "192.0.2.10", 50000)


def make_pipeline():
    got = []
    return Pipeline(DemoAdapter(), [got.append]), got


class ReassemblyTest(unittest.TestCase):
    def test_seq_wraparound(self):
        self.assertEqual(seq_delta(5, 2**32 - 5), 10)
        self.assertEqual(seq_delta(2**32 - 5, 5), -10)

    def test_out_of_order_and_retransmit(self):
        flow = FlowBuffer()
        self.assertEqual(flow.push(100, b"abc"), b"abc")
        self.assertEqual(flow.push(106, b"ghi"), b"")
        self.assertEqual(flow.push(103, b"def"), b"defghi")
        self.assertEqual(flow.push(100, b"abc"), b"")

    def test_partial_overlap_keeps_only_new_bytes(self):
        flow = FlowBuffer()
        flow.push(100, b"abcd")
        self.assertEqual(flow.push(102, b"cdef"), b"ef")

    def test_probe_detection(self):
        self.assertTrue(is_stream_probe(0x10, b"\x00"))
        self.assertFalse(is_stream_probe(0x18, b"\x00"))
        self.assertFalse(is_stream_probe(0x10, b"hi"))


class PipelineTest(unittest.TestCase):
    def test_frame_split_across_segments(self):
        pipeline, got = make_pipeline()
        data = encode(sender="a", text="첫째") + encode(sender="b", text="둘째")
        for i in range(len(data)):
            pipeline.feed(FLOW, 1000 + i, data[i:i + 1])
        self.assertEqual([m.text for m in got], ["첫째", "둘째"])

    def test_non_message_frame_is_filtered(self):
        pipeline, got = make_pipeline()
        pipeline.feed(FLOW, 1, encode(state="heartbeat"))
        self.assertEqual(got, [])

    def test_directions_do_not_mix(self):
        pipeline, got = make_pipeline()
        a, b = encode(text="위"), encode(text="아래")
        reverse = (FLOW[2], FLOW[3], FLOW[0], FLOW[1])
        pipeline.feed(FLOW, 1, a[:5])
        pipeline.feed(reverse, 900, b)
        pipeline.feed(FLOW, 6, a[5:])
        self.assertEqual([m.text for m in got], ["아래", "위"])

    def test_resyncs_after_garbage_and_broken_frame(self):
        pipeline, got = make_pipeline()
        broken = b"DEMO\x00\x02{{"
        pipeline.feed(FLOW, 1, b"junk" + broken + encode(text="복구"))
        self.assertEqual([m.text for m in got], ["복구"])

    def test_flush_drops_truncated_frame_and_stream_continues(self):
        pipeline, got = make_pipeline()
        whole = encode(text="잘림")
        pipeline.feed(FLOW, 1, whole[:-2])
        pipeline.flush()
        self.assertEqual(got, [])
        next_seq = 1 + len(whole) - 2
        pipeline.feed(FLOW, next_seq, encode(text="다음"))
        self.assertEqual([m.text for m in got], ["다음"])


class CaptureFilterTest(unittest.TestCase):
    def test_endpoints_take_priority(self):
        self.assertEqual(build_bpf({("192.0.2.1", 5000)}, [6000]), "tcp and (host 192.0.2.1) and (port 5000)")

    def test_fallback_ports(self):
        self.assertEqual(build_bpf(set(), [6000, 6001]), "tcp and (port 6000 or port 6001)")

    def test_no_target_is_an_error(self):
        with self.assertRaises(ValueError):
            build_bpf(set(), [])


class DevicesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "config.json"
        self.cfg = {}
        self.devices = Devices(self.cfg, self.save, self.path)

    def save(self):
        self.path.write_text(json.dumps(self.cfg), encoding="utf-8")

    def test_pair_stores_only_hash_and_revoke_works(self):
        self.devices.start_pairing("phone")
        key = self.devices.pair(self.devices.code, "phone")
        dev_id = self.devices.check(key)
        self.assertIsNotNone(dev_id)
        self.assertNotIn(key, self.path.read_text(encoding="utf-8"))
        self.assertEqual(self.devices.revoke("phone"), [dev_id])
        self.assertIsNone(self.devices.check(key))

    def test_code_discarded_after_five_wrong_attempts(self):
        self.devices.start_pairing("phone")
        code = self.devices.code
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(5):
            self.assertIsNone(self.devices.pair(wrong, "phone"))
        self.assertIsNone(self.devices.pair(code, "phone"))


if __name__ == "__main__":
    unittest.main()
