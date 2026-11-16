"""run_assessment_worker.py refuses to start without conformal quantiles (backlog 3a6666e9).

auto_tier routes on calibration.toml `[conformal.quantiles]` and raises when the
section is missing. process_entry catches every auto_tier exception and marks
the queue entry 'failed', so without a check at startup a misconfigured
CALIBRATION_PATH would fail the whole batch one claim at a time, after setting
each to 'assessing'. main() reads the quantiles before it touches the queue.
"""
import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
# The worker checks at import that its read and admin DSNs name one database.
# Pin both to one placeholder (nothing connects: the queue read is stubbed), so
# the test does not depend on the shell's DATABASE_URL or on DSN defaults.
_DSN = "postgres://worker:worker@localhost:5432/assessment_worker_test"
with mock.patch.dict(os.environ, {"DATABASE_URL": _DSN, "MAINTENANCE_DATABASE_URL": _DSN}):
    import run_assessment_worker as worker  # noqa: E402
from lib import tiered_enrichment as te  # noqa: E402


class WorkerCalibrationTest(unittest.TestCase):
    def setUp(self):
        self.queue_reads = []
        te.routing_quantiles.cache_clear()
        self.addCleanup(te.routing_quantiles.cache_clear)

    def run_main(self, calibration_path):
        def fake_pending(limit, include_failed=False):
            self.queue_reads.append(limit)
            return []

        env = dict(os.environ)
        if calibration_path is None:
            env.pop("CALIBRATION_PATH", None)
        else:
            env["CALIBRATION_PATH"] = calibration_path
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(worker, "get_pending_assessments", fake_pending), \
                mock.patch.object(sys, "argv", ["run_assessment_worker.py", "--limit", "3"]):
            asyncio.run(worker.main())

    def test_missing_conformal_section_stops_the_run_before_the_queue_is_read(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
            fh.write("[thresholds]\nsupported = 0.5\n")
        self.addCleanup(os.unlink, fh.name)
        with self.assertRaisesRegex(ValueError, r"\[conformal\.quantiles\]"):
            self.run_main(fh.name)
        self.assertEqual(self.queue_reads, [])

    def test_shipped_calibration_lets_the_run_proceed(self):
        self.run_main(None)
        self.assertEqual(self.queue_reads, [3])


if __name__ == "__main__":
    unittest.main()
