"""scripts/migrate_provenance_bba.py must seed the SAME BBA the runtime seeds.

Backlog fc55465b (drain U026): `ds_auto::auto_wire_ds_update` seeds a BBA-less
claim with `MassFunction::from_pignistic_prior` (m({idx}) = 2t-1, m(Θ) = 2-2t, so
BetP = t), t capped to [0.005, 0.995], tagged `combination_method =
'truth_value_seed'`. #472's corpus migration seeded m({idx}) = t (BetP = (1+t)/2).
It skips any (claim, frame) that already has a BBA, so if the two disagree the
corpus keeps two conventions forever. These tests drive `migrate()` (and
`validate_targets()`) through a recording cursor at the DB boundary and assert
on the rows the script would INSERT. Nothing here touches a database.

Run: python3 -m unittest discover -s scripts/tests -p 'test_migrate_provenance_bba.py' -v
"""
import argparse
import io
import json
import sys
import types
import unittest
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
try:  # the script imports psycopg2 at module load; the logic under test does not need it
    import psycopg2  # noqa: F401
except ImportError:  # pragma: no cover - environment without psycopg2
    extras = types.ModuleType("psycopg2.extras")
    extras.RealDictCursor = object
    stub = types.ModuleType("psycopg2")
    stub.extras = extras
    sys.modules["psycopg2"] = stub
    sys.modules["psycopg2.extras"] = extras
import migrate_provenance_bba as mpb  # noqa: E402

FRAME = str(uuid.uuid4())
AGENT = str(uuid.uuid4())
PERSP = str(uuid.uuid4())


class RecordingCursor:
    """Answers the eligible-pairs SELECT with `rows`; records every INSERT."""

    def __init__(self, rows):
        self._rows = rows
        self._pending = None
        self.inserts = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        if s.startswith("SELECT c.id AS claim_id"):
            self._pending = ("all", list(self._rows))
        elif s.startswith("INSERT INTO claim_frames"):
            self.rowcount = 1
        elif s.startswith("INSERT INTO mass_functions"):
            self.inserts.append(dict(params))
            self._pending = ("one", {"id": uuid.uuid4()})
        else:
            raise AssertionError(f"unexpected SQL in test: {s[:80]}")

    def fetchall(self):
        kind, val = self._pending
        assert kind == "all"
        return val

    def fetchone(self):
        kind, val = self._pending
        assert kind == "one"
        return val


def pair(tv, idx=0, n_hyp=2):
    return {
        "claim_id": uuid.uuid4(),
        "frame_id": FRAME,
        "frame_name": "binary_truth",
        "n_hypotheses": n_hyp,
        "truth_value": tv,
        "hypothesis_index": idx,
        "needs_assignment": False,
    }


def args(execute=True):
    return argparse.Namespace(
        frame_ids=[FRAME], default_hypothesis_index=0, limit=100, offset=0,
        execute=execute, source_agent_id=AGENT, perspective_id=PERSP,
        source_strength=0.7, evidence_type="textbook_assertion",
    )


def run(rows, execute=True):
    cur = RecordingCursor(rows)
    manifest = io.StringIO()
    written = mpb.migrate(cur, args(execute), manifest)
    return cur, written, [json.loads(l) for l in manifest.getvalue().splitlines()]


def betp(masses, idx):
    return masses.get(str(idx), 0.0) + masses.get("0,1", 0.0) / 2


class SeedShape(unittest.TestCase):
    def test_seed_is_pignistic_preserving_not_simple_support(self):
        cur, _, _ = run([pair(0.75)])
        masses = json.loads(cur.inserts[0]["masses"])
        # from_pignistic_prior(binary, 0, 0.75) = {T 0.5, Θ 0.5}; the #472 shape was {T 0.75, Θ 0.25}
        self.assertEqual(masses, {"0": 0.5, "0,1": 0.5})
        self.assertAlmostEqual(betp(masses, 0), 0.75, places=12)

    def test_betp_equals_truth_value_across_the_range(self):
        for tv in (0.05, 0.3, 0.49, 0.51, 0.6, 0.85, 0.9, 0.99):
            for idx in (0, 1):
                with self.subTest(tv=tv, idx=idx):
                    cur, _, _ = run([pair(tv, idx)])
                    masses = json.loads(cur.inserts[0]["masses"])
                    self.assertAlmostEqual(betp(masses, idx), tv, places=12)
                    self.assertAlmostEqual(sum(masses.values()), 1.0, places=12)
                    self.assertTrue(all(m >= 0 for m in masses.values()))

    def test_false_leaning_truth_puts_mass_on_the_other_hypothesis(self):
        cur, _, _ = run([pair(0.25, 0), pair(0.25, 1)])
        self.assertEqual(json.loads(cur.inserts[0]["masses"]), {"1": 0.5, "0,1": 0.5})
        self.assertEqual(json.loads(cur.inserts[1]["masses"]), {"0": 0.5, "0,1": 0.5})

    def test_certain_truth_is_capped_to_a_revisable_seed(self):
        # SEED_TRUTH_BOUNDS (0.005, 0.995): committed mass <= 0.99, never categorical
        cur, _, _ = run([pair(1.0), pair(0.0)])
        top, bottom = (json.loads(i["masses"]) for i in cur.inserts)
        self.assertAlmostEqual(top["0"], 0.99, places=12)
        self.assertAlmostEqual(top["0,1"], 0.01, places=12)
        self.assertAlmostEqual(bottom["1"], 0.99, places=12)
        self.assertAlmostEqual(bottom["0,1"], 0.01, places=12)

    def test_half_writes_nothing(self):
        cur, written, manifest = run([pair(0.5), pair(0.5 + 1e-12)])
        self.assertEqual(cur.inserts, [])
        self.assertEqual(written, 0)
        self.assertEqual(manifest, [])


class Tagging(unittest.TestCase):
    def test_rows_carry_the_runtime_seed_tag_and_the_migration_is_in_the_manifest(self):
        cur, written, manifest = run([pair(0.85)])
        self.assertEqual(written, 1)
        self.assertEqual(cur.inserts[0]["marker"], "truth_value_seed")
        self.assertEqual(manifest[0]["combination_method"], "truth_value_seed")
        self.assertEqual(manifest[0]["migration"], "provenance_migration_v1")


class DryRun(unittest.TestCase):
    def test_dry_run_inserts_nothing_and_counts_only_non_vacuous_pairs(self):
        cur, would, manifest = run([pair(0.85), pair(0.5), pair(0.2)], execute=False)
        self.assertEqual(cur.inserts, [])
        self.assertEqual(manifest, [])
        self.assertEqual(would, 2)


class FrameArity(unittest.TestCase):
    def test_a_ternary_pair_is_refused_not_seeded(self):
        with self.assertRaises(SystemExit):
            run([pair(0.75, 0, n_hyp=3)])

    def test_validate_targets_refuses_a_non_binary_frame(self):
        class Cur:
            def execute(self, sql, params=None):
                self.sql = sql

            def fetchall(self):
                return [{"id": FRAME, "name": "ternary", "hypotheses": ["a", "b", "c"]}]

            def fetchone(self):  # any later lookup (perspective, agent) finds nothing
                return None

        with self.assertRaises(SystemExit) as cm:
            mpb.validate_targets(Cur(), [FRAME], PERSP, AGENT, "textbook_assertion", 0)
        self.assertIn("binary", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
