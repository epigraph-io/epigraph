"""`theme_pipeline --dry-run` writes nothing.

`grow --dry-run` used to run the whole base phase before it looked at the flag.
`cluster_claims.seed_phase` wrote a new run's `cluster_centroids` and
`cluster_labels` and replaced `data/umap_reducer.pkl`. `assign_batch` then
upserted `claim_clusters`, which holds one row per claim (`UNIQUE (claim_id)`).
So a "preview" replaced every claim's live cluster assignment with an unsplit
base run. It also left that run as the newest `cluster_centroids` run, which
`project` and `discover` pick when given no run id. `project --dry-run` and
`label --dry-run` ignored the flag and wrote for real.

These tests pin the replacement:

* a fresh `grow --dry-run` reports its plan and calls no writer, and runs no
  SQL at all;
* a resumed `grow --from-run-id X --dry-run` reads the run's stats and stops
  before any split, projection or label;
* `--dry-run` opens the connection read-only before its first statement, so a
  write that slips in later raises instead of committing;
* `project` and `label` refuse `--dry-run` before they connect, and keep a
  writable connection without it.

Each case runs `theme_pipeline` in a child process behind
`_offline_script_harness`'s stubs, with every writer replaced by a recorder and
the connection replaced by a fake that logs each statement. Nothing opens a
socket. Run from the repo root with Python 3.11 or newer:

    python3 -m unittest discover -s scripts/tests -p 'test_theme_pipeline_dry_run.py'
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
HARNESS_DIR = Path(__file__).resolve().parent

# A DSN with no password, so this file never trips the credential lint. The
# fake connection never uses it.
SCRATCH_DSN = "postgres://someone@127.0.0.1:1/scratch"

# One cluster over the default --max-size ceiling, one under it. With k=2 and
# --target-k 72, the loop's first iteration selects cluster 0 and does not stop,
# so a resumed dry run reaches its "would split" branch.
STATS = [[0, 40000, 0.03, 0.30], [1, 3000, 0.02, 0.20]]

GROW_ARGS = {
    "sample_size": 5000,
    "batch_size": 2000,
    "k": None,
    "all_claims": False,
    "target_k": 72,
    "min_size": 2000,
    "max_size": 8000,
    "max_iter": 8,
    "run_id": None,
    "from_run_id": None,
    "dry_run": True,
    "database_url": SCRATCH_DSN,
}

PROBE = r"""
import argparse, json, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import _offline_script_harness
_offline_script_harness.install_stubs()
import theme_pipeline as T

scenario = json.loads(sys.argv[3])
calls, events = [], []

def recorder(name, ret=None):
    def record(*args, **kwargs):
        calls.append(name)
        return ret
    return record

T.cluster_claims.seed_phase = recorder("seed_phase", (None, [], 0))
T.cluster_claims.assign_batch = recorder("assign_batch")
T.refine_clusters.auto_refine = recorder("auto_refine")
T.project_to_themes.project_run = recorder("project_run", 0)
T.subprocess.run = recorder("subprocess.run")

class Cursor:
    def __init__(self, conn):
        self.conn, self.rows = conn, []
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False
    def execute(self, sql, params=None):
        text = " ".join(sql.split())
        events.append(["execute", text])
        low = text.lower()
        if "percentile_cont" in low:
            self.rows = [tuple(r) for r in self.conn.stats]
        elif "count(distinct cluster_id)" in low:
            self.rows = [(len(self.conn.stats),)]
        else:
            self.rows = []
    def fetchall(self):
        return list(self.rows)
    def fetchone(self):
        return self.rows[0] if self.rows else None

class Conn:
    def __init__(self, stats):
        self.stats = stats
    def cursor(self):
        return Cursor(self)
    def set_session(self, **kwargs):
        events.append(["set_session", kwargs])
    def commit(self):
        events.append(["commit"])
    def rollback(self):
        events.append(["rollback"])
    def close(self):
        events.append(["close"])

conn = Conn(scenario.get("stats", []))
out = {"calls": calls, "events": events}
if "grow_args" in scenario:
    out["result"] = T.grow(conn, argparse.Namespace(**scenario["grow_args"]))
else:
    def connect(url=None):
        events.append(["connect"])
        return conn
    T.theme_lib.connect = connect
    sys.argv = ["theme_pipeline.py", *scenario["argv"]]
    try:
        T.main()
        out["exit"] = 0
    except SystemExit as e:
        out["exit"] = e.code
print(json.dumps(out))
"""


def probe(scenario):
    proc = subprocess.run(
        [sys.executable, "-c", PROBE, str(HARNESS_DIR), str(SCRIPTS), json.dumps(scenario)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise AssertionError(f"probe failed ({proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[-1]), proc.stderr


def statements(events):
    return [e[1] for e in events if e[0] == "execute"]


class ThemePipelineDryRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.version_info < (3, 11):
            raise AssertionError(
                f"run these with Python >= 3.11; this is {sys.version.split()[0]}."
            )

    def assert_no_writes(self, out):
        self.assertEqual(out["calls"], [], "a dry run called a writer")
        for sql in statements(out["events"]):
            self.assertTrue(
                sql.upper().startswith(("SELECT", "SET ")),
                f"a dry run executed a non-read statement: {sql}",
            )

    def test_fresh_grow_dry_run_creates_no_base_run(self):
        # Before the fix this called seed_phase and assign_batch, which is the
        # ~40-minute base run that overwrites claim_clusters for every claim.
        out, _ = probe({"grow_args": GROW_ARGS, "stats": STATS})
        self.assert_no_writes(out)
        self.assertEqual(statements(out["events"]), [], "a fresh dry run has no run to read")
        self.assertNotIn(["commit"], out["events"])
        self.assertEqual(out["result"]["status"], "dry-run")
        self.assertIsNone(out["result"]["run_id"], "a dry run must not mint a run id")
        # The plan names the parameters the real run would use.
        plan = json.dumps(out["result"])
        for value in ("5000", "2000", "8000", "72"):
            self.assertIn(value, plan)

    def test_resumed_grow_dry_run_reports_the_split_and_writes_nothing(self):
        args = dict(GROW_ARGS, from_run_id="run-under-test")
        out, stderr = probe({"grow_args": args, "stats": STATS})
        self.assert_no_writes(out)
        self.assertNotIn(["commit"], out["events"])
        self.assertEqual(
            out["result"], {"status": "dry-run", "run_id": "run-under-test", "k": 2}
        )
        self.assertIn("would split clusters [0]", stderr)

    def test_dry_run_connection_is_read_only_before_any_statement(self):
        out, _ = probe({
            "argv": ["grow", "--dry-run", "--database-url", SCRATCH_DSN],
            "stats": STATS,
        })
        self.assertEqual(out["exit"], 0)
        self.assert_no_writes(out)
        kinds = [e[0] for e in out["events"]]
        self.assertIn("set_session", kinds, "a dry run must open a read-only session")
        first_session = kinds.index("set_session")
        self.assertEqual(out["events"][first_session][1], {"readonly": True})
        # psycopg2 refuses set_session inside an open transaction, and a
        # statement issued first would run outside the read-only guard.
        self.assertEqual(kinds[:2], ["connect", "set_session"], out["events"])

    def test_resumed_dry_run_through_main_is_read_only_too(self):
        out, _ = probe({
            "argv": ["grow", "--from-run-id", "run-under-test", "--dry-run",
                     "--database-url", SCRATCH_DSN],
            "stats": STATS,
        })
        self.assertEqual(out["exit"], 0)
        self.assert_no_writes(out)
        kinds = [e[0] for e in out["events"]]
        self.assertEqual(kinds[:2], ["connect", "set_session"], out["events"])

    def test_project_and_label_refuse_dry_run_before_connecting(self):
        # Both ignored the flag: `project --dry-run` replaced claim_themes and
        # `label --dry-run` relabelled every theme.
        for argv in (["project", "--run-id", "run-under-test"], ["label"]):
            with self.subTest(command=argv[0]):
                out, _ = probe({
                    "argv": [*argv, "--dry-run", "--database-url", SCRATCH_DSN],
                    "stats": STATS,
                })
                self.assertEqual(out["exit"], 2, "argparse usage error expected")
                self.assertEqual(out["calls"], [])
                self.assertEqual(out["events"], [], "refusal must come before connect")

    def test_write_commands_keep_a_writable_connection(self):
        # The read-only session is scoped to --dry-run; project must still write.
        out, _ = probe({
            "argv": ["project", "--run-id", "run-under-test", "--database-url", SCRATCH_DSN],
            "stats": STATS,
        })
        self.assertEqual(out["exit"], 0)
        self.assertEqual(out["calls"], ["project_run"])
        self.assertNotIn("set_session", [e[0] for e in out["events"]])


if __name__ == "__main__":
    unittest.main()
