"""There is no default database: every script that connects refuses without a DSN.

Twenty-one scripts under `scripts/` used to fall back to a credentialed DSN for
the live `epigraph` database whenever the environment named none. This pins the
replacement rule (`maintenance_dsn.require_dsn`) at two levels:

* the helpers themselves, in-process; and
* every connecting script, end to end, run through `_offline_script_harness.py`
  with the database driver stubbed. With no DSN in the environment each must
  exit with the refusal BEFORE it reaches the driver's connect. Before the fix
  every one of them reached connect, handing it the hardcoded literal.

Run from the repo root with Python 3.11 or newer (the scripts' own floor: one
imports `tomllib` unconditionally, and `lib/claude_cli.py` uses PEP 604
annotations):

    python3 -m unittest discover -s scripts/tests -p 'test_no_default_database.py'

Nothing here opens a socket. The harness replaces the driver before any script
imports it, on a machine where the real driver is installed as well.

The static half of this rule, which CI runs, is
`crates/epigraph-db/tests/scripts_have_no_default_dsn.rs`.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
HARNESS = Path(__file__).resolve().parent / "_offline_script_harness.py"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(HARNESS.parent))

import maintenance_dsn as md  # noqa: E402
from _offline_script_harness import REACHED_CONNECT_EXIT, REACHED_CONNECT_MARKER  # noqa: E402

REFUSAL = "FATAL: no database configured."

# Every variable a script, or libpq behind it, could take a database from.
DSN_ENV = (
    "DATABASE_URL",
    "MAINTENANCE_DATABASE_URL",
    "DATABASE_ADMIN_URL",
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGSERVICE",
)

# A DSN with no password, so this file never trips the credential lint.
SCRATCH_DSN = "postgres://someone@127.0.0.1:1/scratch"
OTHER_DSN = "postgres://someone@127.0.0.1:1/elsewhere"

# Every script that opens a connection, with the fewest arguments that get it
# past argparse. `test_connecting_scripts_are_all_listed` fails when a new one
# appears, so this table cannot silently fall behind the tree.
CASES = {
    "anchor_papers_to_themes.py": [],
    "audit_claims_content_hash_agent.py": [],
    "audit_mixed_bbas.py": [],
    "backfill_intra_source_evidence_discount.py": [],
    "backfill_locality_tag.py": [],
    "backfill_source_strength.py": [],
    "classify_paper_document_type.py": [],
    "cluster_claims.py": [],
    "compute_semantic_dedup.py": [],
    "evidential_clustering.py": [],
    "fuzzy_dedup_claims.py": [],
    "label_themes_llm.py": [],
    "link_mass_function_evidence.py": [],
    "migrate_mixed_bbas.py": [],
    "migrate_provenance_bba.py": [],
    "phase2_locality_tag_vocab_migration.py": [],
    "project_to_themes.py": [],
    "refine_clusters.py": [],
    "run_assessment_worker.py": [],
    "seed_themes_from_textbooks.py": [],
    "subcluster_outliers.py": [],
    "theme_pipeline.py": ["grow"],
    "update_theme_workflow_steps.py": [],
    "lib/tiered_enrichment.py": [
        "--tier", "1", "--claim-id", "00000000-0000-0000-0000-000000000000",
    ],
}

# Library modules that connect on behalf of a script rather than being one.
# `theme_lib.connect` is exercised through project_to_themes and theme_pipeline.
LIBRARIES = {"theme_lib.py"}

# Spelled in two halves so this file does not itself read as a script that
# opens a connection to `no_unmaintained_dsn.rs`, which greps for the whole.
DRIVER_CONNECT = "psycopg2" + ".connect("
THEME_LIB_CONNECT = "theme_lib" + ".connect("


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in DSN_ENV}
    env.update(extra)
    return env


def run_script(rel, args, env):
    return subprocess.run(
        [sys.executable, str(HARNESS), str(SCRIPTS / rel), *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


class RequireDsnTests(unittest.TestCase):
    def test_none_refuses(self):
        with self.assertRaises(SystemExit) as cm:
            md.require_dsn(None)
        self.assertIn(REFUSAL, str(cm.exception.code))
        self.assertIn("MAINTENANCE_DATABASE_URL", str(cm.exception.code))

    def test_empty_string_refuses(self):
        # An empty DSN is as dangerous as None: libpq fills it in from its own
        # environment rather than raising.
        with self.assertRaises(SystemExit):
            md.require_dsn("")

    def test_a_dsn_passes_through_unchanged(self):
        self.assertEqual(md.require_dsn(SCRATCH_DSN), SCRATCH_DSN)

    def test_the_refusal_names_the_callers_sources(self):
        with self.assertRaises(SystemExit) as cm:
            md.require_dsn(None, "DATABASE_URL (the read-only role)")
        self.assertIn("DATABASE_URL (the read-only role)", str(cm.exception.code))


class MaintenanceDsnHasNoDefaultTierTests(unittest.TestCase):
    def test_nothing_set_resolves_to_none(self):
        with mock.patch.dict(os.environ, clean_env(), clear=True):
            self.assertIsNone(md.maintenance_dsn())

    def test_database_url_alone(self):
        with mock.patch.dict(os.environ, clean_env(DATABASE_URL=SCRATCH_DSN), clear=True):
            self.assertEqual(md.maintenance_dsn(), SCRATCH_DSN)

    def test_maintenance_wins_and_the_guard_is_unchanged(self):
        same = clean_env(DATABASE_URL=SCRATCH_DSN, MAINTENANCE_DATABASE_URL=SCRATCH_DSN)
        with mock.patch.dict(os.environ, same, clear=True):
            self.assertEqual(md.maintenance_dsn(), SCRATCH_DSN)
        split = clean_env(DATABASE_URL=SCRATCH_DSN, MAINTENANCE_DATABASE_URL=OTHER_DSN)
        with mock.patch.dict(os.environ, split, clear=True):
            with self.assertRaises(RuntimeError):
                md.maintenance_dsn()

    def test_the_default_parameter_is_gone(self):
        # Every script used to thread its hardcoded DSN through this argument.
        with self.assertRaises(TypeError):
            md.maintenance_dsn(SCRATCH_DSN)


class ScriptsRefuseWithoutADsnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.version_info < (3, 11):
            raise AssertionError(
                f"run these with Python >= 3.11, the scripts' own floor; this is "
                f"{sys.version.split()[0]}. A skip here would read as a pass."
            )

    def test_connecting_scripts_are_all_listed(self):
        found = set()
        for path in SCRIPTS.rglob("*.py"):
            rel = path.relative_to(SCRIPTS).as_posix()
            if rel.startswith("tests/") or rel in LIBRARIES:
                continue
            src = path.read_text()
            if DRIVER_CONNECT in src or THEME_LIB_CONNECT in src:
                found.add(rel)
        self.assertGreater(len(found), 20, "the discovery scan found almost nothing")
        self.assertEqual(
            found,
            set(CASES),
            "a script that connects was added or removed; update CASES so it is "
            "proven to refuse without a DSN",
        )

    def test_each_script_refuses_before_connecting(self):
        for rel, args in sorted(CASES.items()):
            with self.subTest(script=rel):
                proc = run_script(rel, args, clean_env())
                self.assertNotIn(
                    REACHED_CONNECT_MARKER, proc.stderr,
                    f"{rel} reached the driver with no DSN configured:\n{proc.stderr}",
                )
                self.assertNotEqual(proc.returncode, REACHED_CONNECT_EXIT)
                self.assertNotEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(REFUSAL, proc.stderr, proc.stderr[-2000:])

    def test_the_assessment_worker_dry_run_needs_only_the_read_half(self):
        proc = run_script("run_assessment_worker.py", ["--dry-run"], clean_env())
        self.assertIn("DATABASE_URL (the read-only role)", proc.stderr)
        proc = run_script(
            "run_assessment_worker.py", ["--dry-run"], clean_env(DATABASE_URL=SCRATCH_DSN)
        )
        self.assertNotIn(REFUSAL, proc.stderr)
        self.assertIn(f"{REACHED_CONNECT_MARKER}{SCRATCH_DSN!r}", proc.stderr)

    def test_the_assessment_worker_refuses_to_write_without_the_admin_half(self):
        proc = run_script("run_assessment_worker.py", [], clean_env(DATABASE_URL=SCRATCH_DSN))
        self.assertIn(REFUSAL, proc.stderr)
        self.assertIn("DATABASE_ADMIN_URL", proc.stderr)
        self.assertNotIn(REACHED_CONNECT_MARKER, proc.stderr)

    def test_a_configured_dsn_is_what_reaches_the_driver(self):
        # The environment variable, then the flag over it: removing the default
        # must not have removed either way of naming a database.
        proc = run_script("migrate_mixed_bbas.py", [], clean_env(DATABASE_URL=SCRATCH_DSN))
        self.assertEqual(proc.returncode, REACHED_CONNECT_EXIT, proc.stderr)
        self.assertIn(f"{REACHED_CONNECT_MARKER}{SCRATCH_DSN!r}", proc.stderr)

        proc = run_script(
            "migrate_mixed_bbas.py",
            ["--database-url", OTHER_DSN],
            clean_env(DATABASE_URL=SCRATCH_DSN),
        )
        self.assertEqual(proc.returncode, REACHED_CONNECT_EXIT, proc.stderr)
        self.assertIn(f"{REACHED_CONNECT_MARKER}{OTHER_DSN!r}", proc.stderr)

    def test_an_empty_flag_is_not_a_dsn(self):
        proc = run_script("migrate_mixed_bbas.py", ["--database-url", ""], clean_env())
        self.assertIn(REFUSAL, proc.stderr)
        self.assertNotIn(REACHED_CONNECT_MARKER, proc.stderr)


class ThemePipelineLabelStepTests(unittest.TestCase):
    """`theme_pipeline` hands its own database to the label child it spawns."""

    # Imports theme_pipeline behind the stubs, replaces subprocess.run, and
    # prints what the label child would have been given.
    PROBE = """
import json, subprocess, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import _offline_script_harness
_offline_script_harness.install_stubs()
import theme_pipeline
seen = {}
def fake_run(argv, **kwargs):
    seen["argv"] = argv
    env = kwargs.get("env") or {}
    seen["env"] = {k: env.get(k) for k in ("MAINTENANCE_DATABASE_URL", "DATABASE_URL")}
theme_pipeline.subprocess.run = fake_run
theme_pipeline.run_label_step(sys.argv[3])
print(json.dumps(seen))
"""

    @classmethod
    def setUpClass(cls):
        if sys.version_info < (3, 11):
            raise AssertionError(
                f"run these with Python >= 3.11; this is {sys.version.split()[0]}."
            )

    def test_the_label_child_runs_on_the_pipelines_database(self):
        # A different DSN in the environment must not win over the pipeline's.
        proc = subprocess.run(
            [sys.executable, "-c", self.PROBE, str(HARNESS.parent), str(SCRIPTS), OTHER_DSN],
            cwd=REPO,
            env=clean_env(DATABASE_URL=SCRATCH_DSN),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        seen = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(
            seen["env"],
            {"MAINTENANCE_DATABASE_URL": OTHER_DSN, "DATABASE_URL": OTHER_DSN},
        )
        self.assertTrue(seen["argv"][-2].endswith("label_themes_llm.py"), seen["argv"])
        self.assertNotIn(OTHER_DSN, seen["argv"], "the DSN must not be on the command line")


if __name__ == "__main__":
    unittest.main()
