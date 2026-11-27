"""DB arm: link_mass_function_evidence.py against a real migrated database.

The script backfills `mass_functions.evidence_id` on historical rows. These
tests run it as an operator would (a subprocess on the maintenance login,
tests/db_roles.py) over fixture rows seeded on the superuser connection, and
read the rows back.

Retracted rows (backlog d2c71a07): migration 184's rewrite guard (re-created
by 228) refuses any change to a retracted row's `evidence_id`, so a single
retracted, unlinked row the UPDATE matched aborted the whole `--execute` and
linked nothing. The backfill skips retracted rows and counts them.

Uses the CI-provisioned `_test` database (.github/workflows/ci.yml, job
`python`: DEDUP_TEST_DATABASE_URL, EPIGRAPH_PYTEST_REQUIRE_DB=1) and skips
without it, the tests/dedup shape. It seeds and removes its own rows. A run
links every eligible row in the database, not only the fixture's; each test
reverts what its runs linked through the undo file in teardown.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import uuid

import pytest

REQUIRE_DB = os.environ.get("EPIGRAPH_PYTEST_REQUIRE_DB") == "1"


def _unavailable(reason: str, **kw):
    if REQUIRE_DB:
        pytest.fail(f"EPIGRAPH_PYTEST_REQUIRE_DB=1 but {reason}", pytrace=False)
    pytest.skip(reason, **kw)


try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    _unavailable("psycopg2 is not installed", allow_module_level=True)

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "link_mass_function_evidence.py"
sys.path.insert(0, str(REPO))

from tests import db_roles  # noqa: E402

TEST_DSN = os.environ.get("DEDUP_TEST_DATABASE_URL", "")

# Same guard as tests/dedup: this fixture INSERTs and removes rows, and the
# script under test UPDATEs every eligible row, so it must never be pointed at
# a real corpus.
if not (TEST_DSN.rstrip("/").endswith("_test") or "/_sqlx_test" in TEST_DSN):
    _unavailable(
        "DEDUP_TEST_DATABASE_URL must name a database ending in `_test`",
        allow_module_level=True,
    )

MASSES = {"0": 0.6, "0,1": 0.4}


def _bba(cur, claim, frame, agent, slot_kind=None, slot_id=None):
    cur.execute(
        "INSERT INTO mass_functions "
        "(claim_id, frame_id, source_agent_id, perspective_id, slot_kind, slot_id, masses, "
        " conflict_k, combination_method, source_strength, evidence_type) "
        "VALUES (%s, %s, %s, NULL, %s, %s, %s::jsonb, 0.0, 'auto_wire', 1.0, 'document') "
        "RETURNING id::text AS id",
        (claim, frame, agent, slot_kind, slot_id, json.dumps(MASSES)),
    )
    return cur.fetchone()["id"]


def _evidence(cur, claim):
    cur.execute(
        "INSERT INTO evidence (content_hash, evidence_type, claim_id, raw_content) "
        "VALUES (%s, 'document', %s, 'link-db fixture') RETURNING id::text AS id",
        (psycopg2.Binary(os.urandom(32)), claim),
    )
    return cur.fetchone()["id"]


def _retract(cur, mf_id, agent, group):
    """Migration 184's definer, on the application role stamped as a writer of
    the row's owning group, the way production retracts a row."""
    cur.execute("SET SESSION AUTHORIZATION epigraph_app")
    try:
        cur.execute(
            "SELECT set_config('epigraph.group_ids', %s, false), "
            "       set_config('epigraph.writable_group_ids', %s, false), "
            "       set_config('epigraph.principal_id', %s, false)",
            (group, group, agent),
        )
        cur.execute(
            "SELECT public.epigraph_retract_mass_function(%s::uuid, %s, NULL, NULL) AS out",
            (mf_id, "link-db fixture: retracted before the backfill"),
        )
        out = cur.fetchone()["out"]
        assert out["status"] == "retracted", out
    finally:
        cur.execute(
            "SELECT set_config('epigraph.group_ids', '', false), "
            "       set_config('epigraph.writable_group_ids', '', false), "
            "       set_config('epigraph.principal_id', '', false)"
        )
        cur.execute("RESET SESSION AUTHORIZATION")


class World:
    def __init__(self, cur, tmp_path):
        self.cur = cur
        self.tmp_path = tmp_path
        self.undo_files = []
        self.ids = {}
        self.claims = []
        self.retracted = []

    def evidence_id(self, name):
        self.cur.execute(
            "SELECT evidence_id::text AS e FROM mass_functions WHERE id = %s", (self.ids[name],)
        )
        return self.cur.fetchone()["e"]

    def linked_total(self):
        self.cur.execute("SELECT count(*) AS n FROM mass_functions WHERE evidence_id IS NOT NULL")
        return self.cur.fetchone()["n"]

    def run(self, *args, check=True):
        """The script as an operator runs it, on the maintenance login
        (`--database-url` wins over any DSN in the environment)."""
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--database-url", db_roles.script_dsn(TEST_DSN), *args],
            capture_output=True, text=True, timeout=300, cwd=str(REPO),
        )
        if check:
            assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-3000:]
        return proc

    def execute(self):
        return self.run("--execute"), None


@pytest.fixture
def world(tmp_path):
    try:
        # MAINTENANCE-DSN-EXEMPT: a test fixture on the CI-provisioned disposable
        # `_test` database (guarded above), not an operator script; it never
        # reads a deployment's DSN.
        conn = psycopg2.connect(TEST_DSN)
    except Exception as e:  # noqa: BLE001
        _unavailable(f"test DB unavailable: {e}")
    conn.autocommit = True
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Migration 267's slot columns and 184's rewrite guard must be present, or
    # "an evidence-slot row is linked" and "a retracted row is skipped" would
    # hold vacuously.
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
        "                WHERE table_name = 'mass_functions' AND column_name = 'slot_kind') AS slot, "
        "       EXISTS (SELECT 1 FROM pg_trigger "
        "                WHERE tgrelid = 'public.mass_functions'::regclass "
        "                  AND tgname = 'mass_functions_retracted_rewrite_guard') AS guard"
    )
    facts = cur.fetchone()
    if not (facts["slot"] and facts["guard"]):
        _unavailable(f"the test database lacks migration 267 or 184: {dict(facts)}")

    agent = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO agents (id, public_key, agent_type) VALUES (%s, %s, 'system')",
        (agent, psycopg2.Binary(os.urandom(32))),
    )
    cur.execute(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) "
        "VALUES (%s, 'did:epigraph:personal:' || %s, ''::bytea, 'personal', %s) "
        "RETURNING id::text AS id",
        (f"link-db:{agent}", agent, agent),
    )
    group = cur.fetchone()["id"]
    cur.execute(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) "
        "VALUES (%s, %s, ''::bytea, 0, 'admin')",
        (group, agent),
    )
    cur.execute(
        "INSERT INTO frames (name, hypotheses) VALUES (%s, ARRAY['h0','h1']::text[]) "
        "RETURNING id::text AS id",
        (f"link-db-{uuid.uuid4()}",),
    )
    frame = cur.fetchone()["id"]

    w = World(cur, tmp_path)

    def claim():
        cid = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, "
            "                    visibility, owner_group_id) "
            "VALUES (%s, %s, %s, 0.5, %s, true, 'public', %s)",
            (cid, f"link-db fixture {cid}", psycopg2.Binary(os.urandom(32)), agent, group),
        )
        w.claims.append(cid)
        return cid

    # SINGLE: an ordinary (unslotted) BBA on a claim with exactly one
    # evidence row; the single-candidate pass links it.
    c_single = claim()
    w.ids["single_evidence"] = _evidence(cur, c_single)
    w.ids["single"] = _bba(cur, c_single, frame, agent)

    # RETRACTED: a retracted, unlinked BBA on a one-evidence claim. The
    # rewrite guard refuses to set its evidence_id.
    c_retracted = claim()
    _evidence(cur, c_retracted)
    w.ids["retracted"] = _bba(cur, c_retracted, frame, agent)
    _retract(cur, w.ids["retracted"], agent, group)
    w.retracted.append(w.ids["retracted"])

    w.frame = frame
    w.agent = agent
    w.group = group
    w.claim = claim

    yield w

    # Revert every run's links (other rows of the shared test database too),
    # newest first, then remove the fixture.
    for undo in reversed(w.undo_files):
        if undo.exists():
            w.run("--undo", str(undo), "--execute", check=False)
    cur.execute(
        "SELECT public.epigraph_purge_mass_functions(%s::uuid[], 'link-db teardown')",
        (w.retracted,),
    )
    cur.execute("DELETE FROM claims WHERE id = ANY(%s::uuid[])", (w.claims,))
    cur.execute("DELETE FROM frames WHERE id = %s", (frame,))
    conn.close()


def test_a_retracted_row_is_skipped_and_does_not_abort_the_backfill(world):
    proc, _ = world.execute()
    assert world.evidence_id("retracted") is None, "the retracted row is left as it was"
    assert world.evidence_id("single") == world.ids["single_evidence"], (
        "the rest of the backfill committed:\n" + proc.stdout
    )
