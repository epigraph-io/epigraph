"""DB arm: migrate_provenance_bba.py's rollback completes under migration 194.

SPEC section 11 phase 1, K4b. Migration 194 (H10) refuses any delete of a
RETRACTED mass function outside its audited purge definer, with SR09, so a
rollback whose DELETE named a retracted manifest row would abort whole. The
rollback must skip retracted ids, report them, and delete the rest.

scripts/tests/test_migrate_provenance_bba.py pins the SQL text through a
recording cursor. This file runs `rollback()` against a REAL migrated database
holding a REAL retracted row (made by migration 184's definer on a stamped
`epigraph_app` session, the way production makes one). The retracted row
carries the same `combination_method` and `locality_tag` as the live rows, so
`retracted_at IS NULL` is the only thing that keeps it.

Uses the CI-provisioned `_test` database (.github/workflows/ci.yml, job
`python`: DEDUP_TEST_DATABASE_URL, EPIGRAPH_PYTEST_REQUIRE_DB=1) and skips
without it, the tests/dedup shape. It writes and removes its own rows only.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import pathlib
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
sys.path.insert(0, str(REPO / "scripts"))
import migrate_provenance_bba as mpb  # noqa: E402

TEST_DSN = os.environ.get("DEDUP_TEST_DATABASE_URL", "")

# Same guard as tests/dedup: this fixture INSERTs and removes rows, so it must
# never be pointed at a real corpus.
if not (TEST_DSN.rstrip("/").endswith("_test") or "/_sqlx_test" in TEST_DSN):
    _unavailable(
        "DEDUP_TEST_DATABASE_URL must name a database ending in `_test`",
        allow_module_level=True,
    )

MASSES = {"0": 0.6, "0,1": 0.4}


def _seed_bba(cur, claim: str, frame: str, agent: str) -> str:
    """One seed BBA exactly as migrate_provenance_bba.migrate() writes it."""
    cur.execute(
        "INSERT INTO mass_functions "
        "(id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, "
        " combination_method, source_strength, evidence_type, locality_tag) "
        "VALUES (gen_random_uuid(), %s, %s, %s, NULL, %s::jsonb, 0.0, %s, 1.0, "
        "        'textbook_assertion', %s) RETURNING id::text AS id",
        (claim, frame, agent, json.dumps(MASSES), mpb.SEED_METHOD, mpb.LOCALITY_TAG),
    )
    return cur.fetchone()["id"]


def _retract_through_definer(cur, mf_id: str, agent: str, group: str) -> None:
    """Migration 184's definer, on the application role, stamped as a writer
    of the row's owning group (its owner arm)."""
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
            (mf_id, "K4b DB arm: retracted before the rollback"),
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


def _exists(cur, mf_id: str) -> bool:
    cur.execute("SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = %s) AS e", (mf_id,))
    return cur.fetchone()["e"]


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

    # The database must carry migration 194, or "the retracted row survives"
    # would hold vacuously (nothing would refuse its delete).
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 194 AND success) AS m, "
        "       to_regprocedure('public.epigraph_purge_mass_functions(uuid[], text)') "
        "         IS NOT NULL AS purge, "
        "       EXISTS (SELECT 1 FROM pg_trigger "
        "                WHERE tgrelid = 'public.mass_functions'::regclass "
        "                  AND tgname = 'mass_functions_retracted_delete_guard') AS guard"
    )
    facts = cur.fetchone()
    if not (facts["m"] and facts["purge"] and facts["guard"]):
        _unavailable(f"the test database does not carry migration 194: {dict(facts)}")

    agent = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO agents (id, public_key, agent_type) VALUES (%s, %s, 'system')",
        (agent, psycopg2.Binary(os.urandom(32))),
    )
    cur.execute(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) "
        "VALUES (%s, 'did:epigraph:personal:' || %s, ''::bytea, 'personal', %s) "
        "RETURNING id::text AS id",
        (f"k4b-db:{agent}", agent, agent),
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
        (f"k4b-db-{uuid.uuid4()}",),
    )
    frame = cur.fetchone()["id"]
    claims = []
    for _ in range(3):
        cid = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, "
            "                    visibility, owner_group_id) "
            "VALUES (%s, %s, %s, 0.5, %s, true, 'public', %s)",
            (cid, f"k4b db arm {cid}", psycopg2.Binary(os.urandom(32)), agent, group),
        )
        claims.append(cid)
    rows = [_seed_bba(cur, c, frame, agent) for c in claims]
    cur.execute(
        "SELECT count(*) AS n FROM mass_functions "
        "WHERE id = ANY(%s::uuid[]) AND owner_group_id = %s::uuid",
        (rows, group),
    )
    assert cur.fetchone()["n"] == 3, "fixture: the seed rows belong to the writer's group"
    live, retracted = rows[:2], rows[2]
    _retract_through_definer(cur, retracted, agent, group)

    manifest = tmp_path / "run.jsonl"
    with open(manifest, "w", encoding="utf-8") as fh:
        for c, r in zip(claims, rows):
            fh.write(json.dumps({"mass_function_id": r, "claim_id": c, "frame_id": frame,
                                 "created_assignment": False}) + "\n")

    yield {"cur": cur, "live": live, "retracted": retracted, "manifest": str(manifest)}

    # Teardown: the retracted row goes only through the purge definer (194),
    # then the claims and the frame. The agent, its group and the audit rows
    # stay: security_events is append-only, and they reference the agent.
    cur.execute(
        "SELECT public.epigraph_purge_mass_functions(%s::uuid[], 'K4b DB arm teardown')",
        (rows,),
    )
    cur.execute("DELETE FROM claims WHERE id = ANY(%s::uuid[])", (claims,))
    cur.execute("DELETE FROM frames WHERE id = %s", (frame,))
    conn.close()


def _rollback(cur, manifest: str, execute: bool) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        mpb.rollback(cur, argparse.Namespace(execute=execute), manifest)
    return out.getvalue()


def test_the_dry_run_counts_the_live_rows_names_the_retracted_one_and_deletes_nothing(world):
    cur = world["cur"]
    out = _rollback(cur, world["manifest"], execute=False)
    assert "would delete 2 BBAs" in out, out
    assert "would skip 1 retracted BBAs" in out, out
    assert world["retracted"] in out, out
    for r in world["live"] + [world["retracted"]]:
        assert _exists(cur, r), f"a dry run deletes nothing: {r}"


def test_the_rollback_completes_deletes_the_live_rows_and_keeps_the_retracted_one(world):
    cur = world["cur"]
    out = _rollback(cur, world["manifest"], execute=True)
    assert "deleted 2 BBAs" in out, out
    assert "skipped 1 retracted BBAs" in out, out
    assert world["retracted"] in out, out
    assert "already absent" not in out, out
    for r in world["live"]:
        assert not _exists(cur, r), f"the live seed row is rolled back: {r}"
    assert _exists(cur, world["retracted"]), "the retracted row is kept for audit"
    cur.execute(
        "SELECT retracted_at IS NOT NULL AS r FROM mass_functions WHERE id = %s",
        (world["retracted"],),
    )
    assert cur.fetchone()["r"], "and is still retracted"
