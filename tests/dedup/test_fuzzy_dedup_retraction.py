"""Integration test: fuzzy_dedup_claims.py must RETRACT duplicates, through the act.

Backlog c40ab067: the script once only labelled duplicates, leaving them
`is_current = true` with their embedding, so `recall()` (which filters `WHERE
c.embedding IS NOT NULL AND c.is_current`) kept returning them next to their
canonical. Backlog 32c01f7d: it then retracted them with its own SQL, which
wrote no `same_as` identity edge, so the mark could not be un-marked. It now
marks through `POST /api/v1/claims/{dup}/dedup` and reads the database only.

These tests assert the RECALL CONSEQUENCE and the identity edge, and drive the
real script end to end against a disposable database. The executed-mark test
also needs an API serving that database (DEDUP_TEST_API_BASE) and a bearer
token for it with `claims:write` (plus `claims:admin` for a cross-agent
cluster) in DEDUP_TEST_TOKEN, and skips without them; the rest are
database-only. The request shape and the read-only contract are pinned without
a database in scripts/tests/test_fuzzy_dedup_claims.py.

Uses a `_test`-suffixed DSN and skips the whole module when it is unavailable,
same shape as tests/theme/conftest.py. It writes and deletes its own rows only.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import uuid

import pytest

# CI (.github/workflows/ci.yml, job `python`) provisions a migrated `_test`
# database and sets this, so a database-backed arm that cannot reach it FAILS
# there instead of skipping: a job whose arms all skip would pass while running
# none of them (backlog d5781a48). Unset, they skip as before.
REQUIRE_DB = os.environ.get("EPIGRAPH_PYTEST_REQUIRE_DB") == "1"


def _unavailable(reason: str, **kw):
    if REQUIRE_DB:
        pytest.fail(f"EPIGRAPH_PYTEST_REQUIRE_DB=1 but {reason}", pytrace=False)
    pytest.skip(reason, **kw)


try:
    import psycopg2
except ImportError:
    _unavailable("psycopg2 is not installed", allow_module_level=True)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "fuzzy_dedup_claims.py"

TEST_DSN = os.environ.get(
    "DEDUP_TEST_DATABASE_URL",
    "postgres://epigraph:epigraph@localhost/epigraph_gate_0921_test",
)

# Same guard epigraph-db's `db_is_disposable` applies: this fixture INSERTs and
# DELETEs claims, so it must never be pointed at a real corpus.
if not (TEST_DSN.rstrip("/").endswith("_test") or "/_sqlx_test" in TEST_DSN):
    _unavailable(
        f"refusing to run destructive dedup fixtures against {TEST_DSN!r}: "
        "the database name must end in `_test`",
        allow_module_level=True,
    )

# `recall()`'s visibility predicate, transcribed. A duplicate the script has
# retracted must NOT satisfy it; its canonical must.
RECALL_PREDICATE = "SELECT embedding IS NOT NULL AND is_current FROM claims WHERE id = %s"


@pytest.fixture
def db():
    try:
        conn = psycopg2.connect(TEST_DSN)
    except Exception as e:  # noqa: BLE001
        _unavailable(f"test DB unavailable ({TEST_DSN}): {e}")
    yield conn
    conn.close()


@pytest.fixture
def seeded(db):
    """Seed one agent and three claims with embeddings; clean up afterwards.

    Returns (canonical_id, dup_id, already_superseded_dup_id, agent_id).
    """
    created_claims: list[str] = []
    agent_id = str(uuid.uuid4())
    vec = "[" + ",".join(["0.01"] * 1536) + "]"
    vec_3072 = "[" + ",".join(["0.01"] * 3072) + "]"

    with db.cursor() as cur:
        cur.execute("SELECT id FROM groups LIMIT 1")
        row = cur.fetchone()
        if row is None:
            _unavailable("no rows in `groups` — run the tenancy migrations on the test DB")
        group_id = row[0]

        # `agents_public_key_length` requires a real 32-byte ed25519 key.
        cur.execute(
            "INSERT INTO agents (id, public_key, role, state) "
            "VALUES (%s::uuid, %s, 'researcher', 'active')",
            (agent_id, psycopg2.Binary(os.urandom(32))),
        )

        def mk(text: str) -> str:
            cid = str(uuid.uuid4())
            cur.execute(
                "INSERT INTO claims "
                "(id, content, content_hash, agent_id, owner_group_id, visibility, embedding, "
                " embedding_3072) "
                "VALUES (%s::uuid, %s, %s, %s::uuid, %s, 'public', %s::vector, %s::vector)",
                # `claims_content_hash_length` wants a 32-byte BLAKE3 digest.
                (cid, text, psycopg2.Binary(os.urandom(32)), agent_id, group_id, vec,
                 vec_3072),
            )
            created_claims.append(cid)
            return cid

        canonical = mk("PEG brush spring constant is 21 pN/nm over a 40x40 nm tile")
        dup = mk("PEG brush spring constant is 21 pN/nm over a 40x40 nm tile")
        prior = mk("An unrelated prior canonical")
        already = mk("PEG brush spring constant is 21 pN/nm (third restatement)")
        # `already` is ALREADY superseded by `prior`: the script must not
        # re-point it. Nulling both embeddings keeps chk_deprecated_no_embedding
        # (both columns since migration 144) satisfied.
        cur.execute(
            "UPDATE claims SET supersedes = %s::uuid, is_current = false, embedding = NULL, "
            "embedding_3072 = NULL WHERE id = %s::uuid",
            (prior, already),
        )
    db.commit()

    yield canonical, dup, already, prior

    with db.cursor() as cur:
        cur.execute(
            "UPDATE claims SET supersedes = NULL WHERE id = ANY(%s::uuid[])",
            (created_claims,),
        )
        cur.execute("DELETE FROM edges WHERE source_id = ANY(%s::uuid[]) "
                    "OR target_id = ANY(%s::uuid[])", (created_claims, created_claims))
        cur.execute("DELETE FROM claims WHERE id = ANY(%s::uuid[])", (created_claims,))
        cur.execute("DELETE FROM agents WHERE id = %s::uuid", (agent_id,))
    db.commit()


API_BASE = os.environ.get("DEDUP_TEST_API_BASE")
API_TOKEN = os.environ.get("DEDUP_TEST_TOKEN")


def run_script(tmp_path, groups, execute: bool, token: str | None = None, expect_rc: int = 0):
    snapshot = tmp_path / "semantic-dedup.json"
    snapshot.write_text(json.dumps({"groups": groups}))
    argv = [
        sys.executable,
        str(SCRIPT),
        "--input",
        str(snapshot),
        "--database-url",
        TEST_DSN,
    ]
    if execute:
        argv.append("--execute")
    env = {k: v for k, v in os.environ.items() if k not in ("EPIGRAPH_TOKEN", "EPIGRAPH_API_BASE")}
    if token is not None:
        env["EPIGRAPH_TOKEN"] = token
    if API_BASE:
        env["EPIGRAPH_API_BASE"] = API_BASE
    proc = subprocess.run(
        argv, capture_output=True, text=True, cwd=str(REPO_ROOT / "scripts"), env=env
    )
    assert proc.returncode == expect_rc, (
        f"script exited {proc.returncode}, wanted {expect_rc}:\n"
        f"STDOUT\n{proc.stdout}\nSTDERR\n{proc.stderr}"
    )
    return proc.stdout


def recallable(db, claim_id: str) -> bool:
    with db.cursor() as cur:
        cur.execute(RECALL_PREDICATE, (claim_id,))
        return cur.fetchone()[0]


@pytest.mark.skipif(
    not (API_BASE and API_TOKEN),
    reason="needs DEDUP_TEST_API_BASE (an API serving the test DB) and DEDUP_TEST_TOKEN",
)
def test_executed_dedup_removes_the_duplicate_from_recall(db, seeded, tmp_path):
    """THE REGRESSION GUARD for c40ab067 and 32c01f7d.

    After an --execute run the duplicate must no longer satisfy recall's
    `embedding IS NOT NULL AND is_current` predicate, while the canonical still
    does, AND it must carry the in-force `same_as` identity edge (with
    `properties.dedup`) that un-mark and the index view key on.
    """
    canonical, dup, _already, _prior = seeded

    assert recallable(db, canonical), "canonical must be recallable before the run"
    assert recallable(db, dup), "duplicate must be recallable before the run"

    run_script(
        tmp_path, [{"rep": canonical, "members": [canonical, dup]}], execute=True,
        token=API_TOKEN,
    )

    assert recallable(db, canonical), "the canonical must survive the merge intact"
    assert not recallable(db, dup), (
        "the duplicate still satisfies recall's predicate — this is exactly the "
        "c40ab067 defect: a soft-mark leaves it corroborating its own canonical"
    )

    with db.cursor() as cur:
        cur.execute(
            "SELECT supersedes::text, is_current, embedding IS NULL, embedding_3072 IS NULL "
            "FROM claims WHERE id = %s::uuid",
            (dup,),
        )
        supersedes, is_current, emb_null, emb_3072_null = cur.fetchone()
        cur.execute(
            "SELECT count(*) FROM edges WHERE source_id = %s::uuid AND target_id = %s::uuid "
            "AND relationship = 'same_as' AND valid_to IS NULL AND properties ? 'dedup'",
            (dup, canonical),
        )
        identity_edges = cur.fetchone()[0]

    assert supersedes == canonical
    assert is_current is False
    assert emb_null is True
    # Recall at centroid_dim=3072 reads `embedding_3072` with no is_current
    # filter, so the retraction must null it too (as mark_duplicate_act does).
    assert emb_3072_null is True
    # The dedup record: what makes the mark reversible (32c01f7d).
    assert identity_edges == 1


def test_execute_without_a_token_refuses_and_writes_nothing(db, seeded, tmp_path):
    """--execute with no bearer token refuses to start; the duplicate stays
    recallable and unmarked."""
    canonical, dup, _already, _prior = seeded

    run_script(
        tmp_path, [{"rep": canonical, "members": [canonical, dup]}], execute=True,
        expect_rc=2,
    )

    assert recallable(db, dup)
    with db.cursor() as cur:
        cur.execute("SELECT supersedes FROM claims WHERE id = %s::uuid", (dup,))
        assert cur.fetchone()[0] is None


def test_dry_run_leaves_the_duplicate_recallable(db, seeded, tmp_path):
    """Without --execute nothing commits. Guards the retraction against
    becoming an unconditional write that ignores the dry-run default."""
    canonical, dup, _already, _prior = seeded

    run_script(tmp_path, [{"rep": canonical, "members": [canonical, dup]}], execute=False)

    assert recallable(db, dup), "a dry run must not retract anything"
    with db.cursor() as cur:
        cur.execute("SELECT supersedes FROM claims WHERE id = %s::uuid", (dup,))
        assert cur.fetchone()[0] is None


def test_an_already_superseded_duplicate_keeps_its_lineage(db, seeded, tmp_path):
    """A duplicate that already points at another claim must be SKIPPED.

    Re-pointing it at this cluster's canonical would silently destroy the
    earlier lineage. `ClaimRepository::mark_duplicate_with_repair` errors on
    this case ("already superseded; refusing to overwrite"); the script skips
    and counts it, and never asks the endpoint (which refuses it too).
    Decided on the read-only path, so a dry run shows it.
    """
    canonical, _dup, already, prior = seeded

    stdout = run_script(
        tmp_path, [{"rep": canonical, "members": [canonical, already]}], execute=False
    )

    with db.cursor() as cur:
        cur.execute("SELECT supersedes::text FROM claims WHERE id = %s::uuid", (already,))
        assert cur.fetchone()[0] == prior, (
            "the script overwrote a pre-existing supersedes pointer — that destroys "
            "lineage the earlier retraction recorded"
        )
    assert "duplicates_skipped_already_superseded: 1" in stdout
