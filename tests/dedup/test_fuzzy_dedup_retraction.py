"""Integration test: fuzzy_dedup_claims.py must RETRACT duplicates, not just label them.

Backlog c40ab067. The script used to append the `deduped` label plus
`deduped_into`/`deduped_by`/`deduped_at` properties and stop there, leaving the
duplicate `is_current = true` with its embedding intact. `recall()` filters
`WHERE c.embedding IS NOT NULL AND c.is_current` on both its dense and lexical
legs (ClaimRepository::search_hybrid_scoped_since), so those duplicates kept
coming back next to their canonical partner and a single-origin figure read as
two-to-four-way corroboration.

These tests assert the RECALL CONSEQUENCE — "would the recall predicate still
return this row" — not merely that a column changed, and they drive the real
script end to end against a disposable database rather than reimplementing its
SQL.

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

psycopg2 = pytest.importorskip("psycopg2")

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "fuzzy_dedup_claims.py"

TEST_DSN = os.environ.get(
    "DEDUP_TEST_DATABASE_URL",
    "postgres://epigraph:epigraph@localhost/epigraph_gate_0921_test",
)

# Same guard epigraph-db's `db_is_disposable` applies: this fixture INSERTs and
# DELETEs claims, so it must never be pointed at a real corpus.
if not (TEST_DSN.rstrip("/").endswith("_test") or "/_sqlx_test" in TEST_DSN):
    pytest.skip(
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
        pytest.skip(f"test DB unavailable ({TEST_DSN}): {e}")
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

    with db.cursor() as cur:
        cur.execute("SELECT id FROM groups LIMIT 1")
        row = cur.fetchone()
        if row is None:
            pytest.skip("no rows in `groups` — run the tenancy migrations on the test DB")
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
                "(id, content, content_hash, agent_id, owner_group_id, visibility, embedding) "
                "VALUES (%s::uuid, %s, %s, %s::uuid, %s, 'public', %s::vector)",
                # `claims_content_hash_length` wants a 32-byte BLAKE3 digest.
                (cid, text, psycopg2.Binary(os.urandom(32)), agent_id, group_id, vec),
            )
            created_claims.append(cid)
            return cid

        canonical = mk("PEG brush spring constant is 21 pN/nm over a 40x40 nm tile")
        dup = mk("PEG brush spring constant is 21 pN/nm over a 40x40 nm tile")
        prior = mk("An unrelated prior canonical")
        already = mk("PEG brush spring constant is 21 pN/nm (third restatement)")
        # `already` is ALREADY superseded by `prior`: the script must not
        # re-point it. Nulling the embedding keeps chk_deprecated_no_embedding
        # satisfied.
        cur.execute(
            "UPDATE claims SET supersedes = %s::uuid, is_current = false, embedding = NULL "
            "WHERE id = %s::uuid",
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


def run_script(tmp_path, groups, execute: bool):
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
    proc = subprocess.run(
        argv, capture_output=True, text=True, cwd=str(REPO_ROOT / "scripts")
    )
    assert proc.returncode == 0, f"script failed:\nSTDOUT\n{proc.stdout}\nSTDERR\n{proc.stderr}"
    return proc.stdout


def recallable(db, claim_id: str) -> bool:
    with db.cursor() as cur:
        cur.execute(RECALL_PREDICATE, (claim_id,))
        return cur.fetchone()[0]


def test_executed_dedup_removes_the_duplicate_from_recall(db, seeded, tmp_path):
    """THE REGRESSION GUARD for c40ab067.

    After an --execute run the duplicate must no longer satisfy recall's
    `embedding IS NOT NULL AND is_current` predicate, while the canonical still
    does. Asserting the predicate rather than a single column is the point: the
    filed defect is "both rows keep coming back from recall", and a label-only
    soft-mark satisfies every column assertion that is not this one.
    """
    canonical, dup, _already, _prior = seeded

    assert recallable(db, canonical), "canonical must be recallable before the run"
    assert recallable(db, dup), "duplicate must be recallable before the run"

    run_script(tmp_path, [{"rep": canonical, "members": [canonical, dup]}], execute=True)

    assert recallable(db, canonical), "the canonical must survive the merge intact"
    assert not recallable(db, dup), (
        "the duplicate still satisfies recall's predicate — this is exactly the "
        "c40ab067 defect: a label-only soft-mark leaves it corroborating its own canonical"
    )

    with db.cursor() as cur:
        cur.execute(
            "SELECT supersedes::text, is_current, embedding IS NULL, "
            "'deduped' = ANY(labels), properties->>'deduped_into' "
            "FROM claims WHERE id = %s::uuid",
            (dup,),
        )
        supersedes, is_current, emb_null, labelled, deduped_into = cur.fetchone()

    # Lineage, not just visibility: `supersedes` is what makes the retraction
    # reversible and is what mark_duplicate_with_repair writes.
    assert supersedes == canonical
    assert is_current is False
    assert emb_null is True
    # The pre-existing soft-mark contract is preserved, not replaced — the GUI's
    # collapse view and every label-aware reader still work.
    assert labelled is True
    assert deduped_into == canonical


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
    and counts it.
    """
    canonical, _dup, already, prior = seeded

    stdout = run_script(
        tmp_path, [{"rep": canonical, "members": [canonical, already]}], execute=True
    )

    with db.cursor() as cur:
        cur.execute("SELECT supersedes::text FROM claims WHERE id = %s::uuid", (already,))
        assert cur.fetchone()[0] == prior, (
            "the script overwrote a pre-existing supersedes pointer — that destroys "
            "lineage the earlier retraction recorded"
        )
    assert "duplicates_skipped_already_superseded: 1" in stdout
