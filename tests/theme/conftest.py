"""Shared pytest fixtures for theme-pipeline integration tests.

Uses epigraph_db_repo_test (per repo CLAUDE.md). Skips the whole module if the
DB or required tables are missing, so unit tests still run on a bare checkout.
"""
import os
import uuid

import psycopg2
import pytest

from tests import db_roles

TEST_DSN = os.environ.get(
    "THEME_TEST_DATABASE_URL",
    "postgres://epigraph:epigraph@localhost/epigraph_db_repo_test",
)
REQUIRED = ["claims", "claim_themes", "claim_clusters", "cluster_centroids", "cluster_labels"]

# CI (.github/workflows/ci.yml, job `python`) provisions a migrated test database
# and sets this, so a DB-backed arm that cannot reach it FAILS there instead of
# skipping (a job whose DB arms all skip would pass while running none of them).
# Unset, they skip as before.
REQUIRE_DB = os.environ.get("EPIGRAPH_PYTEST_REQUIRE_DB") == "1"


def _unavailable(reason):
    if REQUIRE_DB:
        pytest.fail(f"EPIGRAPH_PYTEST_REQUIRE_DB=1 but {reason}", pytrace=False)
    pytest.skip(reason)


@pytest.fixture
def db():
    try:
        conn = psycopg2.connect(TEST_DSN)
    except Exception as e:  # noqa: BLE001
        _unavailable(f"test DB unavailable ({TEST_DSN}): {e}")
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name = ANY(%s)",
            (REQUIRED,),
        )
        if cur.fetchone()[0] < len(REQUIRED):
            conn.close()
            _unavailable("required tables missing — run `cargo sqlx migrate run` on the test DB")
    # Clean slate for the clustering tables. A bounded lock wait: the script
    # runs on its own connection (script_db), and a lock it still holds must
    # fail the test, not hang the job.
    with conn.cursor() as cur:
        cur.execute("SET lock_timeout = '60s'")
        cur.execute("UPDATE claims SET theme_id = NULL WHERE theme_id IS NOT NULL")
        cur.execute("DELETE FROM claim_clusters")
        cur.execute("DELETE FROM cluster_centroids")
        cur.execute("DELETE FROM cluster_labels")
        cur.execute("DELETE FROM claim_themes")
    conn.commit()
    yield conn
    conn.rollback()
    conn.close()


def script_dsn():
    """The DSN a theme script under test connects on: the maintenance login in
    CI, never the fixture superuser there (tests/db_roles.py)."""
    return db_roles.script_dsn(TEST_DSN)


@pytest.fixture
def script_db(db):
    """The theme script's OWN connection, as the maintenance login (CI) it runs
    as in production. Fixture rows must be committed for it to see them.
    Depends on `db` so it is opened after and closed before the fixture's."""
    conn = db_roles.connect_script(TEST_DSN)
    yield conn
    conn.rollback()
    conn.close()


def make_embedding(seed, dim=1536):
    """Deterministic unit-ish 1536-d vector clustered around `seed`."""
    import numpy as np
    rng = np.random.RandomState(seed)
    v = rng.normal(0, 0.01, dim).astype("float32")
    v[seed % dim] += 1.0  # dominant axis = cluster identity
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


@pytest.fixture
def seed_agent(db):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO agents (public_key, display_name, agent_type) "
            "VALUES (sha256(gen_random_uuid()::text::bytea), 'theme-test', 'system') RETURNING id"
        )
        agent_id = cur.fetchone()[0]
    db.commit()
    return agent_id
