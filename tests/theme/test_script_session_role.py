"""The DB arms run their scripts as the production maintenance login (backlog 9d02a5e0).

tests/db_roles.py explains the split: fixtures on the superuser, scripts on a
non-superuser, NOBYPASSRLS login in `epigraph_maintenance`. These tests pin that
the split is real in the database the arms use, so it cannot quietly decay back
into "everything runs as the superuser":

  * the script session is that login, not a superuser, and is admitted by the
    database's own `epigraph_bypass()`;
  * row security on `claims` is FORCED, so a session it applies to really is
    narrowed: an `epigraph_app` session stamped for one group does not read
    another group's private claim (and does read it once stamped for that
    group, so the narrowing is not an empty table);
  * the script session DOES read that claim. That is what makes the theme
    arms' cross-group tests (test_label_public_only.py and friends) mean
    something: the private row reaches the script, and only the script's own
    public-only SQL keeps its text out of a label.

Under EPIGRAPH_PYTEST_REQUIRE_DB=1 (CI) every one of these must hold; without
it, on a checkout with no maintenance login, the role tests skip.
"""
import uuid

import pytest

from tests import db_roles
from tests.theme.conftest import TEST_DSN

PRIVATE_TEXT = "script-session-role private claim of another group"


def _require_login():
    if db_roles.login_of(db_roles.script_dsn(TEST_DSN)) == db_roles.login_of(TEST_DSN):
        reason = (f"{db_roles.MAINTENANCE_DSN_ENV} logs in as the fixture user: the scripts "
                  "would run as it")
        if db_roles.REQUIRE_DB:
            pytest.fail(reason, pytrace=False)
        pytest.skip(reason)


def test_the_scripts_run_as_a_plain_maintenance_login(script_db):
    _require_login()
    with script_db.cursor() as cur:
        cur.execute(
            "SELECT r.rolsuper, r.rolbypassrls, public.epigraph_bypass() "
            "FROM pg_roles r WHERE r.rolname = session_user"
        )
        superuser, bypassrls, maintenance = cur.fetchone()
    script_db.rollback()
    assert not superuser, "the script session is a superuser: row security and grants are skipped"
    assert not bypassrls, "the script session has BYPASSRLS: the maintenance policies are skipped"
    assert maintenance, "epigraph_bypass() is false: the session is not a maintenance login"


def test_row_security_on_claims_is_forced(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'public.claims'::regclass"
        )
        assert cur.fetchone() == (True, True)
    db.rollback()


def _team(cur, agent_id):
    gid = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) "
        "VALUES (%s, 'script-role', 'did:test:team:' || %s, sha256(%s::bytea), 'team', %s)",
        (gid, gid, gid, agent_id),
    )
    return gid


def _app_reads(db, group, claim):
    """Whether an `epigraph_app` session stamped as a reader of `group` reads
    `claim`. Run on the fixture connection in a transaction that is rolled back,
    which undoes the session switch with it."""
    with db.cursor() as cur:
        cur.execute("SET SESSION AUTHORIZATION epigraph_app")
        cur.execute("SELECT set_config('epigraph.group_ids', %s, false)", (group,))
        cur.execute("SELECT count(*) FROM claims WHERE id = %s", (claim,))
        n = cur.fetchone()[0]
    db.rollback()
    return n == 1


def test_another_groups_private_claim_is_hidden_from_the_app_role_not_the_scripts(
    db, script_db, seed_agent
):
    with db.cursor() as cur:
        mine, theirs = _team(cur, seed_agent), _team(cur, seed_agent)
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, visibility, "
            "                    owner_group_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, 'group', %s) RETURNING id::text",
            (PRIVATE_TEXT, PRIVATE_TEXT, seed_agent, theirs),
        )
        claim = cur.fetchone()[0]
    db.commit()
    try:
        assert not _app_reads(db, mine, claim), (
            "an epigraph_app session stamped for another group read a group-private claim: "
            "row security is not in effect on this database"
        )
        assert _app_reads(db, theirs, claim), "calibration: the owning group's reader sees it"

        _require_login()
        with script_db.cursor() as cur:
            cur.execute("SELECT content FROM claims WHERE id = %s", (claim,))
            assert cur.fetchone() == (PRIVATE_TEXT,), (
                "the maintenance login did not read the private claim: a script would "
                "silently work on a subset"
            )
        script_db.rollback()
    finally:
        db.rollback()
        with db.cursor() as cur:
            cur.execute("DELETE FROM claims WHERE id = %s", (claim,))
            cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
            cur.execute("DELETE FROM groups WHERE id = ANY(%s::uuid[])", ([mine, theirs],))
        db.commit()
