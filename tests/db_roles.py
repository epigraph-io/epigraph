"""The session the DB-backed Python arms run their SCRIPTS as (backlog 9d02a5e0).

Every database-backed script these suites drive (the theme pipeline,
`fuzzy_dedup_claims.py`, `migrate_provenance_bba.py`) connects on
`MAINTENANCE_DATABASE_URL` in production (`scripts/maintenance_dsn.py`): a login
that is NOT a superuser and NOT BYPASSRLS, and is a member of
`epigraph_maintenance`, which `epigraph_bypass()` admits by `session_user`.
The CI service's only credential is a superuser, which skips row-level
security and every grant. Arms that ran their scripts as it proved the scripts'
logic against the schema and nothing about the role: a script needing a grant
the maintenance role lacks, or reading a table whose forced policy has no
bypass arm, would pass.

So the arms split two roles:
  * FIXTURES (seed rows, cleanup) stay on the superuser DSN each suite already
    names (THEME_TEST_DATABASE_URL, DEDUP_TEST_DATABASE_URL);
  * the SCRIPT runs as the maintenance login named by
    EPIGRAPH_PYTEST_MAINTENANCE_DSN: a subprocess or `--database-url` gets
    `script_dsn()`, and an in-process call gets its own connection on it
    (`connect_script()`), as the script opens one in production. A connection,
    not a `SET SESSION AUTHORIZATION` on the fixture's: that switch is
    transactional, so a script that commits or rolls back would silently carry
    the rest of the test on the wrong role.

CI provisions the login (tests/ci/provision_test_roles.py) and sets
EPIGRAPH_PYTEST_REQUIRE_DB=1, under which a missing login DSN FAILS: it never
falls back to the superuser, or the arms would pass while proving nothing
about the role again. Unset (a developer's checkout without the login), the
script runs on the fixture DSN as before.

Running the scripts as `epigraph_app` instead would be wrong, not stronger: an
unstamped application session cannot see another group's private row at all,
so a test that the theme labeller keeps such a row's text out of a label would
pass vacuously. test_script_session_role.py pins both facts.
"""
from __future__ import annotations

import os
import urllib.parse

import pytest

MAINTENANCE_DSN_ENV = "EPIGRAPH_PYTEST_MAINTENANCE_DSN"
REQUIRE_DB = os.environ.get("EPIGRAPH_PYTEST_REQUIRE_DB") == "1"


def _parts(dsn: str):
    return urllib.parse.urlsplit(dsn)


def login_of(dsn: str) -> str | None:
    """The user a postgres:// DSN logs in as, or None."""
    try:
        return _parts(dsn).username
    except ValueError:
        return None


def _database_of(dsn: str) -> str:
    return _parts(dsn).path.lstrip("/")


def script_dsn(fixture_dsn: str) -> str:
    """The DSN a script under test connects on.

    EPIGRAPH_PYTEST_MAINTENANCE_DSN when set; it must name the fixture's
    database (a login on another database would read nothing and pass). Unset,
    the fixture DSN, unless EPIGRAPH_PYTEST_REQUIRE_DB=1, which fails the test.
    """
    dsn = os.environ.get(MAINTENANCE_DSN_ENV, "")
    if not dsn:
        if REQUIRE_DB:
            pytest.fail(
                f"EPIGRAPH_PYTEST_REQUIRE_DB=1 but {MAINTENANCE_DSN_ENV} is unset: the scripts "
                "would run as the fixture superuser, which skips row security and grants",
                pytrace=False,
            )
        return fixture_dsn
    if _database_of(dsn) != _database_of(fixture_dsn):
        pytest.fail(
            f"{MAINTENANCE_DSN_ENV} names database {_database_of(dsn)!r} but the fixtures "
            f"write {_database_of(fixture_dsn)!r}",
            pytrace=False,
        )
    return dsn


def connect_script(fixture_dsn: str):
    """A new connection on `script_dsn(fixture_dsn)`: what the script opens itself
    in production. It sees only what the fixture has COMMITTED, as a script would."""
    import psycopg2

    return psycopg2.connect(script_dsn(fixture_dsn))
