#!/usr/bin/env python3
"""Create the maintenance login the DB-backed Python arms run their scripts as.

usage: TEST_ROLES_DATABASE_URL=<superuser DSN of a _test database> provision_test_roles.py

The Python maintenance and theme scripts connect on MAINTENANCE_DATABASE_URL in
production (scripts/maintenance_dsn.py): a NON-superuser, NOBYPASSRLS login that
is a member of `epigraph_maintenance`, which `epigraph_bypass()` admits by
`session_user` membership. The CI service's only credential is a superuser, which
skips row-level security AND every grant, so a script that needs a grant the
maintenance role lacks, or reads a table whose forced policy has no bypass arm,
would pass CI and fail in production (backlog 9d02a5e0). This creates that login,
`epigraph_test_maintenance`, so the arms run their scripts as it
(tests/db_roles.py); fixtures keep the superuser.

Roles are cluster-wide. The login is created on the fixture DSN's cluster, and
only when that DSN names a `_test` database, so this never runs against a real
deployment. Re-running it re-asserts the attributes and the membership, so a
login left over from an earlier run with other attributes cannot pass for it.
The password equals the name, like the CI service's own `epigraph:epigraph`: the
login exists only on a disposable test cluster.
"""
from __future__ import annotations

import os
import sys
import urllib.parse

import psycopg2
from psycopg2 import sql

LOGIN = "epigraph_test_maintenance"


def main() -> int:
    dsn = os.environ.get("TEST_ROLES_DATABASE_URL", "")
    db = urllib.parse.urlsplit(dsn).path.lstrip("/") if dsn else ""
    if not db.endswith("_test"):
        print(
            "provision_test_roles.py: set TEST_ROLES_DATABASE_URL to a database whose name "
            f"ends in _test (got {db!r}); refusing",
            file=sys.stderr,
        )
        return 64
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance'")
        if cur.fetchone() is None:
            print("provision_test_roles.py: no epigraph_maintenance role; migrate first",
                  file=sys.stderr)
            return 1
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (LOGIN,))
        verb = "ALTER" if cur.fetchone() else "CREATE"
        cur.execute(
            sql.SQL(
                "{} ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT "
                "PASSWORD {}"
            ).format(sql.SQL(verb), sql.Identifier(LOGIN), sql.Literal(LOGIN))
        )
        cur.execute(sql.SQL("GRANT epigraph_maintenance TO {}").format(sql.Identifier(LOGIN)))
        cur.execute(
            "SELECT r.rolsuper, r.rolbypassrls, "
            "       pg_has_role(r.oid, 'epigraph_maintenance', 'MEMBER') "
            "FROM pg_roles r WHERE r.rolname = %s",
            (LOGIN,),
        )
        superuser, bypassrls, member = cur.fetchone()
    conn.close()
    if superuser or bypassrls or not member:
        print(f"provision_test_roles.py: {LOGIN} is not a plain maintenance login "
              f"(super={superuser}, bypassrls={bypassrls}, member={member})", file=sys.stderr)
        return 1
    print(f"provision_test_roles.py: {LOGIN} ready ({verb}; a member of epigraph_maintenance)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
