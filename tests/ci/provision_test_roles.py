#!/usr/bin/env python3
"""Create the maintenance login the DB-backed Python arms run their scripts as.

usage: TEST_ROLES_DATABASE_URL=<superuser DSN of a _test database> \
       provision_test_roles.py --env-file <file>

The Python maintenance and theme scripts connect on MAINTENANCE_DATABASE_URL in
production (scripts/maintenance_dsn.py): a NON-superuser, NOBYPASSRLS login that
is a member of `epigraph_maintenance`, which `epigraph_bypass()` admits by
`session_user` membership. The CI service's only credential is a superuser, which
skips row-level security AND every grant, so a script that needs a grant the
maintenance role lacks, or reads a table whose forced policy has no bypass arm,
would pass CI and fail in production (backlog 9d02a5e0). This creates that login,
`epigraph_test_maintenance`, so the arms run their scripts as it
(tests/db_roles.py); fixtures keep the superuser.

Roles are cluster-wide, and a member of `epigraph_maintenance` bypasses row
security on EVERY database of the cluster that has the EpiGraph roles. So the
`_test` database-name check alone does not keep this away from real data, and
the script also refuses unless it runs in GitHub Actions or the caller opts in
explicitly (EPIGRAPH_PROVISION_TEST_ROLES=1, for a disposable local cluster).
Within that:
  * the password is random per run (never a value written in this public repo),
    masked in the Actions log, and expires (VALID UNTIL) a few hours later;
  * the DSN is appended to --env-file as EPIGRAPH_PYTEST_MAINTENANCE_DSN=<dsn>
    (CI passes $GITHUB_ENV, so later steps see it; it is never printed);
  * a role of that name that this script did not create (no marker comment) is
    refused, not re-passworded;
  * re-running re-asserts the attributes and the membership, so a login left
    over from an earlier run with other attributes cannot pass for it.
"""
from __future__ import annotations

import argparse
import datetime
import os
import secrets
import sys
import urllib.parse

LOGIN = "epigraph_test_maintenance"
MARKER = "epigraph CI test maintenance login (tests/ci/provision_test_roles.py)"
DSN_ENV = "EPIGRAPH_PYTEST_MAINTENANCE_DSN"
OPT_IN_ENV = "EPIGRAPH_PROVISION_TEST_ROLES"
LIFETIME = datetime.timedelta(hours=6)


def refusal(environ, fixture_dsn: str) -> str | None:
    """Why this run must not touch the cluster, or None when it may."""
    if environ.get("GITHUB_ACTIONS") != "true" and environ.get(OPT_IN_ENV) != "1":
        return (
            "not in GitHub Actions and no explicit opt-in: this creates a cluster-wide role "
            "that bypasses row security on every EpiGraph database of the cluster; set "
            f"{OPT_IN_ENV}=1 only for a disposable test cluster"
        )
    db = urllib.parse.urlsplit(fixture_dsn).path.lstrip("/") if fixture_dsn else ""
    if not db.endswith("_test"):
        return (
            "set TEST_ROLES_DATABASE_URL to a database whose name ends in _test "
            f"(got {db!r})"
        )
    return None


def login_dsn(fixture_dsn: str, password: str) -> str:
    """The fixture DSN's host, port and database, logged in as LOGIN."""
    parts = urllib.parse.urlsplit(fixture_dsn)
    host = parts.hostname or "localhost"
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{LOGIN}:{urllib.parse.quote(password, safe='')}@{host}"
    if parts.port:
        netloc += f":{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--env-file", required=True,
                    help=f"file to append {DSN_ENV}=<dsn> to (CI: $GITHUB_ENV)")
    args = ap.parse_args(argv)

    dsn = os.environ.get("TEST_ROLES_DATABASE_URL", "")
    why = refusal(os.environ, dsn)
    if why:
        print(f"provision_test_roles.py: {why}; refusing", file=sys.stderr)
        return 64

    import psycopg2
    from psycopg2 import sql

    password = secrets.token_urlsafe(24)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{password}", flush=True)
    until = (datetime.datetime.now(datetime.timezone.utc) + LIFETIME).isoformat()

    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance'")
        if cur.fetchone() is None:
            print("provision_test_roles.py: no epigraph_maintenance role; migrate first",
                  file=sys.stderr)
            return 1
        cur.execute(
            "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname = %s",
            (LOGIN,),
        )
        row = cur.fetchone()
        if row is not None and row[0] != MARKER:
            print(
                f"provision_test_roles.py: a role {LOGIN} exists that this script did not "
                "create (no marker comment); refusing to change its password or grants",
                file=sys.stderr,
            )
            return 1
        verb = "ALTER" if row is not None else "CREATE"
        cur.execute(
            sql.SQL(
                "{} ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT "
                "PASSWORD {} VALID UNTIL {}"
            ).format(sql.SQL(verb), sql.Identifier(LOGIN), sql.Literal(password),
                     sql.Literal(until))
        )
        cur.execute(sql.SQL("COMMENT ON ROLE {} IS {}").format(sql.Identifier(LOGIN),
                                                             sql.Literal(MARKER)))
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
    fd = os.open(args.env_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as fh:
        fh.write(f"{DSN_ENV}={login_dsn(dsn, password)}\n")
    print(f"provision_test_roles.py: {LOGIN} ready ({verb}; a member of "
          f"epigraph_maintenance; valid until {until}); {DSN_ENV} appended to --env-file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
