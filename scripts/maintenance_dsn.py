#!/usr/bin/env python3
"""The Python half of PR-15's maintenance-DSN rule, in one place.

Every operator script in `scripts/` that enumerates or UPDATEs the claim corpus
must connect on `MAINTENANCE_DATABASE_URL` when one is set: those statements run
corpus-wide, and once RLS is active (PR-17) an ordinary application connection
makes every one of them match a subset — the SELECTs see less, the UPDATEs touch
nothing, and the script exits 0.

This module exists rather than the two-line expression it replaces because the
precedence swap needs a GUARD, and nineteen copies of a guard is nineteen places
for it to drift. It deliberately imports nothing outside the standard library:
`theme_lib` pulls in numpy and psycopg2, and most of the scripts that need this
rule need neither, so routing them through `theme_lib` would have added a hard
dependency to seventeen files as a side effect of a DSN change.

`scripts/` is on `sys.path` when a script in it is run directly (the mode every
one of these is written for), so `from maintenance_dsn import maintenance_dsn`
resolves the same way `import theme_lib` already does.
"""
import os
import urllib.parse


def effective_database(dsn):
    """The database a libpq DSN actually connects to, or None if unknowable.

    The written path if there is one, else the username: libpq — and sqlx —
    default the database to the role name, so two pathless DSNs differing only
    in role reach two DIFFERENT databases while comparing equal on their path.
    Mirrors `epigraph_db::resolve_maintenance_url`'s `db_of` exactly.

    Returns None for a key=value DSN or anything else unparseable, so an
    unrecognised spelling degrades to "no opinion" rather than to a spurious
    refusal that would brick a working configuration.
    """
    if not dsn:
        return None
    try:
        parts = urllib.parse.urlsplit(dsn)
    except ValueError:
        return None
    if parts.scheme not in ("postgres", "postgresql"):
        return None
    try:
        username = parts.username
    except ValueError:
        username = None
    return parts.path.lstrip("/") or username or None


def require_same_database(dsn_a, name_a, dsn_b, name_b):
    """Refuse if two DSNs name different effective databases.

    Extracted so the split-role scripts — the ones whose second connection is
    not `DATABASE_URL` — get the identical rule rather than an approximation of
    it. Silent on any pair where either database cannot be determined.

    Raises:
        RuntimeError: when both are known and they differ.
    """
    db_a = effective_database(dsn_a)
    db_b = effective_database(dsn_b)
    if db_a and db_b and db_a != db_b:
        raise RuntimeError(
            f"{name_a} names database {db_a!r} but {name_b} names {db_b!r}. A "
            "maintenance connection to a different database does not error — it reads "
            "zero rows and writes nowhere. Refusing. Point both at the same database "
            "and vary only the role."
        )


def maintenance_dsn(default=None):
    """Resolve the DSN a corpus-wide script should connect on.

    `MAINTENANCE_DATABASE_URL` wins, then `DATABASE_URL`, then `default`.

    THE DATABASE-NAME GUARD IS THE REASON THIS IS A FUNCTION. Giving
    `MAINTENANCE_DATABASE_URL` precedence is a footgun on its own: an operator
    pointing `DATABASE_URL` at a scratch database while a sibling job has
    exported `MAINTENANCE_DATABASE_URL` would have every statement in this
    script family silently redirected, and several of these scripts write. A
    maintenance connection to the wrong database does not error — it reads zero
    rows and writes nowhere. So when both variables are set and they name
    different effective databases, this raises. That is the same rule, for the
    same reason, as `epigraph_db::resolve_maintenance_url`.

    Host and port are NOT compared. The Rust side warns on them; these are
    one-shots with no shared logging contract, and refusing on host equality
    would break every deployment where `localhost`, `127.0.0.1` and a container
    DNS name denote the same server. The residual — a same-named database on a
    different cluster — is documented rather than caught here.

    It deliberately does NOT assert privilege. The Rust constructor can refuse
    on `epigraph_bypass()` and row-security state because it is a long-running
    process with a logger; a Python-side reimplementation of that rule would
    drift from it. The refusal that matters is at the API and CLI boundary.

    Raises:
        RuntimeError: when both variables are set and name different databases.
    """
    maintenance = os.environ.get("MAINTENANCE_DATABASE_URL")
    application = os.environ.get("DATABASE_URL")
    if not maintenance:
        return application if application else default

    require_same_database(
        maintenance, "MAINTENANCE_DATABASE_URL", application, "DATABASE_URL"
    )
    return maintenance
