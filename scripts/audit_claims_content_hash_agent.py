#!/usr/bin/env python3
"""Audit the drifted `uq_claims_content_hash_agent` constraint on a live DB.

Migration 013 adds `UNIQUE (content_hash, agent_id)` to `claims`. On the
long-lived `epigraph` deployment `_sqlx_migrations` records version 13 as
applied *and successful*, yet the constraint is absent from `claims` — it was
created by the migration and later dropped out-of-band by integration-test
fixtures that ran `ALTER TABLE claims DROP CONSTRAINT IF EXISTS ...` against a
`DATABASE_URL` pointing at production. Those fixtures are now guarded
(`crates/epigraph-db/tests/claim_repo_helpers.rs`), but the drift they left
behind, and the duplicate rows that accumulated while the table was
unconstrained, still need an operator decision.

This script does NOT delete anything. Deduping `claims` cannot be done with
the `ctid > ctid` trick the test fixtures use: 15 of the 31 foreign keys
referencing `claims.id` are `ON DELETE CASCADE` (`evidence`,
`reasoning_traces`, `mass_functions`, `triples`, `entity_mentions`,
`match_candidates`, ...), so a blind delete silently destroys real evidence
and reasoning provenance; another 14 are NO ACTION/RESTRICT and would abort
the delete outright. Choosing a survivor per group is a judgement call about
which claim's downstream graph to keep. That belongs to a human.

What it does instead: report the numbers needed to make that call, for both
candidate constraint shapes, and optionally add the constraint when (and only
when) the table is already clean enough to accept it.

  Option A — full, as written in migration 013:
      UNIQUE (content_hash, agent_id)
    Blocked by every duplicate group, including ones that are just supersession
    history (one is_current row plus N superseded ancestors).

  Option B — partial, floated in
    docs/superpowers/specs/2026-06-03-plan-2.5-server-side-ingestion-idempotency.md:181:
      UNIQUE (content_hash, agent_id) WHERE is_current
    Permits supersession history, blocks only genuinely-live duplicates. Note
    this is a weaker invariant than 013 and diverges from what CI enforces.

Usage:
    python3 scripts/audit_claims_content_hash_agent.py
    DATABASE_URL=postgres://... python3 scripts/audit_claims_content_hash_agent.py
    python3 scripts/audit_claims_content_hash_agent.py --json

    # Only succeeds if zero blocking rows; never deletes:
    python3 scripts/audit_claims_content_hash_agent.py --apply-constraint full
    python3 scripts/audit_claims_content_hash_agent.py --apply-constraint partial

Read-only by default. `--apply-constraint` needs DDL rights on `claims`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import psycopg2

DEFAULT_DATABASE_URL = "postgres://epigraph_dev:epigraph_dev@127.0.0.1:5432/epigraph"

CONSTRAINT = "uq_claims_content_hash_agent"
# Migration 013's exact shape. Option B is an index, not a table constraint,
# because Postgres has no partial UNIQUE *constraint* — only a partial unique
# index.
PARTIAL_INDEX = "uq_claims_content_hash_agent_current"

Q_CONSTRAINT_PRESENT = """
SELECT EXISTS (
  SELECT 1 FROM pg_constraint
  WHERE conrelid = 'claims'::regclass AND conname = %s
)
"""

Q_INDEX_PRESENT = "SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = %s)"

Q_MIGRATION_013 = """
SELECT version, description, success
FROM _sqlx_migrations WHERE version = 13
"""

Q_TOTALS = """
SELECT count(*)                              AS total_claims,
       count(*) FILTER (WHERE is_current)    AS current_claims
FROM claims
"""

# Option A blockers: any (content_hash, agent_id) with >1 row at all.
Q_FULL_BLOCKERS = """
SELECT count(*)                              AS dup_groups,
       COALESCE(sum(n - 1), 0)::bigint       AS excess_rows
FROM (
  SELECT count(*) AS n FROM claims GROUP BY content_hash, agent_id HAVING count(*) > 1
) t
"""

# Option B blockers: groups with >1 *live* row.
Q_PARTIAL_BLOCKERS = """
SELECT count(*)                              AS dup_groups,
       COALESCE(sum(c - 1), 0)::bigint       AS excess_rows
FROM (
  SELECT count(*) FILTER (WHERE is_current) AS c
  FROM claims GROUP BY content_hash, agent_id
  HAVING count(*) FILTER (WHERE is_current) > 1
) t
"""

# How much of the duplication is host telemetry (intentionally unembedded,
# low-value) vs real claims — see CLAUDE.md "Telemetry exception".
Q_TELEMETRY_SPLIT = """
SELECT ('telemetry' = ANY(c.labels)) AS is_telemetry, count(*) AS rows_in_dup_groups
FROM claims c
JOIN (
  SELECT content_hash, agent_id FROM claims
  GROUP BY content_hash, agent_id HAVING count(*) > 1
) d ON c.content_hash = d.content_hash AND c.agent_id = d.agent_id
GROUP BY 1
"""

# Anything that would be dragged down with a deleted claim, or would block the
# delete. This is the reason dedup is not automated here.
Q_FK_FANOUT = """
SELECT conrelid::regclass::text AS referencing_table,
       conname,
       confdeltype
FROM pg_constraint
WHERE confrelid = 'claims'::regclass AND contype = 'f'
ORDER BY confdeltype, 1
"""

DELETE_ACTION = {
    "a": "NO ACTION (blocks delete)",
    "r": "RESTRICT (blocks delete)",
    "c": "CASCADE (deletes dependent rows!)",
    "n": "SET NULL",
    "d": "SET DEFAULT",
}


def scalar_row(cur, sql, params=None):
    cur.execute(sql, params or ())
    return cur.fetchone()


def collect(cur) -> dict:
    db = scalar_row(cur, "SELECT current_database()")[0]
    has_constraint = scalar_row(cur, Q_CONSTRAINT_PRESENT, (CONSTRAINT,))[0]
    has_partial = scalar_row(cur, Q_INDEX_PRESENT, (PARTIAL_INDEX,))[0]

    try:
        mig = scalar_row(cur, Q_MIGRATION_013)
    except psycopg2.Error:
        # Restricted roles may not be able to read _sqlx_migrations.
        cur.connection.rollback()
        mig = None

    total, current = scalar_row(cur, Q_TOTALS)
    full_groups, full_excess = scalar_row(cur, Q_FULL_BLOCKERS)
    part_groups, part_excess = scalar_row(cur, Q_PARTIAL_BLOCKERS)

    cur.execute(Q_TELEMETRY_SPLIT)
    telemetry = {bool(r[0]): r[1] for r in cur.fetchall()}

    cur.execute(Q_FK_FANOUT)
    fks = [
        {"table": t, "constraint": c, "on_delete": DELETE_ACTION.get(d, d)}
        for t, c, d in cur.fetchall()
    ]

    return {
        "database": db,
        "constraint_present": has_constraint,
        "partial_index_present": has_partial,
        "migration_013": (
            None
            if mig is None
            else {"version": mig[0], "description": mig[1], "success": mig[2]}
        ),
        "total_claims": total,
        "current_claims": current,
        "option_a_full": {"dup_groups": full_groups, "excess_rows": full_excess},
        "option_b_partial": {"dup_groups": part_groups, "excess_rows": part_excess},
        "dup_rows_telemetry": telemetry.get(True, 0),
        "dup_rows_non_telemetry": telemetry.get(False, 0),
        "cascade_fks": [f for f in fks if f["on_delete"].startswith("CASCADE")],
        "blocking_fks": [f for f in fks if "blocks delete" in f["on_delete"]],
    }


def render(r: dict) -> str:
    out = []
    add = out.append
    add(f"Database: {r['database']}")
    add(f"  claims rows: {r['total_claims']:,} ({r['current_claims']:,} is_current)")

    mig = r["migration_013"]
    if mig is None:
        add("  migration 013: <_sqlx_migrations not readable by this role>")
    else:
        add(f"  migration 013 recorded applied: success={mig['success']}")
    add(f"  {CONSTRAINT} present: {r['constraint_present']}")
    add(f"  {PARTIAL_INDEX} present: {r['partial_index_present']}")

    if mig is not None and mig["success"] and not r["constraint_present"]:
        add("")
        add("  *** DRIFT: 013 is recorded as applied but the constraint is gone.")
        add("      The deployed schema permits exactly the duplicate class 013")
        add("      was written to prevent, and CI tests a stricter schema than")
        add("      this database runs.")

    a, b = r["option_a_full"], r["option_b_partial"]
    add("")
    add("Blocking rows, by candidate constraint shape:")
    add("  Option A  UNIQUE (content_hash, agent_id)                  [migration 013]")
    add(f"            {a['dup_groups']:,} groups, {a['excess_rows']:,} excess rows")
    add("  Option B  UNIQUE (content_hash, agent_id) WHERE is_current [spec 2.5]")
    add(f"            {b['dup_groups']:,} groups, {b['excess_rows']:,} excess rows")
    add("")
    add(
        f"  Of the rows sitting in duplicate groups: "
        f"{r['dup_rows_non_telemetry']:,} non-telemetry, "
        f"{r['dup_rows_telemetry']:,} telemetry."
    )
    add(
        "  Option A - Option B is supersession history (one live row + superseded"
    )
    add("  ancestors), which is legitimate under 013's shape but still blocks it.")

    add("")
    add("Why this script will not dedup for you:")
    add(
        f"  {len(r['cascade_fks'])} of the FKs referencing claims.id are ON DELETE"
        " CASCADE."
    )
    for f in r["cascade_fks"][:8]:
        add(f"    - {f['table']}")
    if len(r["cascade_fks"]) > 8:
        add(f"    ... and {len(r['cascade_fks']) - 8} more")
    add(
        f"  Another {len(r['blocking_fks'])} are NO ACTION/RESTRICT and would abort"
        " the delete."
    )
    add("  Deleting a duplicate claim therefore destroys its evidence, reasoning")
    add("  traces and mass functions, or fails outright. Picking the survivor per")
    add("  group is an epistemic decision, not a mechanical one.")

    add("")
    if a["excess_rows"] == 0:
        add("Next step: table is clean for Option A — rerun with")
        add("  --apply-constraint full")
    elif b["excess_rows"] == 0:
        add("Next step: Option A still blocked, but Option B is satisfiable now:")
        add("  --apply-constraint partial")
        add("  (weaker than 013; confirm the divergence from CI is acceptable)")
    else:
        add("Next step: neither shape is satisfiable without reconciling duplicates.")
        add("  Reconcile first (owner decision), then rerun this script.")
    return "\n".join(out)


def apply_constraint(conn, shape: str, report: dict) -> int:
    """Add the constraint/index, but only onto an already-clean table."""
    if shape == "full":
        blockers = report["option_a_full"]["excess_rows"]
        if report["constraint_present"]:
            print(f"{CONSTRAINT} already present; nothing to do.")
            return 0
        # NOTE: a plain ADD CONSTRAINT builds the backing index under an
        # ACCESS EXCLUSIVE lock on `claims` — every reader and writer blocks
        # for the duration, and `claims` is ~457k rows on the live graph.
        # Schedule it, or build the index CONCURRENTLY first and attach it with
        # ADD CONSTRAINT ... USING INDEX. Kept as the plain form here because
        # it is what migration 013 declares, and matching 013 exactly is the
        # point of restoring it.
        ddl = (
            f"ALTER TABLE claims ADD CONSTRAINT {CONSTRAINT} "
            "UNIQUE (content_hash, agent_id)"
        )
    else:
        blockers = report["option_b_partial"]["excess_rows"]
        if report["partial_index_present"]:
            print(f"{PARTIAL_INDEX} already present; nothing to do.")
            return 0
        # CONCURRENTLY: this runs against a live graph; a plain CREATE INDEX
        # takes an ACCESS EXCLUSIVE lock on claims for the duration.
        ddl = (
            f"CREATE UNIQUE INDEX CONCURRENTLY {PARTIAL_INDEX} "
            "ON claims (content_hash, agent_id) WHERE is_current"
        )

    if blockers:
        print(
            f"REFUSING to apply: {blockers:,} rows still violate the '{shape}' shape.\n"
            "Reconcile duplicates first — this script does not delete claims.",
            file=sys.stderr,
        )
        return 1

    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block.
    conn.autocommit = True
    with conn.cursor() as cur:
        print(f"Applying: {ddl}")
        cur.execute(ddl)
    print("Applied.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument(
        "--apply-constraint",
        choices=("full", "partial"),
        help="add the constraint; refuses unless zero rows violate it",
    )
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    try:
        with conn.cursor() as cur:
            report = collect(cur)

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(render(report))

        if args.apply_constraint:
            print()
            return apply_constraint(conn, args.apply_constraint, report)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
