#!/usr/bin/env python3
"""Migrate legacy mixed-format BBAs where m({0}) > 0 AND m({1}) > 0.

A "mixed" BBA has both m({0}) > 0 (support for TRUE/CLAIM) AND m({1}) > 0
(support for FALSE) in the same mass function row.  These are numerical
artifacts from before build_binary_bba was introduced; they cause high
Dempster conflict K when combined with new pure-support BBAs, forcing the
monotonicity clamp introduced in PR #299.

Spec: backlog 5687fb5a.  Dry-run by default; pass --execute to commit.

Populations (for current claims only):
  trivial  : m({FALSE}) < 0.05   -> zero out m({FALSE}), renormalize remaining
  minor    : 0.05 <= m({FALSE}) < 0.10  -> log counts, skip
  genuine  : m({FALSE}) >= 0.10  -> MUST NOT touch (~511 rows, genuine signal)
  special  : evidence_type='derived_support' AND m({TRUE}) < 0.05
             -> internally contradictory, skip and log for manual review

Usage:
    DATABASE_URL=postgres://... python3 scripts/migrate_mixed_bbas.py
    DATABASE_URL=postgres://... python3 scripts/migrate_mixed_bbas.py --execute
"""

from __future__ import annotations

import argparse
import os
import uuid as uuid_mod

import psycopg2
from psycopg2.extras import RealDictCursor

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Commit the migration (default: dry-run only)",
    )
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Find all mixed-format rows joined to is_current claims.
        # masses JSONB keys: "0" = m_true, "1" = m_false, "~" = uncertain,
        # "0,1" = ignorance, "~0,1" = uncertain+ignorance (rare).
        cur.execute("""
            SELECT
                mf.id,
                mf.claim_id,
                mf.evidence_type,
                (mf.masses->>'0')::float AS m_true,
                (mf.masses->>'1')::float AS m_false
            FROM mass_functions mf
            JOIN claims c ON c.id = mf.claim_id
            WHERE
                c.is_current = true
                AND (mf.masses->>'0') IS NOT NULL
                AND (mf.masses->>'1') IS NOT NULL
                AND (mf.masses->>'0')::float > 0
                AND (mf.masses->>'1')::float > 0
            ORDER BY (mf.masses->>'1')::float DESC
        """)
        rows = cur.fetchall()

    total_mixed = len(rows)
    print(f"Found {total_mixed:,} mixed-format rows (is_current claims only)")

    trivial_ids: list = []
    minor_ids:   list = []
    genuine_ids: list = []
    special_ids: list = []
    special_examples: list[tuple] = []  # (claim_id, m_true, m_false, evtype)

    for row in rows:
        m_false = float(row["m_false"])
        m_true  = float(row["m_true"])
        evtype  = row["evidence_type"]
        mf_id   = row["id"]

        # Special case: derived_support with near-zero TRUE mass — these are
        # internally contradictory (source claims FALSE is true) and must be
        # reviewed manually before any automated fix.
        if evtype == "derived_support" and m_true < 0.05:
            special_ids.append(mf_id)
            if len(special_examples) < 5:
                special_examples.append((row["claim_id"], m_true, m_false, evtype))
            continue

        if m_false >= 0.10:
            genuine_ids.append(mf_id)
        elif m_false >= 0.05:
            minor_ids.append(mf_id)
        else:
            trivial_ids.append(mf_id)

    print()
    print(f"  trivial  (m_false < 0.05):              {len(trivial_ids):>7,} rows  -> WILL migrate")
    print(f"  minor    (0.05 <= m_false < 0.10):      {len(minor_ids):>7,} rows  -> skip (log only)")
    print(f"  genuine  (m_false >= 0.10):              {len(genuine_ids):>7,} rows  -> MUST NOT touch")
    print(f"  special  (derived_support, low m_true): {len(special_ids):>7,} rows  -> manual review")

    if special_examples:
        print()
        print("  Special rows (first 5 — manual review required):")
        print(f"    {'claim_id':36s}  {'m_true':>7}  {'m_false':>8}  evidence_type")
        for claim_id, mt, mf, evtype in special_examples:
            print(f"    {claim_id}  {mt:7.4f}  {mf:8.4f}  {evtype or 'NULL'}")

    if not args.execute:
        print()
        print("Dry-run complete. Pass --execute to commit the trivial migration.")
        conn.close()
        return

    if not trivial_ids:
        print()
        print("No trivial rows to migrate — nothing to do.")
        conn.close()
        return

    # Bulk UPDATE: zero out m({1}) and renormalize all remaining focal elements.
    #
    # For each trivial row we construct a new masses JSONB via jsonb_object_agg:
    #   - key '1' is set to 0.0
    #   - all other keys are divided by (1 - m_false), i.e. the renormalization
    #     factor.  Since m_false < 0.05 the denominator is always >= 0.95,
    #     so there is no division-by-zero risk.
    #
    # Using ANY(array) lets PostgreSQL execute this as a single statement
    # over all 254k trivial rows rather than one round-trip per row.
    print()
    print(f"Migrating {len(trivial_ids):,} trivial rows …")

    # psycopg2 accepts a Python list as a PostgreSQL array for ANY().
    # Convert uuid.UUID objects to strings to ensure array type is text/uuid.
    trivial_id_list = [str(i) if isinstance(i, uuid_mod.UUID) else i for i in trivial_ids]

    with conn.cursor() as cur:
        cur.execute("""
            UPDATE mass_functions mf
            SET masses = (
                SELECT jsonb_object_agg(
                    j.key,
                    CASE
                        WHEN j.key = '1' THEN 0.0
                        ELSE j.value::double precision
                             / (1.0 - (mf.masses->>'1')::double precision)
                    END
                )
                FROM jsonb_each_text(mf.masses) AS j(key, value)
            )
            WHERE mf.id = ANY(%s::uuid[])
        """, (trivial_id_list,))
        migrated = cur.rowcount

    conn.commit()
    print(f"Migrated {migrated:,} trivial mixed-BBA rows.")
    if migrated != len(trivial_ids):
        print(f"WARNING: expected {len(trivial_ids):,} rows updated, got {migrated:,}.")
    conn.close()


if __name__ == "__main__":
    main()
