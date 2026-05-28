#!/usr/bin/env python3
"""Backfill mass_functions.locality_tag for historical BBAs.

Phase 1b of issue #197. Run AFTER migration 045 is applied via Phase 1a deploy.

Populates `mass_functions.locality_tag` for the ~279 894 BBAs written before the
column existed, using the same intra-source-evidence heuristic that
`backfill_intra_source_evidence_discount.py` uses to decide which claims to
discount. Unlike that script, this one does NOT mutate numeric reliability;
it only writes the typing tag. Once Phase 2 lands, the combine path reads
the tag and computes effective source_strength dynamically.

Tags emitted:
  * `intra`   — claim has ≥1 evidence row whose `properties->>'doi'` matches
                the DOI of the paper asserting the claim.
  * `cross`   — claim has evidence rows, but none of them are intra-source.
  * `unknown` — claim has no evidence rows (or whatever the default was);
                left as-is, the column's default.

Heuristic limitation (same as the discount script): we operate per-CLAIM, not
per-BBA. A claim with both intra and cross evidence will get `intra` for ALL
its BBAs, even the ones derived from cross-source evidence. The long-term fix
is per-BBA provenance (`mass_functions.evidence_id` — Phase 3 in the plan).

Idempotency: every UPDATE has a `WHERE locality_tag = 'unknown'` guard, so
already-tagged rows are skipped. A re-run finds zero candidates. The forward
write path (Phase 1a) also emits tags directly, so newly-written BBAs are
naturally excluded.

Usage:
    # Dry-run (default) — preview per-bucket counts, no writes:
    python3 scripts/backfill_locality_tag.py

    # Commit:
    python3 scripts/backfill_locality_tag.py --execute

The script wraps all three UPDATEs in a single transaction. If any one
fails, the whole transaction rolls back and the script exits 1.

Validation: at startup we check `information_schema.columns` for
`mass_functions.locality_tag`. If missing, exit 2 with a clear error
("migration 045 not applied — deploy Phase 1a first.") rather than letting
Postgres surface a less-helpful "column does not exist".
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg2


DEFAULT_DATABASE_URL = "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph"

# Predicate fragments. The "intra" predicate matches BBAs whose claim has at
# least one evidence row whose DOI matches the paper asserting the claim. The
# "any-evidence" predicate matches BBAs whose claim has any evidence row.
INTRA_EXISTS_SQL = """
EXISTS (
    SELECT 1
      FROM evidence e
      JOIN edges ed
        ON ed.target_id = e.claim_id
       AND ed.relationship = 'asserts'
       AND ed.source_type = 'paper'
      JOIN papers p
        ON p.id = ed.source_id
       AND p.doi = e.properties->>'doi'
     WHERE e.claim_id = mf.claim_id
       AND e.properties ? 'doi'
)
"""

ANY_EVIDENCE_EXISTS_SQL = """
EXISTS (
    SELECT 1
      FROM evidence e
     WHERE e.claim_id = mf.claim_id
)
"""

UPDATE_INTRA_SQL = f"""
UPDATE mass_functions mf
   SET locality_tag = 'intra'
 WHERE mf.locality_tag = 'unknown'
   AND {INTRA_EXISTS_SQL}
"""

UPDATE_CROSS_SQL = f"""
UPDATE mass_functions mf
   SET locality_tag = 'cross'
 WHERE mf.locality_tag = 'unknown'
   AND {ANY_EVIDENCE_EXISTS_SQL}
"""

# Dry-run delta queries. "delta_intra" mirrors UPDATE_INTRA_SQL's WHERE; the
# cross delta is computed assuming the intra UPDATE has already run, i.e.
# rows still at 'unknown' (so NOT intra-eligible) AND any-evidence. This
# matches the sequential UPDATE semantics.
DELTA_INTRA_SQL = f"""
SELECT COUNT(*) FROM mass_functions mf
 WHERE mf.locality_tag = 'unknown'
   AND {INTRA_EXISTS_SQL}
"""

DELTA_CROSS_SQL = f"""
SELECT COUNT(*) FROM mass_functions mf
 WHERE mf.locality_tag = 'unknown'
   AND NOT {INTRA_EXISTS_SQL}
   AND {ANY_EVIDENCE_EXISTS_SQL}
"""

BUCKET_COUNTS_SQL = """
SELECT locality_tag, COUNT(*)
  FROM mass_functions
 GROUP BY locality_tag
"""


def column_exists(conn) -> bool:
    """Return True iff `mass_functions.locality_tag` is in the schema."""
    sql = (
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'mass_functions' AND column_name = 'locality_tag'"
    )
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchone() is not None


def current_bucket_counts(conn) -> dict[str, int]:
    """Return {tag: count} for every distinct locality_tag value present."""
    with conn.cursor() as cur:
        cur.execute(BUCKET_COUNTS_SQL)
        rows = cur.fetchall()
    return {tag: count for tag, count in rows}


def scalar(conn, sql: str) -> int:
    """Run a count query and return the integer result."""
    with conn.cursor() as cur:
        cur.execute(sql)
        return int(cur.fetchone()[0])


def print_bucket_table(before: dict[str, int], after: dict[str, int]) -> None:
    """Render a small BEFORE/AFTER per-bucket table.

    Shows the three canonical tags in fixed order so the table is stable even
    if the DB has stray values (which it shouldn't, given the NOT NULL DEFAULT
    'unknown' column constraint, but we print any extras under each map too).
    """
    canonical = ("intra", "cross", "unknown")
    print(f"{'tag':<10} {'before':>12} {'after':>12} {'delta':>12}")
    print("-" * 50)
    for tag in canonical:
        b = before.get(tag, 0)
        a = after.get(tag, 0)
        print(f"{tag:<10} {b:>12} {a:>12} {a - b:>+12}")
    # Surface anything outside the canonical set (e.g. a hypothetical future
    # tag) without crashing.
    extras = sorted((set(before) | set(after)) - set(canonical))
    for tag in extras:
        b = before.get(tag, 0)
        a = after.get(tag, 0)
        print(f"{tag:<10} {b:>12} {a:>12} {a - b:>+12}  (non-canonical)")
    print("-" * 50)


def execute_backfill(conn) -> tuple[int, int]:
    """Run the three-step backfill in a single transaction.

    Returns (intra_updated, cross_updated). Raises on any per-statement
    failure; caller is responsible for the rollback + exit-1 path.
    """
    with conn.cursor() as cur:
        cur.execute(UPDATE_INTRA_SQL)
        intra_n = cur.rowcount
        print(f"  intra UPDATE: {intra_n} rows")
        cur.execute(UPDATE_CROSS_SQL)
        cross_n = cur.rowcount
        print(f"  cross UPDATE: {cross_n} rows")
        # The "everything else stays 'unknown'" branch in the plan is a
        # no-op by construction — it's the default. Nothing to execute.
    conn.commit()
    return intra_n, cross_n


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Commit the UPDATEs. Default is dry-run (no writes).",
    )
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    # Migration guard — fail fast with a clear message if Phase 1a hasn't
    # landed against this DB yet. Otherwise the COUNT queries below would
    # surface a less-actionable "column 'locality_tag' does not exist".
    if not column_exists(conn):
        print(
            "ERROR: mass_functions.locality_tag column missing.\n"
            "migration 045 not applied — deploy Phase 1a first.",
            file=sys.stderr,
        )
        conn.close()
        return 2

    before = current_bucket_counts(conn)

    if not args.execute:
        # Compute deltas WITHOUT writing. The cross delta mirrors the
        # sequential UPDATE semantics: rows that would still be 'unknown'
        # after the intra UPDATE AND have some evidence (so NOT intra-eligible).
        delta_intra = scalar(conn, DELTA_INTRA_SQL)
        delta_cross = scalar(conn, DELTA_CROSS_SQL)
        after = dict(before)
        after["intra"] = before.get("intra", 0) + delta_intra
        after["cross"] = before.get("cross", 0) + delta_cross
        after["unknown"] = before.get("unknown", 0) - delta_intra - delta_cross
        print("DRY-RUN — no writes. Per-bucket counts:")
        print()
        print_bucket_table(before, after)
        print()
        print(f"would set {delta_intra} rows to 'intra' (claim has intra-source evidence)")
        print(f"would set {delta_cross} rows to 'cross' (claim has evidence, none intra-source)")
        print(f"would leave {after['unknown']} rows as 'unknown'")
        print()
        print("Pass --execute to commit.")
        conn.close()
        return 0

    print("Executing backfill (single transaction)...")
    try:
        intra_n, cross_n = execute_backfill(conn)
    except Exception as exc:
        conn.rollback()
        print(f"ERROR: backfill failed mid-transaction, rolled back: {exc}", file=sys.stderr)
        conn.close()
        return 1

    after = current_bucket_counts(conn)
    print()
    print("Post-execute per-bucket counts:")
    print()
    print_bucket_table(before, after)
    print()
    print(f"updated {intra_n} rows to 'intra', {cross_n} rows to 'cross'")
    conn.close()

    print()
    print(
        "Next: deploy Phase 2 (combine path reads locality_tag dynamically) — see\n"
        "docs/superpowers/plans/2026-05-28-locality-tag-schema.md."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
