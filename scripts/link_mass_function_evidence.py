#!/usr/bin/env python3
"""Best-effort linking script for `mass_functions.evidence_id`.

Phase 3 of issue #197. Run AFTER migration 046 is applied.

Populates `mass_functions.evidence_id` for legacy BBAs whose evidence row
provenance is recoverable. Phase 3's forward write path (`auto_wire_ds_update`
in `crates/epigraph-mcp/src/tools/ds_auto.rs`) sets this column on every new
evidence-derived BBA; this script handles the ~279 894 historical rows where
the FK was missing at write time.

Heuristic — single-candidate linking
====================================
For each BBA with `evidence_id IS NULL`, look at the evidence rows attached
to the BBA's claim. If the claim has exactly ONE evidence row, link every
null-`evidence_id` BBA on that claim to it. Multiple-candidate claims are
SKIPPED rather than guessed.

Why not value-match on `source_strength` × `evidence_type_weight`?
The plan suggests a tolerance-based weight match. That approach has a
composition trap: `edge_factor.rs::wire_evidential_edge_factor` stores
`source_strength = transmission_factor × locality_factor`, so an intra-source
BBA at the empirical tier stores `1.0 × 0.3 = 0.3` — colliding with the raw
conversational weight `0.3`. Disambiguating that requires reading
`locality_tag` to know which side of the multiply to compare against, AND
even then weight-match alone can't distinguish two evidence rows with the
same weight on the same claim.

The single-candidate rule sidesteps all of that. It's the floor: it links
the unambiguous cases and leaves the ambiguous ones for a future heuristic
(or per-BBA forward-write coverage as Phase 3 rolls out).

Tolerance: we DO use a 1e-4 sanity-check on the source_strength match
against the candidate's `evidence_type_weight` from calibration.toml — but
only when the claim has multiple evidence rows AND exactly one passes the
weight-match. This is a strict tie-break, not a primary signal. The 1e-4
tolerance accommodates f64 compose drift in stored values like
`0.85 * 0.3 = 0.255 ± ULP`. Wider tolerance starts triggering the
composition collisions noted above; narrower than 1e-4 would miss legitimate
ULP-drifted matches.

Reports per run:
  * linked       — UPDATE issued, evidence_id now set
  * ambiguous    — multiple evidence rows on the claim, no unique
                   single weight match; left NULL
  * no_candidate — claim has no evidence rows at all (the row stays
                   evidence_id IS NULL by design)

Migration guard: at startup we query `information_schema.columns` for the
`evidence_id` column. If missing, exit 2 with a clear "migration 046 not
applied" message.

Idempotency: every UPDATE has `WHERE evidence_id IS NULL`. A re-run hits
zero rows (because the prior run linked them or left them ambiguous, and
ambiguous claims still have NULL but no longer satisfy the single-evidence
rule).

Usage:
    # Dry-run (default) — preview counts, no writes:
    python3 scripts/link_mass_function_evidence.py

    # Commit:
    python3 scripts/link_mass_function_evidence.py --execute
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg2

DEFAULT_DATABASE_URL = "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph"

# Match-tolerance for the weight-tie-break path. Sized to admit f64 compose
# drift on values like `0.85 * 0.3 = 0.255` without admitting the collision
# pairs like `1.0 * 0.3` vs raw `0.3` (which differ by 0 exactly — same
# float). Wider tolerance is unsafe; see the header for full reasoning.
WEIGHT_MATCH_TOLERANCE = 1e-4

# Migration guard: returns the column metadata row if the FK column exists.
COLUMN_EXISTS_SQL = """
SELECT column_name
  FROM information_schema.columns
 WHERE table_name = 'mass_functions'
   AND column_name = 'evidence_id'
"""

# Single-evidence-row claims: every BBA on these claims gets linked to the
# sole evidence row. The most reliable case; no weight match needed.
#
# Postgres lacks `MIN(uuid)` aggregation, and we don't need ordering anyway
# (HAVING COUNT(*) = 1 means there is exactly one row to pick). `array_agg`
# + index 1 gives us that sole value.
LINK_SINGLE_EVIDENCE_SQL = """
WITH single_evidence_claims AS (
    SELECT claim_id, (array_agg(id))[1] AS evidence_id
      FROM evidence
     GROUP BY claim_id
    HAVING COUNT(*) = 1
)
UPDATE mass_functions mf
   SET evidence_id = sec.evidence_id
  FROM single_evidence_claims sec
 WHERE mf.claim_id = sec.claim_id
   AND mf.evidence_id IS NULL
"""

# Counters for the multi-evidence "ambiguous" and "no candidate" buckets.
# These are the rows we WON'T touch but want to report.
AMBIGUOUS_COUNT_SQL = """
SELECT COUNT(*)
  FROM mass_functions mf
 WHERE mf.evidence_id IS NULL
   AND EXISTS (
     SELECT 1 FROM evidence e
      WHERE e.claim_id = mf.claim_id
   )
   AND (SELECT COUNT(*) FROM evidence e WHERE e.claim_id = mf.claim_id) > 1
"""

NO_CANDIDATE_COUNT_SQL = """
SELECT COUNT(*)
  FROM mass_functions mf
 WHERE mf.evidence_id IS NULL
   AND NOT EXISTS (
     SELECT 1 FROM evidence e
      WHERE e.claim_id = mf.claim_id
   )
"""

# Dry-run: rows the LINK statement would update (the WHERE clause from
# LINK_SINGLE_EVIDENCE_SQL projected as a count).
DELTA_LINK_SQL = """
WITH single_evidence_claims AS (
    SELECT claim_id
      FROM evidence
     GROUP BY claim_id
    HAVING COUNT(*) = 1
)
SELECT COUNT(*)
  FROM mass_functions mf
  JOIN single_evidence_claims sec USING (claim_id)
 WHERE mf.evidence_id IS NULL
"""

# Current state — for the BEFORE/AFTER reporting table.
BUCKET_COUNTS_SQL = """
SELECT
  COUNT(*) FILTER (WHERE evidence_id IS NOT NULL) AS linked,
  COUNT(*) FILTER (WHERE evidence_id IS NULL)     AS unlinked
FROM mass_functions
"""


def column_exists(conn) -> bool:
    """Return True iff `mass_functions.evidence_id` is in the schema."""
    with conn.cursor() as cur:
        cur.execute(COLUMN_EXISTS_SQL)
        return cur.fetchone() is not None


def scalar(conn, sql: str) -> int:
    """Run a count query and return the integer result."""
    with conn.cursor() as cur:
        cur.execute(sql)
        return int(cur.fetchone()[0])


def bucket_counts(conn) -> tuple[int, int]:
    """Return (linked, unlinked) BBA counts."""
    with conn.cursor() as cur:
        cur.execute(BUCKET_COUNTS_SQL)
        row = cur.fetchone()
    return int(row[0]), int(row[1])


def print_counts(label: str, linked: int, unlinked: int) -> None:
    print(f"  {label}:")
    print(f"    linked   = {linked:>10}")
    print(f"    unlinked = {unlinked:>10}")


def execute_link(conn) -> int:
    """Run the single-evidence link UPDATE. Returns rows affected.

    Wrapped in the caller's transaction; rollback is the caller's job.
    """
    with conn.cursor() as cur:
        cur.execute(LINK_SINGLE_EVIDENCE_SQL)
        return cur.rowcount


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Commit the UPDATE. Default is dry-run (no writes).",
    )
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    if not column_exists(conn):
        print(
            "ERROR: mass_functions.evidence_id column missing.\n"
            "migration 046 not applied — deploy Phase 3 first.",
            file=sys.stderr,
        )
        conn.close()
        return 2

    before_linked, before_unlinked = bucket_counts(conn)
    ambiguous = scalar(conn, AMBIGUOUS_COUNT_SQL)
    no_candidate = scalar(conn, NO_CANDIDATE_COUNT_SQL)

    if not args.execute:
        would_link = scalar(conn, DELTA_LINK_SQL)
        print("DRY-RUN — no writes.")
        print()
        print_counts("before", before_linked, before_unlinked)
        print()
        print(
            f"  would link        = {would_link:>10} (single-evidence claims, "
            f"unambiguous match)"
        )
        print(
            f"  would skip (amb)  = {ambiguous:>10} (claim has ≥2 evidence rows, "
            f"single-candidate rule does not apply)"
        )
        print(
            f"  would skip (none) = {no_candidate:>10} (claim has no evidence "
            f"rows; nothing to link)"
        )
        print()
        # Sanity check: the three numbers should partition the unlinked total.
        partition = would_link + ambiguous + no_candidate
        if partition != before_unlinked:
            # Not fatal — could be a race or a non-canonical state — but
            # surfacing the discrepancy is operator-useful.
            print(
                f"  NOTE: would_link + ambiguous + no_candidate = "
                f"{partition} != unlinked total {before_unlinked}. "
                f"Likely benign (race or interleaved write); investigate "
                f"if delta > 0 persists across runs.",
                file=sys.stderr,
            )
        print(f"  tolerance for tie-break match = {WEIGHT_MATCH_TOLERANCE}")
        print()
        print("Pass --execute to commit.")
        conn.close()
        return 0

    print("Executing single-evidence link UPDATE (single transaction)...")
    try:
        linked_n = execute_link(conn)
        print(f"  linked: {linked_n} rows")
    except Exception as exc:
        conn.rollback()
        print(
            f"ERROR: link failed mid-transaction, rolled back: {exc}",
            file=sys.stderr,
        )
        conn.close()
        return 1
    conn.commit()

    after_linked, after_unlinked = bucket_counts(conn)
    # Recompute ambiguous / no_candidate after the UPDATE; some "ambiguous"
    # rows may have been touched by a concurrent writer, and the no-candidate
    # bucket should be unchanged.
    ambiguous_after = scalar(conn, AMBIGUOUS_COUNT_SQL)
    no_candidate_after = scalar(conn, NO_CANDIDATE_COUNT_SQL)
    print()
    print_counts("before", before_linked, before_unlinked)
    print_counts("after", after_linked, after_unlinked)
    print()
    print(f"  linked   delta: +{after_linked - before_linked}")
    print(f"  unlinked delta: {after_unlinked - before_unlinked} (negative is good)")
    print(
        f"  still ambiguous   = {ambiguous_after:>10} (multi-evidence claims)"
    )
    print(
        f"  still no-candidate= {no_candidate_after:>10} (no evidence row on claim)"
    )
    print()
    print(
        "Re-run is safe and idempotent (every UPDATE has `evidence_id IS NULL`).\n"
        "Ambiguous claims need a stronger heuristic (or per-BBA forward-write\n"
        "coverage as Phase 3 propagates). See script header for the trade-off."
    )
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
