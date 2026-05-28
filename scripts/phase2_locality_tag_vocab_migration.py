#!/usr/bin/env python3
"""Phase 2 (issue #197) one-shot vocabulary migration for mass_functions.

Runs ONCE post-deploy, after Phase 2 (this PR) lands. Idempotent via WHERE
clauses that won't re-match on a second run. Do NOT fold into the binary's
automatic migration sequence — this is a data migration that operates on
historical row content the helper has now changed how it interprets.

Two pieces of work:

1. **locality_tag vocabulary expansion (Q3 decision).**
   Phase 1a/1b wrote the bare tag 'intra' for every DOI-match BBA. Phase 2
   distinguishes 'intra_self_cite' (DOI-match → the supporter cites the
   target's own paper) from a hypothetical future 'intra_methodological_overlap'.
   The forward write path now emits 'intra_self_cite' for DOI-match. This
   migration renames the 99 378 historical 'intra' rows to match.

   Phase 2 helper treats any locality_tag starting with "intra" as intra,
   so this is purely cosmetic in terms of belief math. But it lets future
   per-tag analytics (e.g. "what fraction of intra-source evidence is
   self-citation vs methodological overlap?") work without rewriting the
   data again.

2. **evidence_type canonical-key migration (Q5 path 3).**
   Phase 1a/3 forward writes from edge_factor stored the raw relationship
   string (e.g. 'supports', 'CORROBORATES', 'refutes') in evidence_type.
   Phase 2's helper resolves those through [evidence_type_aliases] in
   calibration.toml to the canonical SciFact-calibrated keys
   ('derived_support', 'derived_refute', ...). This migration rewrites
   the stored evidence_type to the canonical key so downstream
   read-side analytics (and any future direct-key lookups) match the
   new vocabulary. Helper math doesn't change — the alias chain
   produces the same weight either way.

   Production vocabulary as of 2026-05-27 (queried against the live DB):
       empirical      : 414  ← SciFact canonical; unchanged.
       document       : 380  ← SciFact alias; unchanged.
       observation    : 118  ← SciFact alias; unchanged.
       logical        : 115  ← SciFact canonical; unchanged.
       reference      : 104  ← SciFact alias; unchanged.
       statistical    :  69  ← SciFact canonical; unchanged.
       testimony      :  56  ← SciFact alias; unchanged.
       CORROBORATES   :  56  ← relationship → derived_support (Phase 2 key)
       testimonial    :  39  ← SciFact canonical; unchanged.
       supersedes     :   2  ← relationship → derived_supersession
       circumstantial :   2  ← SciFact canonical; unchanged.
       SUPPORTS       :   1  ← relationship → derived_support

   Only the relationship-as-evidence-type rows (59 total) are
   migrated. The SciFact / SciFact-alias rows already resolve to
   calibrated weights via [evidence_type_aliases]; leaving them
   verbatim costs zero math precision.

Usage:
    # Dry-run (default) — preview row counts, no writes:
    python3 scripts/phase2_locality_tag_vocab_migration.py

    # Commit:
    python3 scripts/phase2_locality_tag_vocab_migration.py --execute

Both updates run in a single transaction. If either fails the whole
thing rolls back and the script exits 1.

Validation: at startup we check `information_schema.columns` for the
expected columns. If the schema doesn't match Phase 1a (locality_tag)
+ Phase 1a (evidence_type), exit early with a hint.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Dict

import psycopg2  # type: ignore[import-untyped]

# Rename existing 'intra' rows to the more specific 'intra_self_cite' tag.
# The Phase 1a/1b detection was DOI-match → self-cite by definition.
RENAME_INTRA_SQL = """
UPDATE mass_functions
   SET locality_tag = 'intra_self_cite'
 WHERE locality_tag = 'intra'
"""

# Path-3 backfill: relationship-string evidence_type → canonical key.
# Aliases are case-insensitive in CalibrationConfig::get_evidence_type_weight,
# but the stored value is case-as-written. Match all known casings.
RELATIONSHIP_REWRITES: Dict[str, list[str]] = {
    "derived_support": ["supports", "corroborates", "SUPPORTS", "CORROBORATES", "Supports", "Corroborates"],
    "derived_refute": ["refutes", "contradicts", "REFUTES", "CONTRADICTS", "Refutes", "Contradicts"],
    "derived_supersession": ["supersedes", "SUPERSEDES", "Supersedes"],
    "derived_elaboration": ["elaborates", "specializes", "ELABORATES", "SPECIALIZES"],
    "derived_generalization": ["generalizes", "GENERALIZES"],
    "derived_informational": ["informs", "INFORMS"],
    "derived_frame_evidence": ["frame_validates", "FRAME_VALIDATES"],
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--execute", action="store_true", help="commit the migration (default: dry-run)")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="postgres DSN (default: $DATABASE_URL)",
    )
    args = parser.parse_args()

    if not args.database_url:
        print("ERROR: --database-url or $DATABASE_URL required", file=sys.stderr)
        return 1

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            # Schema preconditions.
            cur.execute(
                """
                SELECT column_name FROM information_schema.columns
                 WHERE table_name = 'mass_functions'
                   AND column_name IN ('locality_tag', 'evidence_type')
                """
            )
            cols = {row[0] for row in cur.fetchall()}
            if "locality_tag" not in cols:
                print("ERROR: mass_functions.locality_tag not found — apply migration 045 first", file=sys.stderr)
                return 1
            if "evidence_type" not in cols:
                print("ERROR: mass_functions.evidence_type not found — schema unexpected", file=sys.stderr)
                return 1

            # Preview counts BEFORE.
            cur.execute("SELECT locality_tag, COUNT(*) FROM mass_functions GROUP BY 1 ORDER BY 2 DESC")
            print("== locality_tag distribution (before) ==")
            for tag, count in cur.fetchall():
                print(f"  {tag!r:35} {count}")

            cur.execute(
                "SELECT evidence_type, COUNT(*) FROM mass_functions WHERE evidence_type IS NOT NULL "
                "GROUP BY 1 ORDER BY 2 DESC"
            )
            print("== evidence_type distribution (before) ==")
            for et, count in cur.fetchall():
                print(f"  {et!r:35} {count}")

            # Step 1: locality_tag 'intra' → 'intra_self_cite'.
            cur.execute("SELECT COUNT(*) FROM mass_functions WHERE locality_tag = 'intra'")
            intra_count = cur.fetchone()[0]
            print(f"\n[step 1] {intra_count} rows have locality_tag = 'intra'; will rename to 'intra_self_cite'")
            if args.execute:
                cur.execute(RENAME_INTRA_SQL)
                print(f"         UPDATED {cur.rowcount} rows")

            # Step 2: relationship → canonical evidence_type.
            for canonical, sources in RELATIONSHIP_REWRITES.items():
                # ANY ($1) lets us match multiple casings in one query.
                cur.execute(
                    "SELECT COUNT(*) FROM mass_functions WHERE evidence_type = ANY(%s)",
                    (sources,),
                )
                n = cur.fetchone()[0]
                print(
                    f"[step 2] {n} rows with evidence_type in {sources!r} → '{canonical}'"
                )
                if args.execute and n > 0:
                    cur.execute(
                        "UPDATE mass_functions SET evidence_type = %s WHERE evidence_type = ANY(%s)",
                        (canonical, sources),
                    )
                    print(f"         UPDATED {cur.rowcount} rows")

            if args.execute:
                conn.commit()
                print("\nCOMMITTED.")
                # Preview AFTER.
                with conn.cursor() as cur2:
                    cur2.execute("SELECT locality_tag, COUNT(*) FROM mass_functions GROUP BY 1 ORDER BY 2 DESC")
                    print("== locality_tag distribution (after) ==")
                    for tag, count in cur2.fetchall():
                        print(f"  {tag!r:35} {count}")
                    cur2.execute(
                        "SELECT evidence_type, COUNT(*) FROM mass_functions WHERE evidence_type IS NOT NULL "
                        "GROUP BY 1 ORDER BY 2 DESC"
                    )
                    print("== evidence_type distribution (after) ==")
                    for et, count in cur2.fetchall():
                        print(f"  {et!r:35} {count}")
            else:
                conn.rollback()
                print("\nDRY RUN — no rows committed. Re-run with --execute.")
    except Exception as exc:
        conn.rollback()
        print(f"ERROR — rolled back: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
