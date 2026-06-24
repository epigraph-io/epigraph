#!/usr/bin/env python3
"""Audit legacy mixed-format BBAs in mass_functions.

A "mixed" BBA has both m({0}) > 0 (support for TRUE) AND m({1}) > 0
(support for FALSE) in the same row — the old pre-build_binary_bba format.
These cause high Dempster conflict K when combined with new pure-support BBAs,
which can lower pignistic_prob even when supports=true (backlog 30bfbb19,
fixed by PR branch 1c1360bb via monotonicity clamp).

This script answers:
  - How many mixed BBAs are there?
  - How many distinct claims carry them?
  - What is the distribution of m({1}) (opposing mass)?
  - Are any of them meaningfully opposing (m({1}) > 0.10)?

If most mixed BBAs have tiny m({1}) (< 0.05), a follow-up migration to
zero out that mass and re-run combine would be mathematically sound and
would eliminate the need for the monotonicity clamp entirely. If many
have large m({1}), the clamp is the correct permanent fix.

Usage:
    python3 scripts/audit_mixed_bbas.py
    DATABASE_URL=postgres://... python3 scripts/audit_mixed_bbas.py
"""

from __future__ import annotations

import argparse
import json
import os

import psycopg2

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)

MEANINGFUL_THRESHOLD = 0.10  # m({1}) above this = genuinely opposing signal


def parse_false_mass(masses: dict) -> float:
    """Extract m({FALSE}) from a masses JSON dict.

    Keys seen in production: "0", "1", "~", "0,1".
    Key "1" = FALSE focal element in the binary frame.
    """
    return float(masses.get("1", 0.0))


def parse_true_mass(masses: dict) -> float:
    return float(masses.get("0", 0.0))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=MEANINGFUL_THRESHOLD,
        help=f"m({{1}}) above this is 'meaningfully opposing' (default {MEANINGFUL_THRESHOLD})",
    )
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = True

    with conn.cursor() as cur:
        # Total mass_functions rows
        cur.execute("SELECT count(*) FROM mass_functions")
        total_rows = cur.fetchone()[0]

        # Mixed-format rows: have both m({0}) > 0 AND m({1}) > 0.
        # masses is jsonb; cast via ->> to text then to float for comparison.
        cur.execute("""
            SELECT
                id,
                claim_id,
                source_strength,
                evidence_type,
                (masses->>'0')::float  AS m_true,
                (masses->>'1')::float  AS m_false,
                (masses->>'~')::float  AS m_missing,
                (masses->>'0,1')::float AS m_ignorance
            FROM mass_functions
            WHERE
                (masses->>'0') IS NOT NULL
                AND (masses->>'1') IS NOT NULL
                AND (masses->>'0')::float > 0
                AND (masses->>'1')::float > 0
            ORDER BY (masses->>'1')::float DESC
        """)
        rows = cur.fetchall()

    conn.close()

    mixed_count = len(rows)
    claim_ids = {r[1] for r in rows}
    n_claims = len(claim_ids)

    print(f"Total mass_functions rows : {total_rows:,}")
    print(f"Mixed-format BBAs         : {mixed_count:,}  ({mixed_count/total_rows*100:.1f}%)")
    print(f"Distinct claims affected  : {n_claims:,}")
    print()

    if mixed_count == 0:
        print("No mixed BBAs found — the legacy format has been fully migrated.")
        return

    false_masses = [r[5] for r in rows]

    # Distribution buckets
    buckets = [
        (0.00, 0.01, "< 0.01  (negligible noise)"),
        (0.01, 0.05, "0.01–0.05  (small artifact)"),
        (0.05, 0.10, "0.05–0.10  (minor signal)"),
        (0.10, 0.20, "0.10–0.20  (moderate opposing)"),
        (0.20, 1.01, "> 0.20  (strong opposing signal)"),
    ]
    print("m({FALSE}) distribution:")
    for lo, hi, label in buckets:
        n = sum(1 for m in false_masses if lo <= m < hi)
        print(f"  {label:35s} {n:5d}  ({n/mixed_count*100:5.1f}%)")
    print()

    meaningful = [(r[1], r[4], r[5], r[3]) for r in rows if r[5] >= args.threshold]
    print(f"Meaningfully opposing (m({{1}}) >= {args.threshold}): {len(meaningful)}")
    if meaningful:
        print()
        print(f"  {'claim_id':36s}  {'m_true':>7}  {'m_false':>8}  evidence_type")
        for claim_id, m_true, m_false, ev_type in meaningful[:30]:
            print(f"  {claim_id}  {m_true:7.4f}  {m_false:8.4f}  {ev_type or 'NULL'}")
        if len(meaningful) > 30:
            print(f"  ... and {len(meaningful) - 30} more")
    print()

    # Migration recommendation
    trivial = sum(1 for m in false_masses if m < 0.05)
    trivial_pct = trivial / mixed_count * 100
    print("Migration verdict:")
    if len(meaningful) == 0:
        print(
            f"  ALL {mixed_count} mixed BBAs have m({{1}}) < {args.threshold}."
            "  Safe to zero out m({{1}}) and renormalize —"
            "  would eliminate the monotonicity clamp entirely."
        )
    elif trivial_pct >= 90:
        print(
            f"  {trivial_pct:.0f}% of mixed BBAs are trivially small (m({{1}}) < 0.05)."
            f"  {len(meaningful)} have meaningful opposing signal and should be kept as-is."
            "  Partial migration (zero out only the trivial rows) is feasible."
        )
    else:
        print(
            f"  {len(meaningful)}/{mixed_count} mixed BBAs carry genuine opposing signal."
            "  The monotonicity clamp is the correct permanent fix; migration would be lossy."
        )


if __name__ == "__main__":
    main()
