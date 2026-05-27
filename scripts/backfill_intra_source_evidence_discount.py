#!/usr/bin/env python3
"""Compose intra-source locality factor onto historical `mass_functions.source_strength`.

Companion to `backfill_source_strength.py` (commit 5202ded, 2026-05-03), which
populated `source_strength` from per-BBA `evidence_type` weights. This script
multiplies that per-BBA reliability by the calibrated
`intra_evidence_locality_factor` (from `calibration.toml`, default 0.3) for
BBAs whose claim has at least one intra-source evidence row.

Composition (does NOT replace):
    source_strength_new = source_strength_old * intra_evidence_locality_factor

So a logical/intra BBA at 0.85 lands at 0.85 * 0.3 = 0.255 (close to the
single-value 0.25 the original #185 script REPLACED with), but an
empirical/intra BBA at 1.0 lands at 0.30 — preserving the evidence-type
ordering. Cross-source BBAs are left untouched.

Schema bridge:
  mass_functions.claim_id -> evidence.claim_id
  evidence.properties->>'doi' = (paper that asserts mass_functions.claim_id)

Heuristic: the script discounts every BBA on a claim that has ≥1 intra-source
evidence row (by doi match). It cannot tell which BBAs derived from which
evidence row, so claims with MIXED intra+cross evidence over-discount the
cross-derived BBAs. The long-term fix is per-BBA provenance (e.g.
`mass_functions.evidence_id` FK); this script is the pragmatic step until
that lands.

Usage:
    python3 scripts/backfill_intra_source_evidence_discount.py            # dry run
    python3 scripts/backfill_intra_source_evidence_discount.py --execute  # write + reconcile

By default `--scope 0.85` targets the largest tier (≈74 711 BBAs in prod
as of 2026-05-27). Pass `--scope 1.0`, `--scope 0.75`, `--scope 0.5`,
`--scope 0.3`, or `--scope all` to widen.

Idempotency: the predicate only matches BBAs whose `source_strength`
sits at an UNCOMPOSED tier value. The set of post-composition values
({0.255, 0.225, 0.30, 0.18, 0.09} for the standard tiers at intra=0.3)
is disjoint from the set of pre-composition tier values
({0.85, 0.75, 1.0, 0.6, 0.3}) for any intra factor strictly less than 1.0,
so a second run sees no candidates. The forward write path (post-#185)
ALSO emits composed values directly, so newly-written BBAs are also
naturally excluded from re-discounting.

After --execute, the script POSTs each affected claim_id to
`/api/v1/graph/reconcile_sheaf` so beliefs re-aggregate against the new
composed weights.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for older interpreters
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]

import psycopg2
import requests


DEFAULT_DATABASE_URL = "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph"
DEFAULT_API = "http://localhost:8080"
DEFAULT_CALIBRATION = Path(__file__).resolve().parent.parent / "calibration.toml"

# Scope flag maps to a tier filter on `mf.source_strength`. `all` means
# "every BBA at a known uncomposed tier value". The pre-composition tier
# set is {0.85, 0.75, 1.0, 0.6, 0.3, 0.5, 0.9, 0.95, 0.98, 0.99, 0.97, 0.93,
# 0.92, 0.96, 0.8} — the 15 largest source_strength buckets in prod today.
# Composed values (input * 0.3) won't appear in this set for any intra
# factor strictly less than 1.0, which gives us natural idempotency
# without a schema-level marker.
KNOWN_TIERS = (
    1.0, 0.99, 0.98, 0.97, 0.96, 0.95, 0.93, 0.92, 0.9, 0.85, 0.8, 0.75, 0.6, 0.5, 0.3,
)
SCOPE_TIERS: dict[str, tuple[float, ...] | None] = {
    "1.0": (1.0,),
    "0.85": (0.85,),
    "0.75": (0.75,),
    "0.6": (0.6,),
    "0.5": (0.5,),
    "0.3": (0.3,),
    "all": KNOWN_TIERS,
}


def load_intra_factor(calibration_path: Path) -> float:
    with calibration_path.open("rb") as fh:
        cfg = tomllib.load(fh)
    locality = cfg["evidence_locality"]
    # Accept either the new key or, transitionally, the old one. The script
    # itself only uses the new key going forward.
    if "intra_evidence_locality_factor" in locality:
        return float(locality["intra_evidence_locality_factor"])
    raise KeyError(
        "evidence_locality.intra_evidence_locality_factor missing from "
        f"{calibration_path}. Did the calibration shape change?"
    )


def in_clause(values: tuple[float, ...]) -> str:
    """Render a SQL `IN (...)` list from a tuple of floats."""
    return "(" + ", ".join(f"{v}" for v in values) + ")"


def candidate_query(scope_tiers: tuple[float, ...]) -> str:
    """SELECT for in-scope BBAs. `scope_tiers` filters `mf.source_strength`.

    Match criterion: BBA's claim has at least one evidence row whose
    `properties->>'doi'` equals the doi of the paper that asserts the
    claim. The set of post-composition tier values is disjoint from
    `scope_tiers` for any intra factor < 1.0, giving natural idempotency.
    """
    tier_filter = f"mf.source_strength IN {in_clause(scope_tiers)}"
    return f"""
        SELECT mf.id, mf.claim_id, mf.source_strength
          FROM mass_functions mf
         WHERE {tier_filter}
           AND EXISTS (
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
           );
    """


def preview_distribution(
    conn, scope_tiers: tuple[float, ...], intra_factor: float
) -> tuple[int, int]:
    """Show what would be written, grouped by source_strength."""
    sql = candidate_query(scope_tiers)
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    n_rows = len(rows)
    n_claims = len({r[1] for r in rows})
    if n_rows == 0:
        return n_rows, n_claims

    # Group by source_strength tier and show pre / post values.
    by_tier: dict[float, int] = {}
    for _, _, ss in rows:
        ss_f = float(ss)
        by_tier[ss_f] = by_tier.get(ss_f, 0) + 1

    print(f"{'pre':>9} {'post':>9} {'rows':>10}")
    print("-" * 32)
    for tier in sorted(by_tier.keys(), reverse=True):
        post = tier * intra_factor
        print(f"{tier:>9.4f} {post:>9.4f} {by_tier[tier]:>10}")
    print("-" * 32)
    print(f"total rows: {n_rows}, distinct claims: {n_claims}")
    return n_rows, n_claims


def execute_backfill(
    conn, scope_tiers: tuple[float, ...], intra_factor: float
) -> tuple[int, list]:
    """Multiply source_strength by intra_factor for in-scope BBAs.

    Returns (n_rows_updated, sorted_unique_affected_claim_ids).
    """
    tier_filter = f"mf.source_strength IN {in_clause(scope_tiers)}"
    sql = f"""
        UPDATE mass_functions mf
           SET source_strength = source_strength * %s
         WHERE {tier_filter}
           AND EXISTS (
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
         RETURNING mf.claim_id;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (intra_factor,))
        claim_ids = [row[0] for row in cur.fetchall()]
    n_rows = len(claim_ids)
    conn.commit()
    return n_rows, sorted(set(claim_ids))


def reconcile_claims(api_url: str, claim_ids: list) -> int:
    """POST each affected claim_id to /api/v1/graph/reconcile_sheaf.

    Returns the count of failures (non-2xx responses). Continues past
    individual failures so a single bad claim doesn't abort the loop.
    """
    failures = 0
    for i, claim_id in enumerate(claim_ids, 1):
        try:
            r = requests.post(
                f"{api_url}/api/v1/graph/reconcile_sheaf",
                json={"claim_id": str(claim_id)},
                timeout=60,
            )
        except requests.RequestException as e:
            failures += 1
            print(f"  [{i}/{len(claim_ids)}] {claim_id}: request failed: {e}")
            continue
        if not r.ok:
            failures += 1
            print(
                f"  [{i}/{len(claim_ids)}] {claim_id}: "
                f"{r.status_code} {r.text[:200]}"
            )
        elif i % 100 == 0:
            print(f"  [{i}/{len(claim_ids)}] ok")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("EPIGRAPH_API", DEFAULT_API),
    )
    parser.add_argument(
        "--calibration",
        type=Path,
        default=DEFAULT_CALIBRATION,
    )
    parser.add_argument(
        "--scope",
        choices=sorted(SCOPE_TIERS.keys()),
        default="0.85",
        help="Tier of source_strength to target. Default 0.85 (largest tier in prod).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Write the multiplication + POST reconcile_sheaf. Otherwise dry-run.",
    )
    parser.add_argument(
        "--skip-reconcile",
        action="store_true",
        help="With --execute: write the UPDATE but skip the reconcile POSTs.",
    )
    args = parser.parse_args()

    intra_factor = load_intra_factor(args.calibration)
    scope_tiers = SCOPE_TIERS[args.scope]
    assert scope_tiers is not None
    print(f"intra_evidence_locality_factor = {intra_factor}")
    print(f"scope = {args.scope} (tier filter: source_strength IN {in_clause(scope_tiers)})")
    print()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    n_rows, n_claims = preview_distribution(conn, scope_tiers, intra_factor)
    print()
    print(f"matched {n_rows} BBAs across {n_claims} target claims")

    if n_rows == 0:
        print("nothing to do")
        conn.close()
        return 0

    if not args.execute:
        print()
        print("DRY-RUN — pass --execute to commit.")
        conn.close()
        return 0

    print()
    print(f"executing UPDATE (source_strength * {intra_factor})...")
    written, claim_ids = execute_backfill(conn, scope_tiers, intra_factor)
    print(f"  updated {written} BBAs across {len(claim_ids)} claims")
    conn.close()

    if args.skip_reconcile:
        print()
        print("--skip-reconcile set; not POSTing reconcile_sheaf.")
        print("Beliefs will re-aggregate on the next nightly graph-integrity pass.")
        return 0

    print()
    print(f"POSTing reconcile_sheaf for {len(claim_ids)} claims via {args.api_url}...")
    failures = reconcile_claims(args.api_url, claim_ids)
    print(f"reconcile complete; {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
