#!/usr/bin/env python3
"""Backfill `mass_functions.source_strength` for intra-source evidential BBAs.

Companion to `backfill_source_strength.py` (commit 5202ded, 2026-05-03) and
replacement for the broken `backfill_intra_source_discount.py` (reverted in
PR #191). See `docs/superpowers/plans/2026-05-27-locality-backfill-redesign.md`
for the redesign rationale.

After PR #185, new evidential edges write `source_strength` using the
locality-aware discount (intra-source: 0.25, cross-source: 1.0) via
`edge_factor::wire_evidential_edge_factor`. Historical BBAs written by the
predecessor backfill (`5202ded`) carry tier weights from `evidence_type`
(0.85 for reference/document/logical, 1.0 for empirical, 0.75 for
testimonial, 0.3 for no-evidence/conversational). The 0.85 tier in
particular is where the bulk of intra-source self-citation evidence
lives — papers that cite themselves in their own extracted-claim
evidence rows.

This script re-discounts that tier to the locality-aware intra value
(0.25 by default, read from `calibration.toml`).

Schema bridge:
  mass_functions.claim_id -> evidence.claim_id
  evidence.properties->>'doi' = (asserting paper's doi)

The schema does NOT carry per-BBA edge provenance, so this is a heuristic
operating at claim-level granularity, not BBA-level. A BBA on a claim
with mixed-source evidence may be over- or under-discounted by this
pass; the long-term fix is `mass_functions.evidence_id` FK so each BBA
carries its own provenance (Option F in the redesign doc).

Usage:
    python3 scripts/backfill_intra_source_evidence_discount.py            # dry run
    python3 scripts/backfill_intra_source_evidence_discount.py --execute  # write + reconcile

By default `--scope 0.85` targets the largest tier (≈74 711 BBAs in prod
as of 2026-05-27). Pass `--scope 1.0`, `--scope 0.75`, or `--scope all`
to widen.

Idempotent: every match is gated on `mf.source_strength IS DISTINCT FROM <intra>`,
so a second pass against an already-backfilled DB matches zero rows.

After --execute, the script POSTs each affected claim_id to
`/api/v1/graph/reconcile_sheaf` so beliefs re-aggregate against the
new discount weights.
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

# Recognized scope values map to a tier filter on `mf.source_strength`.
# `all` means "every BBA that isn't already at intra". `intra=0.25` itself
# is always excluded — that's the IS DISTINCT FROM guard.
SCOPE_TIERS: dict[str, float | None] = {
    "0.85": 0.85,
    "1.0": 1.0,
    "0.75": 0.75,
    "0.5": 0.5,
    "0.3": 0.3,
    "all": None,
}


def load_intra_strength(calibration_path: Path) -> float:
    with calibration_path.open("rb") as fh:
        cfg = tomllib.load(fh)
    return float(cfg["evidence_locality"]["intra_source_support_strength"])


def candidate_query(scope_tier: float | None) -> tuple[str, tuple]:
    """SELECT for BBAs in scope. Returns (sql, params) with %s placeholders.

    Match criterion: BBA's claim has at least one evidence row whose
    `properties->>'doi'` equals a paper that asserts the claim. That is
    "this evidence row cites the paper that asserts the target claim"
    — i.e. paper self-citation in its own extracted-claim evidence rows.
    """
    tier_filter = ""
    params: list = []
    if scope_tier is not None:
        tier_filter = "AND mf.source_strength = %s"
        params.append(scope_tier)
    # IS DISTINCT FROM intra: guarantees idempotency and excludes BBAs
    # already at the calibrated value (skipped by the scope check itself,
    # but the explicit guard documents the invariant and survives a
    # future widening of `SCOPE_TIERS`).
    params.append(None)  # placeholder filled by caller with intra
    sql = f"""
        SELECT mf.id, mf.claim_id, mf.source_strength
          FROM mass_functions mf
         WHERE TRUE
           {tier_filter}
           AND mf.source_strength IS DISTINCT FROM %s
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
    return sql, tuple(params)


def preview(conn, intra: float, scope_tier: float | None) -> tuple[int, int]:
    sql, params = candidate_query(scope_tier)
    params_with_intra = tuple(intra if p is None else p for p in params)
    with conn.cursor() as cur:
        cur.execute(sql, params_with_intra)
        rows = cur.fetchall()
    n_rows = len(rows)
    n_claims = len({r[1] for r in rows})
    return n_rows, n_claims


def execute_backfill(
    conn, intra: float, scope_tier: float | None
) -> tuple[int, list]:
    """UPDATE the in-scope BBAs to `intra`. Returns (n_rows, affected_claim_ids)."""
    tier_filter = ""
    params: list = []
    if scope_tier is not None:
        tier_filter = "AND mf.source_strength = %s"
        params.append(scope_tier)
    # binding order below: (intra) for SET, then optional tier, then intra
    # for the IS DISTINCT FROM guard.
    sql = f"""
        UPDATE mass_functions mf
           SET source_strength = %s
         WHERE TRUE
           {tier_filter}
           AND mf.source_strength IS DISTINCT FROM %s
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
    bind = (intra, *params, intra)
    with conn.cursor() as cur:
        cur.execute(sql, bind)
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
        help="Tier of source_strength to target. Default 0.85 (Option C).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Write the update + POST reconcile_sheaf. Otherwise dry-run.",
    )
    parser.add_argument(
        "--skip-reconcile",
        action="store_true",
        help="With --execute: write the UPDATE but skip the reconcile POSTs.",
    )
    args = parser.parse_args()

    intra = load_intra_strength(args.calibration)
    scope_tier = SCOPE_TIERS[args.scope]
    print(f"intra_source_support_strength = {intra}")
    print(f"scope = {args.scope} (tier filter: source_strength = {scope_tier})")
    print()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    n_rows, n_claims = preview(conn, intra, scope_tier)
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
    print("executing UPDATE...")
    written, claim_ids = execute_backfill(conn, intra, scope_tier)
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
