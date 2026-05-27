#!/usr/bin/env python3
"""Backfill source_strength on existing intra-source evidential BBAs.

Pre-2026-05-27, every evidential edge wrote source_strength=1.0 regardless
of whether the source and target shared a paper. After the locality-aware
discount lands, new edges get the right value automatically, but the
historical mass_functions rows are still over-strong.

This script:
  1. Loads intra_source_support_strength from calibration.toml.
  2. UPDATEs mass_functions rows whose underlying edge is intra-source.
  3. Collects affected claim_ids and POSTs each to
     /api/v1/graph/reconcile_sheaf to recompute belief.

Usage:
    DATABASE_URL=postgres://... EPIGRAPH_API=http://localhost:8080 \
        python3 scripts/backfill_intra_source_discount.py [--dry-run]

The --dry-run mode reports the count of rows that would be updated and the
distinct affected claims without writing.

Idempotency: the SELECT and UPDATE both include
``mf.source_strength IS DISTINCT FROM <intra>`` so a second run against an
already-backfilled DB matches zero rows. This is the strict-idempotent
variant flagged in the plan (Task 7 Step 3).
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


def load_intra_strength() -> float:
    repo_root = Path(__file__).resolve().parent.parent
    with (repo_root / "calibration.toml").open("rb") as f:
        cfg = tomllib.load(f)
    return float(cfg["evidence_locality"]["intra_source_support_strength"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report only, no writes")
    args = parser.parse_args()

    db_url = os.environ.get("DATABASE_URL")
    api_url = os.environ.get("EPIGRAPH_API", "http://localhost:8080")
    if not db_url:
        print("DATABASE_URL not set", file=sys.stderr)
        return 2

    intra = load_intra_strength()
    print(f"intra_source_support_strength = {intra}")

    conn = psycopg2.connect(db_url)
    conn.autocommit = False
    cur = conn.cursor()

    cur.execute(
        """
        SELECT mf.id, mf.claim_id, mf.source_strength, e.id AS edge_id
          FROM mass_functions mf
          JOIN edges e
            ON mf.source_agent_id = e.source_id
           AND mf.claim_id        = e.target_id
         WHERE e.relationship IN ('supports','refutes','corroborates','contradicts')
           AND mf.source_strength IS DISTINCT FROM %s
           AND same_source_papers(e.source_id, e.target_id);
        """,
        (intra,),
    )
    rows = cur.fetchall()
    affected_claims = sorted({r[1] for r in rows})
    print(f"matched {len(rows)} BBAs across {len(affected_claims)} target claims")
    if not rows:
        print("nothing to do")
        return 0

    if args.dry_run:
        print("dry-run: would update; exiting without write")
        return 0

    cur.execute(
        """
        UPDATE mass_functions mf
           SET source_strength = %s
          FROM edges e
         WHERE mf.source_agent_id = e.source_id
           AND mf.claim_id        = e.target_id
           AND e.relationship IN ('supports','refutes','corroborates','contradicts')
           AND mf.source_strength IS DISTINCT FROM %s
           AND same_source_papers(e.source_id, e.target_id);
        """,
        (intra, intra),
    )
    conn.commit()
    print(f"updated {cur.rowcount} BBAs")

    print(f"reconciling {len(affected_claims)} target claims via {api_url}")
    failures = 0
    for claim_id in affected_claims:
        r = requests.post(
            f"{api_url}/api/v1/graph/reconcile_sheaf",
            json={"claim_id": str(claim_id)},
            timeout=60,
        )
        if not r.ok:
            failures += 1
            print(f"  reconcile failed for {claim_id}: {r.status_code} {r.text[:200]}")
    print(f"done - {failures} reconcile failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
