#!/usr/bin/env python3
"""Backfill source_strength on existing intra-source evidential BBAs.

After the locality-aware discount lands (#185), new evidential BBAs written
by ``edge_factor::wire_evidential_edge_factor`` carry the correct
``source_strength`` automatically. This script catches BBAs written by that
same path that pre-date a re-calibration of ``intra_source_support_strength``
in ``calibration.toml``, OR that were written under the new path but somehow
still hold a stale value (e.g. a transient bug, a partial deploy).

Scope (what this script CAN backfill):
  ``mass_functions`` rows where ``evidence_type = 'edge_factor'`` AND the
  underlying edge (joined via ``mf.perspective_id = e.id``) is intra-source.

Scope (what this script CANNOT backfill):
  Historical BBAs written before the ``edge_factor`` write path existed do
  NOT have ``perspective_id = edge_id`` or ``evidence_type = 'edge_factor'``
  — the schema does not preserve enough provenance to identify which of
  them came from an intra-source evidential edge. Such rows need a
  schema-level remediation or a separate heuristic backfill, not this
  script. Counts of strength=1.0 BBAs unaffected by this script can be
  reviewed via ``SELECT COUNT(*) FROM mass_functions WHERE source_strength
  = 1.0 AND evidence_type IS DISTINCT FROM 'edge_factor';``.

Join semantics (the schema invariant this script relies on):
  ``edge_factor::wire_evidential_edge_factor`` (crates/epigraph-engine/src/
  edge_factor.rs) writes each BBA with ``claim_id = target_id``,
  ``source_agent_id = edge_signer_agent_id``, ``perspective_id = edge_id``,
  ``evidence_type = 'edge_factor'``. The correct way to find a BBA's
  underlying edge is ``mf.perspective_id = e.id`` filtered by
  ``mf.evidence_type = 'edge_factor'``. (The earlier version of this
  script joined on ``mf.source_agent_id = e.source_id``; that compared
  an agent UUID to a claim UUID and never matched in production —
  see PR #186 follow-up.)

This script:
  1. Loads intra_source_support_strength from calibration.toml.
  2. UPDATEs ``edge_factor`` mass_functions rows whose underlying edge is
     intra-source and whose source_strength is not already at the
     calibrated intra value.
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
            ON mf.perspective_id = e.id
         WHERE mf.evidence_type = 'edge_factor'
           AND e.relationship IN ('supports','refutes','corroborates','contradicts')
           AND e.source_type   = 'claim'
           AND e.target_type   = 'claim'
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
         WHERE mf.perspective_id = e.id
           AND mf.evidence_type  = 'edge_factor'
           AND e.relationship IN ('supports','refutes','corroborates','contradicts')
           AND e.source_type    = 'claim'
           AND e.target_type    = 'claim'
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
