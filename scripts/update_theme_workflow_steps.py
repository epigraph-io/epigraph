#!/usr/bin/env python3
"""Update the stored 'Run k-means theme maintenance' workflow steps to reflect
the anchor-aware behaviour added by spec 2026-05-18-cross-source-anchor.

Uses POST /api/v1/workflows/steps/:id/evolve (the canonical evolve_step
endpoint) so the supersession is captured by the same primitive
mcp__epigraph__evolve_step uses internally. Idempotent: skips steps whose
current content already matches the new content.

Affected step IDs (verified 2026-05-18):
  - 4d9bf697-e53c-57ac-ad92-526c8e86f06a  (old: "Run hypothesize() with cluster_count=8 ...")
  - 764aa179-2d19-5018-9581-573dbba2badc  (embedding_neighborhood_density step — keep as-is now that tool exists)
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _api_client import EpiGraphClient

DEFAULT_DATABASE_URL = (
    "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph"
)

UPDATES = {
    "4d9bf697-e53c-57ac-ad92-526c8e86f06a":
        "Run hypothesize(statement='knowledge graph claims themes topics research', "
        "cluster_count=8, search_radius=0.25) to diagnose dense embedding "
        "neighborhoods that lack textbook anchors. For each returned cluster "
        "without strong textbook coverage, surface as a candidate for new "
        "textbook ingest or a theme sub-split.",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    cur = conn.cursor()
    api = EpiGraphClient(scopes=["claims:write", "claims:admin"])

    for step_id, new_content in UPDATES.items():
        cur.execute(
            "SELECT content FROM claims WHERE id = %s AND is_current = true",
            (step_id,),
        )
        row = cur.fetchone()
        if not row:
            print(f"[skip] {step_id}: not found")
            continue
        current = row[0]
        if current.strip() == new_content.strip():
            print(f"[skip] {step_id}: already up to date")
            continue
        print(f"[update] {step_id}")
        if args.dry_run:
            continue
        resp = api.post(
            f"/api/v1/workflows/steps/{step_id}/evolve",
            json={
                "parent_id": step_id,
                "content": new_content,
                "edge_type": "supersedes",
                "reason": "anchor-aware rewrite per spec 2026-05-18-cross-source-anchor",
                "level": 2,
            },
        )
        resp.raise_for_status()
        body = resp.json()
        print(f"  -> {body['claim_id']} (edge {body['edge_type']} {body['edge_id']})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
