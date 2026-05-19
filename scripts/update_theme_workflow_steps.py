#!/usr/bin/env python3
"""Update the stored 'Run k-means theme maintenance' workflow steps to reflect
the anchor-aware behaviour added by spec 2026-05-18-cross-source-anchor.

Calls mcp__epigraph__evolve_step (via the HTTP API) on the affected step
claims. Idempotent: skips steps whose current content already matches the
new content.

Affected step IDs (verified 2026-05-18):
  - 4d9bf697-e53c-57ac-ad92-526c8e86f06a  (old: "Run hypothesize() with cluster_count=8 ...")
  - 764aa179-2d19-5018-9581-573dbba2badc  (embedding_neighborhood_density step — keep as-is now that tool exists)
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg2

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
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
    conn.autocommit = False
    cur = conn.cursor()

    for step_id, new_content in UPDATES.items():
        cur.execute("SELECT content FROM claims WHERE id = %s AND is_current = true", (step_id,))
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
        # Mark current as superseded; insert new current with same lineage.
        # We don't have a Python evolve_step helper, so do it inline:
        cur.execute(
            "INSERT INTO claims (content, content_hash, agent_id, properties, supersedes, is_current) "
            "SELECT %s, decode(md5(%s) || md5(%s), 'hex'), agent_id, properties, %s, true "
            "FROM claims WHERE id = %s RETURNING id",
            (new_content, new_content, new_content, step_id, step_id),
        )
        new_id = cur.fetchone()[0]
        cur.execute("UPDATE claims SET is_current = false WHERE id = %s", (step_id,))
        conn.commit()
        print(f"  -> {new_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
