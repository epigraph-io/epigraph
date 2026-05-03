#!/usr/bin/env python3
"""Regenerate semantic-dedup.json from current claim embeddings.

Pairs every embedded claim with its top-k nearest neighbours via the
existing HNSW index on `claims.embedding`, filters to cosine similarity
≥ threshold, builds connected components via union-find, and writes a
JSON snapshot in the shape epigraph-gui consumes.

Output format (matches existing public/semantic-dedup.json):

    {
      "threshold": 0.95,
      "top_k": 8,
      "computed_at": "<ISO 8601 UTC>",
      "n_claims": <int>,
      "n_groups_with_dupes": <int>,
      "n_dup_claims": <int>,
      "groups": [
        {
          "rep": "<canonical claim uuid>",
          "label": "<canonical claim content prefix>",
          "members": ["<uuid>", ...]
        },
        ...
      ]
    }

Canonical-rep choice mirrors fuzzy_dedup_claims.py:
(reasoning_trace count, mass_function count, edge count) descending,
breaking ties by oldest created_at.

Usage:
    python3 scripts/compute_semantic_dedup.py
    python3 scripts/compute_semantic_dedup.py --threshold 0.92 --top-k 10
    python3 scripts/compute_semantic_dedup.py --limit 5000 --output /tmp/quick-dedup.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)
DEFAULT_OUTPUT = "/home/jeremy/epigraph-gui/public/semantic-dedup.json"


class UnionFind:
    """Path-compression union-find keyed on UUID strings."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
            return x
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        # Path compression
        while self.parent[x] != root:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def components(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for node in self.parent:
            root = self.find(node)
            groups.setdefault(root, []).append(node)
        return groups


def collect_pairs(
    conn,
    threshold: float,
    top_k: int,
    limit: int | None,
    progress_every: int,
) -> tuple[UnionFind, int]:
    """Walk every embedded claim, pull its top-k nearest, union pairs above threshold."""
    distance_cap = 1.0 - threshold

    # Count first, both for progress and for n_claims in the snapshot.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM claims WHERE embedding IS NOT NULL")
        n_claims = cur.fetchone()[0]
    if limit is not None:
        n_claims = min(n_claims, limit)

    uf = UnionFind()
    started = time.monotonic()

    with conn.cursor(name="claim_walk") as walker:
        walker.itersize = 500
        walker.execute(
            "SELECT id::text FROM claims WHERE embedding IS NOT NULL ORDER BY id"
        )

        with conn.cursor() as q:
            for i, (claim_id,) in enumerate(walker):
                if limit is not None and i >= limit:
                    break
                # CTE materialises the target embedding once, then the ORDER BY
                # can use the HNSW index on `claims.embedding`. The earlier JOIN
                # form looked like a cross-join to the planner and scanned all
                # 391k rows per claim.
                q.execute(
                    """
                    WITH t AS (
                        SELECT embedding FROM claims WHERE id = %s::uuid
                    )
                    SELECT n.id::text,
                           n.embedding <=> (SELECT embedding FROM t) AS dist
                      FROM claims n
                     WHERE n.embedding IS NOT NULL
                       AND n.id != %s::uuid
                  ORDER BY n.embedding <=> (SELECT embedding FROM t)
                     LIMIT %s
                    """,
                    (claim_id, claim_id, top_k),
                )
                for nbr_id, dist in q.fetchall():
                    if dist <= distance_cap:
                        uf.union(claim_id, nbr_id)
                # Ensure isolated claims still appear in the union-find so the
                # snapshot's n_claims count is honest.
                uf.find(claim_id)

                if (i + 1) % progress_every == 0:
                    elapsed = time.monotonic() - started
                    rate = (i + 1) / elapsed
                    eta = (n_claims - (i + 1)) / rate if rate > 0 else float("inf")
                    print(
                        f"  walked {i + 1}/{n_claims} claims "
                        f"({rate:.1f}/s, ETA {eta:.0f}s)",
                        file=sys.stderr,
                    )

    return uf, n_claims


def materialize_groups(
    conn, uf: UnionFind, min_members: int = 2
) -> tuple[list[dict], int, int]:
    """Promote each multi-member component to a group dict (rep + label + members)."""
    components = uf.components()
    multi = {root: members for root, members in components.items() if len(members) >= min_members}
    n_groups = len(multi)
    n_dup_claims = sum(len(m) for m in multi.values())

    if not multi:
        return [], 0, 0

    # Pull metadata for every claim in any multi-member component in one shot.
    all_ids: list[str] = []
    for members in multi.values():
        all_ids.extend(members)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT c.id::text,
                   substring(c.content for 200) AS label,
                   c.created_at,
                   COALESCE((SELECT count(*) FROM reasoning_traces WHERE claim_id = c.id), 0) AS trace_count,
                   COALESCE((SELECT count(*) FROM mass_functions  WHERE claim_id = c.id), 0) AS mf_count,
                   COALESCE((SELECT count(*) FROM edges WHERE source_id = c.id OR target_id = c.id), 0) AS edge_count
              FROM claims c
             WHERE c.id = ANY(%s::uuid[])
            """,
            (all_ids,),
        )
        meta = {
            r[0]: {
                "label": r[1] or "",
                "created_at": r[2],
                "trace_count": r[3],
                "mf_count": r[4],
                "edge_count": r[5],
            }
            for r in cur.fetchall()
        }

    groups: list[dict] = []
    for members in multi.values():
        scored = [(m, meta.get(m)) for m in members]
        scored = [(m, info) for m, info in scored if info is not None]
        if len(scored) < min_members:
            continue
        # Canonical-rep heuristic: matches fuzzy_dedup_claims.py.
        scored.sort(
            key=lambda mi: (
                -mi[1]["trace_count"],
                -mi[1]["mf_count"],
                -mi[1]["edge_count"],
                mi[1]["created_at"],
            )
        )
        rep, rep_info = scored[0]
        groups.append(
            {
                "rep": rep,
                "label": rep_info["label"],
                "members": [m for m, _ in scored],
            }
        )

    # Largest-first matches the layout of the existing snapshot.
    groups.sort(key=lambda g: -len(g["members"]))
    return groups, n_groups, n_dup_claims


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    parser.add_argument(
        "--threshold", type=float, default=0.95,
        help="Cosine similarity threshold (default 0.95)",
    )
    parser.add_argument(
        "--top-k", type=int, default=8,
        help="Top-k nearest neighbours per claim (default 8)",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap claims walked (smoke-test convenience)",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output path (default {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--progress-every", type=int, default=5000,
        help="Print progress every N claims (default 5000)",
    )
    args = parser.parse_args()

    if not 0.0 <= args.threshold <= 1.0:
        sys.exit("--threshold must be in [0.0, 1.0]")
    if args.top_k < 1:
        sys.exit("--top-k must be ≥ 1")

    psycopg2.extras.register_uuid()
    conn = psycopg2.connect(args.database_url)
    # Server-side (named) cursors require an open transaction. Keep
    # autocommit off and rely on never issuing writes for read-only safety.
    conn.autocommit = False

    print(
        f"computing semantic dedup (threshold={args.threshold}, top_k={args.top_k}"
        f"{f', limit={args.limit}' if args.limit else ''})",
        file=sys.stderr,
    )
    uf, n_claims = collect_pairs(
        conn,
        threshold=args.threshold,
        top_k=args.top_k,
        limit=args.limit,
        progress_every=args.progress_every,
    )
    groups, n_groups_with_dupes, n_dup_claims = materialize_groups(conn, uf)
    conn.close()

    snapshot = {
        "threshold": args.threshold,
        "top_k": args.top_k,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "n_claims": n_claims,
        "n_groups_with_dupes": n_groups_with_dupes,
        "n_dup_claims": n_dup_claims,
        "groups": groups,
    }
    tmp = args.output + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(snapshot, fh)
    os.replace(tmp, args.output)
    print(
        f"wrote {args.output}: n_claims={n_claims}, "
        f"groups={n_groups_with_dupes}, dup_claims={n_dup_claims}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
