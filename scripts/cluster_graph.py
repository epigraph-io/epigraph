"""
Run Leiden community detection on the claim↔claim edge graph and persist the
result in the graph_community_* tables. One run is captured per execution.

Usage:
    .venv-graph/bin/python scripts/cluster_graph.py [--algo leiden|louvain]
                                                    [--min-size 5]
                                                    [--label-source theme]

Edge weighting (defaults applied when --weighted is on, which is the default):
    decomposes_to       0.4   structural backbone, very dense, dampened
    same_source         0.0   omitted (provenance, not argument)
    CORROBORATES        1.0
    continues_argument  0.6
    refines / REFINES   0.7
    supports / SUPPORTS 1.0
    contradicts / etc   1.0   (Leiden treats negative weights oddly; keep +1)
    relates_to          0.5
    everything else     0.5
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter

import igraph as ig
import leidenalg
import psycopg


DEFAULT_DSN = os.environ.get(
    "DATABASE_URL",
    "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph",
)


# Relationships that carry argumentative or structural meaning between claims.
# `same_source` and `produced` are excluded — they cluster claims by paper of
# origin, which is not what we want from a graph-community view.
EDGE_WEIGHTS: dict[str, float] = {
    "decomposes_to": 0.4,
    "CORROBORATES": 1.0,
    "corroborates": 1.0,
    "continues_argument": 0.6,
    "refines": 0.7,
    "REFINES": 0.7,
    "supports": 1.0,
    "SUPPORTS": 1.0,
    "refutes": 1.0,
    "contradicts": 1.0,
    "CONTRADICTS": 1.0,
    "relates_to": 0.5,
    "RELATES_TO": 0.5,
    "supersedes": 0.6,
    "derived_from": 0.5,
    "DERIVED_FROM": 0.5,
    "derives_from": 0.5,
    "same_as": 0.8,
    "analogous": 0.5,
    "asserts": 0.4,
    "enables": 0.4,
}


def fetch_graph(conn) -> tuple[list, list, list[str], list[float]]:
    """Return (claim_ids, edges_idx_pairs, relationships, weights)."""
    print("[1/5] loading edges...", flush=True)
    t0 = time.time()
    rels = list(EDGE_WEIGHTS.keys())
    rows = conn.execute(
        """
        SELECT source_id, target_id, relationship
        FROM edges
        WHERE source_type = 'claim'
          AND target_type = 'claim'
          AND relationship = ANY(%s)
        """,
        (rels,),
    ).fetchall()
    print(f"      fetched {len(rows):,} edges in {time.time()-t0:.1f}s", flush=True)

    # Build vertex index from edge endpoints (we don't need disconnected claims)
    print("[2/5] indexing vertices...", flush=True)
    t0 = time.time()
    seen: dict[str, int] = {}
    e_pairs: list[tuple[int, int]] = []
    rel_list: list[str] = []
    weights: list[float] = []
    for src, tgt, rel in rows:
        s = str(src)
        t = str(tgt)
        if s == t:
            continue
        si = seen.get(s)
        if si is None:
            si = len(seen)
            seen[s] = si
        ti = seen.get(t)
        if ti is None:
            ti = len(seen)
            seen[t] = ti
        e_pairs.append((si, ti))
        rel_list.append(rel)
        weights.append(EDGE_WEIGHTS.get(rel, 0.5))
    claim_ids = [None] * len(seen)
    for cid, idx in seen.items():
        claim_ids[idx] = cid
    print(
        f"      {len(claim_ids):,} vertices, {len(e_pairs):,} edges "
        f"in {time.time()-t0:.1f}s",
        flush=True,
    )
    return claim_ids, e_pairs, rel_list, weights


def run_leiden(g: ig.Graph, weights: list[float], algo: str):
    print(f"[3/5] running {algo} community detection...", flush=True)
    t0 = time.time()
    if algo == "leiden":
        partition = leidenalg.find_partition(
            g,
            leidenalg.ModularityVertexPartition,
            weights=weights,
            seed=42,
        )
    elif algo == "louvain":
        membership = g.community_multilevel(weights=weights, return_levels=False)
        partition = membership
    else:
        raise SystemExit(f"unknown algo: {algo}")
    modularity = g.modularity(partition.membership, weights=weights)
    print(
        f"      {algo} produced {len(set(partition.membership)):,} communities "
        f"(modularity={modularity:.4f}) in {time.time()-t0:.1f}s",
        flush=True,
    )
    return partition.membership, modularity


def build_labels(conn, claim_ids: list[str], membership: list[int]):
    """Auto-label each community by its dominant claim_theme name."""
    print("[4/5] computing community labels...", flush=True)
    t0 = time.time()
    # community_id -> Counter[theme_label] for community vote
    by_comm: dict[int, list[str]] = {}
    for cid, comm in zip(claim_ids, membership):
        by_comm.setdefault(comm, []).append(cid)
    # Single SQL fetch of theme_id for all involved claims
    theme_rows = conn.execute(
        """
        SELECT c.id, ct.id, ct.label
        FROM claims c
        LEFT JOIN claim_themes ct ON ct.id = c.theme_id
        WHERE c.id = ANY(%s)
        """,
        ([str(c) for c in claim_ids],),
    ).fetchall()
    theme_by_claim: dict[str, tuple[str | None, str | None]] = {
        str(cid): (str(tid) if tid else None, label)
        for cid, tid, label in theme_rows
    }
    labels: dict[int, tuple[str, int, str | None]] = {}
    for comm, cids in by_comm.items():
        votes: Counter = Counter()
        theme_votes: Counter = Counter()
        for c in cids:
            tid, lbl = theme_by_claim.get(str(c), (None, None))
            if lbl:
                votes[lbl] += 1
            if tid:
                theme_votes[tid] += 1
        if votes:
            top_label = votes.most_common(1)[0][0]
        else:
            top_label = f"Community {comm}"
        dominant_theme_id = (
            theme_votes.most_common(1)[0][0] if theme_votes else None
        )
        labels[comm] = (top_label, len(cids), dominant_theme_id)
    print(
        f"      labelled {len(labels):,} communities in {time.time()-t0:.1f}s",
        flush=True,
    )
    return labels


def persist(
    conn,
    *,
    algorithm: str,
    n_nodes: int,
    n_edges: int,
    modularity: float,
    claim_ids: list[str],
    membership: list[int],
    labels: dict[int, tuple[str, int, str | None]],
    min_size: int,
):
    print("[5/5] writing to graph_community_* tables...", flush=True)
    t0 = time.time()
    # Drop singletons / tiny communities for readability — these can be
    # noisy and clutter the GUI. They remain unassigned in this run.
    keep = {c for c, (_lbl, sz, _t) in labels.items() if sz >= min_size}
    n_communities = len(keep)
    with conn.transaction():
        run_id = conn.execute(
            """
            INSERT INTO graph_community_runs
                (algorithm, edge_filter, n_nodes, n_edges, n_communities, modularity)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                algorithm,
                "argumentative_claim_edges",
                n_nodes,
                n_edges,
                n_communities,
                modularity,
            ),
        ).fetchone()[0]
        # Bulk insert assignments using copy
        with conn.cursor().copy(
            "COPY graph_communities (run_id, claim_id, community_id) FROM STDIN"
        ) as copy:
            for cid, comm in zip(claim_ids, membership):
                if comm in keep:
                    copy.write_row((run_id, cid, comm))
        # Insert labels
        with conn.cursor().copy(
            "COPY graph_community_labels (run_id, community_id, label, size, dominant_theme_id) FROM STDIN"
        ) as copy:
            for comm, (label, size, theme_id) in labels.items():
                if comm in keep:
                    copy.write_row((run_id, comm, label, size, theme_id))
    print(
        f"      persisted run {run_id} ({n_communities:,} communities >= "
        f"{min_size}) in {time.time()-t0:.1f}s",
        flush=True,
    )
    return run_id


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--algo", default="leiden", choices=["leiden", "louvain"])
    p.add_argument(
        "--min-size",
        type=int,
        default=5,
        help="drop communities smaller than this many claims (default: 5)",
    )
    p.add_argument(
        "--dsn",
        default=DEFAULT_DSN,
        help="Postgres DSN (defaults to DATABASE_URL or local epigraph)",
    )
    args = p.parse_args()

    # autocommit=True so that `with conn.transaction():` creates a real top-level
    # transaction. With autocommit=False, that block becomes a SAVEPOINT inside
    # an implicit outer transaction that close() silently rolls back.
    conn = psycopg.connect(args.dsn, autocommit=True)
    try:
        claim_ids, e_pairs, _rels, weights = fetch_graph(conn)
        if not claim_ids:
            print("no claim-edges found; exiting", file=sys.stderr)
            sys.exit(1)

        g = ig.Graph(n=len(claim_ids), edges=e_pairs, directed=False)
        # collapse multi-edges by summing weights so parallel relationships
        # reinforce rather than spuriously inflate modularity
        g.es["weight"] = weights
        g = g.simplify(multiple=True, loops=True, combine_edges={"weight": "sum"})

        membership, modularity = run_leiden(g, g.es["weight"], args.algo)
        labels = build_labels(conn, claim_ids, membership)
        run_id = persist(
            conn,
            algorithm=args.algo,
            n_nodes=len(claim_ids),
            n_edges=g.ecount(),
            modularity=modularity,
            claim_ids=claim_ids,
            membership=membership,
            labels=labels,
            min_size=args.min_size,
        )
        print(f"\ndone. run_id = {run_id}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
