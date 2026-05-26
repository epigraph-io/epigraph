#!/usr/bin/env python3
"""Sub-cluster outlier-heavy UMAP clusters to find missing themes.

Ported from EpigraphV2/scripts/subcluster_outliers.py. Read-only analysis:
takes the boundary claims (high boundary_ratio + high centroid_distance)
from specified `claim_clusters` cluster_ids, runs UMAP+k-means on their
embeddings to find sub-structure, and prints a report. Doesn't write
back — operator decides whether the surfaced sub-clusters warrant new
theme creation via `POST /api/v1/themes/create-with-centroid`.

Adaptation vs V2:
- Default DATABASE_URL uses `epigraph_ro` (script never writes)
- No other behavioral changes; UMAP + k-means logic preserved

Usage:
    DATABASE_URL=postgres://epigraph_ro:epigraph_ro@localhost:5432/epigraph \\
        python3 scripts/subcluster_outliers.py --clusters 0,3,6 --sample-size 3000
"""

import argparse
import json
import os
import sys

import numpy as np
import psycopg2
import psycopg2.extras
import umap
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import normalize

psycopg2.extras.register_uuid()

DEFAULT_DATABASE_URL = "postgres://epigraph_ro:epigraph_ro@localhost:5432/epigraph"


def load_boundary_claims(conn, cluster_ids, boundary_threshold=0.85,
                         distance_percentile=90, sample_size=3000):
    """Load boundary claims from specified clusters."""
    with conn.cursor() as cur:
        # Get the distance threshold
        cur.execute("""
            SELECT percentile_cont(%s / 100.0) WITHIN GROUP (ORDER BY centroid_distance)
            FROM claim_clusters
        """, (distance_percentile,))
        dist_threshold = cur.fetchone()[0]

        cur.execute("""
            SELECT cc.claim_id::text, c.embedding::text, cc.cluster_id,
                   cc.boundary_ratio, cc.centroid_distance,
                   LEFT(c.content, 200) as content,
                   ct.label as current_theme
            FROM claim_clusters cc
            JOIN claims c ON c.id = cc.claim_id
            LEFT JOIN claim_themes ct ON c.theme_id = ct.id
            WHERE cc.cluster_id = ANY(%s)
              AND cc.boundary_ratio >= %s
              AND cc.centroid_distance >= %s
              AND c.embedding IS NOT NULL
            ORDER BY random()
            LIMIT %s
        """, (cluster_ids, boundary_threshold, dist_threshold, sample_size))
        rows = cur.fetchall()

    ids = [r[0] for r in rows]
    embs = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
    meta = [{"cluster": r[2], "boundary": float(r[3]), "dist": float(r[4]),
             "content": r[5], "theme": r[6] or "<unthemed>"} for r in rows]
    return ids, embs, meta


def find_subclusters(embs, k_min=3, k_max=12):
    """UMAP reduce + k-means with silhouette optimization."""
    print(f"  UMAP(16) on {len(embs)} claims...", file=sys.stderr)
    reducer = umap.UMAP(n_components=16, metric="cosine", n_neighbors=15,
                        min_dist=0.0, random_state=42)
    reduced = reducer.fit_transform(embs).astype(np.float32)
    reduced_norm = normalize(reduced, norm="l2")

    best_k, best_score = k_min, -1.0
    for k in range(k_min, k_max + 1):
        km = MiniBatchKMeans(n_clusters=k, n_init=5, random_state=42,
                             batch_size=min(512, len(reduced_norm)))
        labels = km.fit_predict(reduced_norm)
        score = silhouette_score(reduced_norm, labels,
                                 sample_size=min(1000, len(reduced_norm)))
        print(f"    k={k}: silhouette={score:.4f}", file=sys.stderr)
        if score > best_score:
            best_score = score
            best_k = k

    print(f"  Best k={best_k} (silhouette={best_score:.4f})", file=sys.stderr)

    km = MiniBatchKMeans(n_clusters=best_k, n_init=5, random_state=42,
                         batch_size=min(512, len(reduced_norm)))
    labels = km.fit_predict(reduced_norm)
    return labels, best_k, best_score


def analyze_subclusters(ids, labels, meta, k):
    """Analyze what each subcluster contains."""
    from collections import Counter, defaultdict

    subclusters = defaultdict(list)
    for i, label in enumerate(labels):
        subclusters[label].append(i)

    results = []
    for sc_id in range(k):
        indices = subclusters[sc_id]
        size = len(indices)

        # Theme distribution
        themes = Counter(meta[i]["theme"] for i in indices)
        top_themes = themes.most_common(3)

        # Sample claims
        sample_idx = indices[:8]
        samples = [meta[i]["content"][:150] for i in sample_idx]

        # Source cluster distribution
        clusters = Counter(meta[i]["cluster"] for i in indices)

        results.append({
            "subcluster": sc_id,
            "size": size,
            "top_themes": [{"theme": t, "count": c} for t, c in top_themes],
            "source_clusters": dict(clusters),
            "avg_boundary": round(float(np.mean([meta[i]["boundary"] for i in indices])), 3),
            "samples": samples,
        })

    results.sort(key=lambda x: -x["size"])
    return results


def main():
    parser = argparse.ArgumentParser(description="Sub-cluster outlier-heavy UMAP clusters")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
        help=f"Postgres URL (default: {DEFAULT_DATABASE_URL})",
    )
    parser.add_argument("--clusters", default="0,3,6",
                        help="Comma-separated cluster IDs to sub-cluster")
    parser.add_argument("--sample-size", type=int, default=3000)
    parser.add_argument("--boundary-threshold", type=float, default=0.85)
    parser.add_argument("--distance-percentile", type=float, default=85)
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    cluster_ids = [int(x) for x in args.clusters.split(",")]

    print(f"Loading boundary claims from clusters {cluster_ids}...", file=sys.stderr)
    ids, embs, meta = load_boundary_claims(
        conn, cluster_ids,
        boundary_threshold=args.boundary_threshold,
        distance_percentile=args.distance_percentile,
        sample_size=args.sample_size,
    )
    conn.close()

    print(f"  {len(ids)} boundary claims loaded ({embs.nbytes / 1024 / 1024:.1f} MB)",
          file=sys.stderr)

    if len(ids) < 20:
        print("Not enough boundary claims to sub-cluster", file=sys.stderr)
        sys.exit(1)

    print("\nFinding sub-clusters...", file=sys.stderr)
    labels, k, score = find_subclusters(embs)

    print(f"\nAnalyzing {k} sub-clusters...\n", file=sys.stderr)
    results = analyze_subclusters(ids, labels, meta, k)

    for sc in results:
        print(f"{'='*80}", file=sys.stderr)
        print(f"Sub-cluster {sc['subcluster']}: {sc['size']} claims "
              f"(avg boundary={sc['avg_boundary']})", file=sys.stderr)
        print(f"  Source clusters: {sc['source_clusters']}", file=sys.stderr)
        print(f"  Top themes:", file=sys.stderr)
        for t in sc["top_themes"]:
            print(f"    {t['count']:4d}  {t['theme']}", file=sys.stderr)
        print(f"  Sample claims:", file=sys.stderr)
        for s in sc["samples"][:5]:
            print(f"    - {s}", file=sys.stderr)
        print(file=sys.stderr)

    print(json.dumps({"k": k, "silhouette": score, "subclusters": results}, indent=2))


if __name__ == "__main__":
    main()
