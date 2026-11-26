#!/usr/bin/env python3
"""UMAP-based claim clustering with full centroid distance coordinate frame.

Ported from EpigraphV2/scripts/cluster_claims.py. Cold-start clustering
pipeline — fits UMAP+k-means on a sample of atomic claims, persists the
fitted reducer to data/umap_reducer.pkl, then assigns every claim a
position in the resulting coordinate frame. The maintain_themes.py loop
replaces most of this for ongoing maintenance; cluster_claims is needed
when a fresh DB has no cluster_centroids rows or when you want to
rebuild the coordinate frame from scratch.

Phase 1 (seed): Sample 5K atomic claims, fit UMAP(32) + k-means(12).
                Store centroids in cluster_centroids.umap_centroid
                (vector(32), migration 222).
                Persist fitted UMAP reducer to disk for future transforms.

Phase 2 (assign): Load all claims in batches of --batch-size (default 100K),
                  UMAP transform using fitted reducer, compute distances to
                  all centroids, store in claim_clusters.
                  Each claim gets a k-dimensional coordinate vector.

Phase 3 (discover): After assignment, find claims far from all centroids.
                    These are candidates for new clusters in unexplored
                    manifold regions.

Memory profile:
  - UMAP reducer: ~620MB RSS (stores 5K training set internally)
  - Per batch: ~3.3x input size (~2GB at 100K batch)
  - Peak at 100K batch: ~2.6GB
  - Safe on 8GB VM with 4.4GB available

Usage:
    # Full run: seed + assign all claims (requires admin DB role for writes)
    DATABASE_URL=postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph \\
        python3 scripts/cluster_claims.py

    # Seed only
    python3 scripts/cluster_claims.py --seed-only

    # Assign only (reuse persisted UMAP reducer + centroids)
    python3 scripts/cluster_claims.py --assign-only

    # Discover new cluster candidates
    python3 scripts/cluster_claims.py --discover-only

Security note: the UMAP reducer is serialized via pickle to data/umap_reducer.pkl.
This file is written and read only by this script on the local machine. UMAP's
internal state (scipy sparse graphs, numpy arrays, pynndescent indices) cannot
be serialized via JSON. Do not load pickle files from untrusted sources.
"""

import argparse
import gc
import json
import math
import os
import pickle  # Required for UMAP reducer — see security note in docstring
import sys
import uuid

import numpy as np
import psycopg2
import psycopg2.extras
import umap
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import normalize

import theme_lib  # noqa: E402  (scripts/ is on sys.path when run as a script)
from maintenance_dsn import maintenance_dsn  # noqa: E402  (same sys.path assumption)

psycopg2.extras.register_uuid()

REDUCER_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "umap_reducer.pkl")
UMAP_DIM = 32  # n_components of the UMAP fit; cluster_centroids.umap_centroid is vector(32)


# ── Phase 1: Seed ───────────────────────────────────────────────────────

def sample_atomic_claims(conn, sample_size=5000):
    """Sample atomic claims (leaf nodes) with embeddings."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.id::text, c.embedding::text
            FROM claims c
            JOIN edges e ON e.target_id = c.id
                AND e.relationship = 'decomposes_to'
                AND e.source_type = 'claim' AND e.target_type = 'claim'
            WHERE c.embedding IS NOT NULL
              AND c.is_current = true
              AND NOT EXISTS (
                  SELECT 1 FROM edges e2
                  WHERE e2.source_id = c.id AND e2.relationship = 'decomposes_to'
                    AND e2.source_type = 'claim'
              )
            ORDER BY random()
            LIMIT %s
        """, (sample_size,))
        rows = cur.fetchall()

    ids = [r[0] for r in rows]
    embs = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
    return ids, embs


def sample_all_claims(conn, sample_size=5000):
    """Sample across ALL current+embedded claims (composites included)."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.id::text, c.embedding::text
            FROM claims c
            WHERE c.embedding IS NOT NULL AND c.is_current = true
            ORDER BY random() LIMIT %s
        """, (sample_size,))
        rows = cur.fetchall()
    ids = [r[0] for r in rows]
    embs = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
    return ids, embs


def find_optimal_k(reduced, k_min=8, k_max=20):
    """Find optimal k via silhouette on UMAP-reduced data."""
    n = len(reduced)
    sub_idx = np.random.RandomState(42).choice(n, min(3000, n), replace=False)
    sub = reduced[sub_idx]

    best_k, best_score = k_min, -1.0
    for k in range(k_min, k_max + 1):
        km = MiniBatchKMeans(n_clusters=k, n_init=5, random_state=42,
                             batch_size=min(1024, len(sub)))
        labels = km.fit_predict(sub)
        score = silhouette_score(sub, labels, sample_size=min(1000, len(sub)))
        print(f"  k={k}: silhouette={score:.4f}", file=sys.stderr)
        if score > best_score:
            best_score = score
            best_k = k

    print(f"  Best k={best_k} (silhouette={best_score:.4f})", file=sys.stderr)
    return best_k


def seed_phase(conn, sample_size, k, run_id, all_claims=False):
    """Fit UMAP reducer and k-means centroids from a sample."""
    scope = "all" if all_claims else "atomic"
    print(f"Phase 1: Sampling {sample_size} {scope} claims...", file=sys.stderr)
    ids, embs = (sample_all_claims if all_claims else sample_atomic_claims)(conn, sample_size)
    print(f"  Loaded {len(ids)} claims ({embs.nbytes / 1024 / 1024:.1f} MB)", file=sys.stderr)

    if len(ids) < 100:
        print(f"Only {len(ids)} claims, aborting", file=sys.stderr)
        sys.exit(1)

    # Fit UMAP
    print("Fitting UMAP(32, cosine)...", file=sys.stderr)
    reducer = umap.UMAP(n_components=UMAP_DIM, metric="cosine", n_neighbors=30,
                        min_dist=0.0, random_state=42)
    reduced = reducer.fit_transform(embs).astype(np.float32)
    reduced_norm = normalize(reduced, norm="l2")
    print(f"  UMAP fit complete", file=sys.stderr)

    # Find k
    if k is None:
        print("Finding optimal k...", file=sys.stderr)
        k = find_optimal_k(reduced_norm)
    else:
        print(f"Using k={k}", file=sys.stderr)

    # Fit k-means on UMAP-reduced data
    km = MiniBatchKMeans(n_clusters=k, n_init=5, random_state=42,
                         batch_size=min(1024, len(reduced_norm)))
    km.fit(reduced_norm)
    centroids = km.cluster_centers_  # (k, 32) in UMAP space

    # Persist reducer to disk (see security note in module docstring)
    os.makedirs(os.path.dirname(REDUCER_PATH), exist_ok=True)
    with open(REDUCER_PATH, "wb") as f:
        pickle.dump(reducer, f)
    print(f"  Saved UMAP reducer to {REDUCER_PATH} "
          f"({os.path.getsize(REDUCER_PATH) / 1024 / 1024:.1f} MB)", file=sys.stderr)

    store_centroids(conn, run_id, centroids)
    print(f"  Stored {k} centroids (run_id={run_id})", file=sys.stderr)

    # Label clusters
    label_clusters(conn, ids, reduced_norm, km.labels_, centroids, k, run_id)

    # Free the large embedding matrix
    del embs, reduced
    gc.collect()

    return reducer, centroids, k


def store_centroids(conn, run_id, centroids):
    """Store the (k, UMAP_DIM) k-means centroids of `run_id` in
    cluster_centroids.umap_centroid (vector(32), migration 222), one row per
    cluster id. The legacy zero-padded `centroid` column is cleared, so a
    pre-222 row re-seeded under the same run keeps no stale padded copy for
    docs/runbooks/222-undo.sql (which re-pads only NULL rows) to resurrect."""
    centroids = np.asarray(centroids, dtype=np.float32)
    if centroids.ndim != 2 or centroids.shape[1] != UMAP_DIM:
        raise ValueError(f"expected (k, {UMAP_DIM}) centroids, got {centroids.shape}")
    with conn.cursor() as cur:
        for cluster_id, centroid in enumerate(centroids):
            cur.execute("""
                INSERT INTO cluster_centroids
                    (cluster_run_id, cluster_id, umap_centroid, claim_count)
                VALUES (%s, %s, %s::vector, 0)
                ON CONFLICT (cluster_run_id, cluster_id) DO UPDATE SET
                    umap_centroid = EXCLUDED.umap_centroid,
                    centroid = NULL
            """, (run_id, cluster_id, json.dumps(centroid.tolist())))
    conn.commit()


def label_clusters(conn, ids, reduced, labels, centroids, k, run_id):
    """Label clusters by nearest claims' content."""
    distances = np.linalg.norm(reduced[:, None] - centroids[None, :], axis=2)
    with conn.cursor() as cur:
        for cluster_id in range(k):
            mask = labels == cluster_id
            if not mask.any():
                continue
            cluster_indices = np.where(mask)[0]
            cluster_dists = distances[cluster_indices, cluster_id]
            nearest_idx = cluster_indices[np.argsort(cluster_dists)[:5]]
            nearest_ids = [ids[i] for i in nearest_idx]

            # Public members' text only: the label is shown to every viewer
            # of any member (theme_lib.public_label_source).
            cur.execute(
                "SELECT substring(c.content for 100) FROM claims c "
                "WHERE c.id = ANY(%s::uuid[]) AND " + theme_lib.public_label_source("c"),
                (nearest_ids,))
            texts = [r[0] for r in cur.fetchall()]
            label = "; ".join(texts)
            size = int(mask.sum())

            cur.execute("""
                INSERT INTO cluster_labels (cluster_run_id, cluster_id, label, sample_count)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cluster_run_id, cluster_id) DO UPDATE SET
                    label = EXCLUDED.label, sample_count = EXCLUDED.sample_count
            """, (run_id, cluster_id, label, size))
    conn.commit()


# ── Phase 2: Assign ─────────────────────────────────────────────────────

def load_reducer():
    """Load persisted UMAP reducer from disk."""
    if not os.path.exists(REDUCER_PATH):
        print(f"ERROR: No UMAP reducer at {REDUCER_PATH}. Run seed phase first.",
              file=sys.stderr)
        sys.exit(1)
    # Security: this pickle is written by this script only — see module docstring
    with open(REDUCER_PATH, "rb") as f:
        reducer = pickle.load(f)
    print(f"  Loaded UMAP reducer ({os.path.getsize(REDUCER_PATH) / 1024 / 1024:.1f} MB)",
          file=sys.stderr)
    return reducer


def load_centroids_from_db(conn, run_id=None):
    """Load a run's (k, UMAP_DIM) UMAP centroids from
    cluster_centroids.umap_centroid (migration 222; it backfilled pre-222
    padded rows). Exits on a run with a row 222 could not backfill (its
    legacy `centroid` had a non-zero tail, so it is no padded UMAP centroid).

    Returns (centroids, run_id, cluster_ids): row i of `centroids` is the
    centroid of cluster `cluster_ids[i]`. The ids need not be 0..k-1: a seal
    deletes the centroid of a cluster whose members are all sealed (backlog
    06cdffaa), so a run can have gaps, and `assign_batch` must write the
    stored id, never the row position.
    """
    with conn.cursor() as cur:
        if run_id:
            cur.execute("""
                SELECT cluster_id, umap_centroid::text, cluster_run_id::text
                FROM cluster_centroids WHERE cluster_run_id = %s
                ORDER BY cluster_id
            """, (run_id,))
        else:
            cur.execute("""
                SELECT cluster_id, umap_centroid::text, cluster_run_id::text
                FROM cluster_centroids
                WHERE cluster_run_id = (
                    SELECT cluster_run_id FROM cluster_centroids
                    ORDER BY created_at DESC LIMIT 1
                )
                ORDER BY cluster_id
            """)
        rows = cur.fetchall()

    if not rows:
        print("ERROR: No centroids found in DB.", file=sys.stderr)
        sys.exit(1)

    actual_run_id = rows[0][2]
    missing = [r[0] for r in rows if r[1] is None]
    if missing:
        print(f"ERROR: run {actual_run_id} has no umap_centroid for cluster(s) {missing} "
              f"(migration 222 backfills only zero-padded 32-d centroids); re-seed the run.",
              file=sys.stderr)
        sys.exit(1)
    centroids = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
    cluster_ids = [int(r[0]) for r in rows]
    print(f"  Loaded {len(centroids)} centroids (run_id={actual_run_id})", file=sys.stderr)
    return centroids, actual_run_id, cluster_ids


def nearest_two(dists, cluster_ids):
    """One claim's assignment from its distances to a run's centroids, where
    `dists[i]` is the distance to the centroid of cluster `cluster_ids[i]`:
    (nearest cluster id, its distance, the second-nearest distance). The
    position of the nearest centroid is translated to its stored cluster id,
    which differs from the position once a cluster of the run was deleted.
    With one centroid left the second distance is the nearest one."""
    order = np.argsort(dists)
    nearest = int(order[0])
    second = float(dists[order[1]]) if len(order) > 1 else float(dists[nearest])
    return int(cluster_ids[nearest]), float(dists[nearest]), second


def distances_by_cluster_id(dists, cluster_ids):
    """`claim_clusters.centroid_distances` indexed by cluster id: entry c is
    the distance to cluster c's centroid, NULL for an id the run has no
    centroid for (a deleted cluster)."""
    full = [None] * (max(cluster_ids) + 1)
    for cid, d in zip(cluster_ids, dists):
        full[int(cid)] = float(d)
    return full


def assign_batch(conn, reducer, centroids, run_id, batch_size=100000,
                 resume=False, cluster_ids=None):
    """Stream claims, UMAP transform, compute all centroid distances, store.
    `cluster_ids[i]` is the cluster id of `centroids[i]` (default 0..k-1, a
    freshly seeded run); pass `load_centroids_from_db`'s ids for a stored run."""
    k = len(centroids)
    if cluster_ids is None:
        cluster_ids = list(range(k))
    if len(cluster_ids) != k:
        raise ValueError(f"{len(cluster_ids)} cluster ids for {k} centroids")
    total = 0
    batch_num = 0

    while True:
        batch_num += 1
        print(f"\n  Batch {batch_num}: loading up to {batch_size} claims...", file=sys.stderr)

        with conn.cursor() as cur:
            if resume:
                cur.execute("""
                    SELECT c.id::text, c.embedding::text
                    FROM claims c
                    WHERE c.embedding IS NOT NULL
                      AND c.id NOT IN (
                          SELECT claim_id FROM claim_clusters
                          WHERE cluster_run_id = %s
                      )
                    ORDER BY c.id
                    LIMIT %s
                """, (run_id, batch_size))
            else:
                cur.execute("""
                    SELECT c.id::text, c.embedding::text
                    FROM claims c
                    WHERE c.embedding IS NOT NULL
                    ORDER BY c.id
                    LIMIT %s OFFSET %s
                """, (batch_size, total))
            rows = cur.fetchall()

        if not rows:
            break

        claim_ids = [r[0] for r in rows]
        embs = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
        print(f"  Loaded {len(claim_ids)} claims ({embs.nbytes / 1024 / 1024:.0f} MB)",
              file=sys.stderr)

        # UMAP transform
        print(f"  UMAP transforming...", file=sys.stderr)
        reduced = reducer.transform(embs).astype(np.float32)
        reduced_norm = normalize(reduced, norm="l2")
        del embs
        gc.collect()

        # Distances to ALL centroids: (batch, k)
        print(f"  Computing distances to {k} centroids...", file=sys.stderr)
        distances = np.linalg.norm(reduced_norm[:, None] - centroids[None, :], axis=2)
        del reduced, reduced_norm
        gc.collect()

        # Store
        print(f"  Writing to DB...", file=sys.stderr)
        with conn.cursor() as cur:
            batch_data = []
            for i, cid in enumerate(claim_ids):
                dists = distances[i]
                nearest, nearest_dist, second_dist = nearest_two(dists, cluster_ids)
                boundary = nearest_dist / second_dist if second_dist > 0 else 0.0
                sil_approx = 1.0 - boundary

                batch_data.append((
                    cid, nearest, nearest_dist, second_dist, boundary,
                    sil_approx, run_id, distances_by_cluster_id(dists, cluster_ids)
                ))

            psycopg2.extras.execute_batch(cur, """
                INSERT INTO claim_clusters
                    (claim_id, cluster_id, centroid_distance, second_centroid_dist,
                     boundary_ratio, silhouette_score, cluster_run_id, centroid_distances)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (claim_id) DO UPDATE SET
                    cluster_id = EXCLUDED.cluster_id,
                    centroid_distance = EXCLUDED.centroid_distance,
                    second_centroid_dist = EXCLUDED.second_centroid_dist,
                    boundary_ratio = EXCLUDED.boundary_ratio,
                    silhouette_score = EXCLUDED.silhouette_score,
                    cluster_run_id = EXCLUDED.cluster_run_id,
                    centroid_distances = EXCLUDED.centroid_distances,
                    computed_at = NOW()
            """, batch_data, page_size=1000)
        conn.commit()
        del distances, batch_data
        gc.collect()

        total += len(claim_ids)
        print(f"  Total assigned: {total}", file=sys.stderr)

    # Update counts
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE cluster_labels cl SET sample_count = sub.n
            FROM (SELECT cluster_id, count(*) as n FROM claim_clusters
                  WHERE cluster_run_id = %s GROUP BY cluster_id) sub
            WHERE cl.cluster_run_id = %s AND cl.cluster_id = sub.cluster_id
        """, (run_id, run_id))
        cur.execute("""
            UPDATE cluster_centroids cc SET claim_count = sub.n
            FROM (SELECT cluster_id, count(*) as n FROM claim_clusters
                  WHERE cluster_run_id = %s GROUP BY cluster_id) sub
            WHERE cc.cluster_run_id = %s AND cc.cluster_id = sub.cluster_id
        """, (run_id, run_id))
    conn.commit()

    return total


# ── Phase 3: Discover ───────────────────────────────────────────────────

def discover_new_clusters(conn, run_id, percentile=95, min_cluster_size=20):
    """Find claims far from all centroids — candidates for new clusters."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT percentile_cont(%s / 100.0) WITHIN GROUP (ORDER BY centroid_distance)
            FROM claim_clusters WHERE cluster_run_id = %s
        """, (percentile, run_id))
        threshold = cur.fetchone()[0]

        cur.execute("""
            SELECT count(*) FROM claim_clusters
            WHERE cluster_run_id = %s AND centroid_distance > %s
        """, (run_id, threshold))
        outlier_count = cur.fetchone()[0]

        cur.execute("""
            SELECT cluster_id, count(*), round(avg(centroid_distance)::numeric, 4)
            FROM claim_clusters
            WHERE cluster_run_id = %s AND centroid_distance > %s
            GROUP BY cluster_id ORDER BY count DESC
        """, (run_id, threshold))
        outlier_dist = cur.fetchall()

    print(f"\nPhase 3: New cluster discovery", file=sys.stderr)
    print(f"  Distance threshold (p{percentile}): {threshold:.4f}", file=sys.stderr)
    print(f"  Outlier claims (above threshold): {outlier_count}", file=sys.stderr)
    print(f"  Distribution by current cluster:", file=sys.stderr)
    for cid, count, avg_dist in outlier_dist:
        print(f"    Cluster {cid}: {count} outliers (avg_dist={avg_dist})", file=sys.stderr)

    return {
        "threshold": float(threshold),
        "outlier_count": outlier_count,
        "outlier_distribution": [
            {"cluster_id": c, "count": n, "avg_distance": float(d)}
            for c, n, d in outlier_dist
        ],
    }


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UMAP-based claim clustering with coordinate frame")
    parser.add_argument(
        "--database-url",
        default=None,
        help="Postgres URL (default: $MAINTENANCE_DATABASE_URL, then $DATABASE_URL; no built-in default)",
    )
    parser.add_argument("--sample-size", type=int, default=5000)
    parser.add_argument("--batch-size", type=int, default=100000)
    parser.add_argument("--k", type=int, default=None,
                        help="Force k (default: auto via silhouette, typically 12)")
    parser.add_argument("--seed-only", action="store_true")
    parser.add_argument("--assign-only", action="store_true")
    parser.add_argument("--discover-only", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--run-id", type=str, default=None)
    parser.add_argument("--all-claims", action="store_true",
                        help="Seed from all current claims (default: atomic leaves only)")
    args = parser.parse_args()
    # No built-in default (backlog 62bdae04): with no flag and no
    # environment, maintenance_dsn() refuses instead of reaching a live database.
    args.database_url = args.database_url or maintenance_dsn()

    conn = psycopg2.connect(args.database_url)
    theme_lib.set_statement_timeout(conn, ms=900000)  # 15 min ceiling per statement
    run_id = args.run_id or str(uuid.uuid4())

    if args.discover_only:
        _, run_id, _ = load_centroids_from_db(conn, args.run_id)
        discovery = discover_new_clusters(conn, run_id)
        print(json.dumps({"status": "discovery_complete", **discovery}, indent=2))
        conn.close()
        return

    if not args.assign_only:
        # Phase 1
        reducer, centroids, k = seed_phase(conn, args.sample_size, args.k, run_id,
                                           all_claims=args.all_claims)
        cluster_ids = None  # a fresh seed: ids 0..k-1

        if args.seed_only:
            print(json.dumps({"status": "seeded", "run_id": run_id, "k": k}))
            conn.close()
            return
    else:
        # Load existing
        print("Loading existing reducer and centroids...", file=sys.stderr)
        reducer = load_reducer()
        centroids, run_id, cluster_ids = load_centroids_from_db(conn, args.run_id)

    # Phase 2
    k = len(centroids)
    print(f"\nPhase 2: Assigning all claims ({k} centroids, "
          f"batch_size={args.batch_size})...", file=sys.stderr)
    total = assign_batch(conn, reducer, centroids, run_id,
                         batch_size=args.batch_size, resume=args.resume,
                         cluster_ids=cluster_ids)

    # Phase 3
    discovery = discover_new_clusters(conn, run_id)

    result = {
        "status": "complete",
        "run_id": run_id,
        "k": k,
        "claims_assigned": total,
        "discovery": discovery,
    }
    print(json.dumps(result, indent=2))
    conn.close()


if __name__ == "__main__":
    main()
