#!/usr/bin/env python3
"""UMAP-based claim clustering that writes into the current epigraph schema.

Phase 1 (seed):   Sample --sample-size atomic claims, fit UMAP(32) + k-means.
                  WIPE prior claim_themes + reset claims.theme_id.
                  Create k claim_themes rows with placeholder labels.
                  Persist fitted reducer, (k,32) centroids, and cluster→theme_id map
                  to --state-dir.

Phase 2 (assign): Load reducer/centroids/map from state-dir.
                  Batch over all current claims, UMAP transform into the FIXED
                  coordinate frame, pick nearest centroid — NEVER re-fit.
                  Bulk-UPDATE claims.theme_id.

Phase 3 (recompute): After all claims assigned, UPDATE claim_themes with
                     the 1536-dim mean of their members' embeddings (centroid
                     column read by GUI and naming script) and the final
                     claim_count.

Memory profile (ported from V2 cluster_claims.py):
  - UMAP reducer: ~620 MB RSS (stores 5K training set internally)
  - Per 50K batch: ~1.3 GB peak
  - Safe on 8 GB VM

Usage:
    # Full run (seed → assign → recompute)
    python3 scripts/cluster_themes.py --database-url $DATABASE_URL

    # Seed only (fit UMAP, pick k, create claim_themes rows, persist artifacts)
    python3 scripts/cluster_themes.py --seed-only

    # Assign only (load artifacts, bulk-update claims.theme_id)
    python3 scripts/cluster_themes.py --assign-only

Security note: the UMAP reducer is serialized via pickle to --state-dir/umap_reducer.pkl.
This file is written and read only by this script on the local machine. UMAP's internal
state (scipy sparse graphs, numpy arrays, pynndescent indices) cannot be serialized via
JSON. Do not load pickle files from untrusted sources.
"""

import argparse
import gc
import json
import os
import pickle  # Required for UMAP reducer — see security note in docstring
import sys

import numpy as np
import psycopg2
import psycopg2.extras
import umap
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import normalize

psycopg2.extras.register_uuid()

DEFAULT_STATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "theme_clustering"
)


# ── Helpers ──────────────────────────────────────────────────────────────

def state_paths(state_dir):
    return {
        "reducer": os.path.join(state_dir, "umap_reducer.pkl"),
        "centroids": os.path.join(state_dir, "centroids.npy"),
        "map": os.path.join(state_dir, "cluster_theme_map.json"),
    }


# ── Phase 1: Seed ────────────────────────────────────────────────────────

def sample_claims(conn, sample_size=50000, atomic_only=False):
    """Random-sample current claims with embeddings for the UMAP seed fit.

    Default: sample across ALL current+embedded claims so the centroids span
    the whole population we assign (composite claims included), not just the
    atomic-leaf manifold. `atomic_only=True` restores the V2 behaviour (seed
    from decomposes_to leaves only).

    Two-step on purpose: projecting embedding::text *through* ORDER BY random()
    forces Postgres to materialise every candidate embedding (~20 KB each) just
    to sort — minutes of CPU at corpus scale. Sorting bare IDs is seconds; we
    then fetch embeddings only for the chosen sample.
    """
    with conn.cursor() as cur:
        if atomic_only:
            # Leaf = decomposes_to points TO it but not OUT of it. DISTINCT so
            # claims with multiple parents aren't over-sampled.
            cur.execute("""
                SELECT id FROM (
                    SELECT DISTINCT c.id
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
                ) leaves
                ORDER BY random()
                LIMIT %s
            """, (sample_size,))
        else:
            cur.execute("""
                SELECT id
                FROM claims
                WHERE embedding IS NOT NULL AND is_current = true
                ORDER BY random()
                LIMIT %s
            """, (sample_size,))
        sampled_ids = [r[0] for r in cur.fetchall()]

        # Step 2: fetch embeddings only for the sampled IDs.
        cur.execute(
            "SELECT id::text, embedding::text FROM claims WHERE id = ANY(%s::uuid[])",
            (sampled_ids,),
        )
        rows = cur.fetchall()

    ids = [r[0] for r in rows]
    embs = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
    return ids, embs


def find_optimal_k(reduced, k_min=8, k_max=20):
    """Find optimal k via silhouette score on UMAP-reduced data (ported from V2)."""
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


def wipe_prior_themes(conn):
    """NULL out claims.theme_id, then DELETE all claim_themes rows."""
    with conn.cursor() as cur:
        cur.execute("UPDATE claims SET theme_id = NULL")
        cur.execute("DELETE FROM claim_themes")
    conn.commit()
    print("  Wiped prior themes.", file=sys.stderr)


def create_theme_rows(conn, k):
    """Insert k placeholder claim_themes rows; return cluster_theme_map {int_str: uuid_str}."""
    cluster_theme_map = {}
    with conn.cursor() as cur:
        for cluster_id in range(k):
            label = f"auto-{cluster_id:02d}"
            cur.execute(
                "INSERT INTO claim_themes (label, description, claim_count)"
                " VALUES (%s, '', 0) RETURNING id",
                (label,)
            )
            theme_uuid = str(cur.fetchone()[0])
            cluster_theme_map[str(cluster_id)] = theme_uuid
    conn.commit()
    print(f"  Created {k} claim_themes rows.", file=sys.stderr)
    return cluster_theme_map


def seed_phase(conn, sample_size, k_arg, state_dir, no_wipe, atomic_only, reproducible):
    """Fit UMAP reducer + k-means, create claim_themes rows, persist artifacts."""
    scope = "atomic-leaf" if atomic_only else "all current"
    print(f"Phase 1: Sampling {sample_size} {scope} claims...", file=sys.stderr)
    ids, embs = sample_claims(conn, sample_size, atomic_only=atomic_only)
    print(f"  Loaded {len(ids)} claims ({embs.nbytes / 1024 / 1024:.1f} MB)",
          file=sys.stderr)

    if len(ids) < 100:
        print(f"ERROR: Only {len(ids)} claims found — aborting.", file=sys.stderr)
        sys.exit(1)

    # Fit UMAP. random_state forces single-threaded (UMAP warns + sets n_jobs=1);
    # omitting it lets UMAP use all cores — much faster on large samples at the
    # cost of run-to-run reproducibility. `--reproducible` restores the seed.
    print(f"Fitting UMAP(32, cosine){' [reproducible/1-core]' if reproducible else ' [parallel]'}...",
          file=sys.stderr)
    umap_kwargs = dict(n_components=32, metric="cosine", n_neighbors=30, min_dist=0.0)
    if reproducible:
        umap_kwargs["random_state"] = 42
    reducer = umap.UMAP(**umap_kwargs)
    reduced = reducer.fit_transform(embs).astype(np.float32)
    reduced_norm = normalize(reduced, norm="l2")
    print("  UMAP fit complete.", file=sys.stderr)

    # Pick k
    if k_arg is not None:
        k = k_arg
        print(f"Using k={k} (forced via --k).", file=sys.stderr)
    else:
        print("Finding optimal k (silhouette search k=8..20)...", file=sys.stderr)
        k = find_optimal_k(reduced_norm)

    # Fit k-means on UMAP-reduced, L2-normalized data
    km = MiniBatchKMeans(n_clusters=k, n_init=5, random_state=42,
                         batch_size=min(1024, len(reduced_norm)))
    km.fit(reduced_norm)
    centroids = km.cluster_centers_.astype(np.float32)  # (k, 32)

    # Wipe + create DB rows
    if not no_wipe:
        wipe_prior_themes(conn)
    else:
        print("  --no-wipe: skipping prior theme deletion.", file=sys.stderr)

    cluster_theme_map = create_theme_rows(conn, k)

    # Persist artifacts
    os.makedirs(state_dir, exist_ok=True)
    paths = state_paths(state_dir)

    # Security: see module docstring about pickle trust boundary
    with open(paths["reducer"], "wb") as f:
        pickle.dump(reducer, f)
    print(f"  Saved reducer to {paths['reducer']} "
          f"({os.path.getsize(paths['reducer']) / 1024 / 1024:.1f} MB)",
          file=sys.stderr)

    np.save(paths["centroids"], centroids)
    print(f"  Saved centroids {centroids.shape} to {paths['centroids']}",
          file=sys.stderr)

    with open(paths["map"], "w") as f:
        json.dump(cluster_theme_map, f)
    print(f"  Saved cluster→theme map to {paths['map']}", file=sys.stderr)

    # Free large arrays
    del embs, reduced, reduced_norm
    gc.collect()

    return k, cluster_theme_map


# ── Phase 2: Assign ──────────────────────────────────────────────────────

def load_artifacts(state_dir):
    """Load reducer, centroids, and cluster_theme_map from state_dir."""
    paths = state_paths(state_dir)
    for name, path in paths.items():
        if not os.path.exists(path):
            print(f"ERROR: Missing artifact '{name}' at {path}. Run seed phase first.",
                  file=sys.stderr)
            sys.exit(1)

    # Security: see module docstring
    with open(paths["reducer"], "rb") as f:
        reducer = pickle.load(f)
    print(f"  Loaded reducer ({os.path.getsize(paths['reducer']) / 1024 / 1024:.1f} MB)",
          file=sys.stderr)

    centroids = np.load(paths["centroids"])
    print(f"  Loaded centroids {centroids.shape}", file=sys.stderr)

    with open(paths["map"]) as f:
        cluster_theme_map = json.load(f)
    print(f"  Loaded cluster→theme map ({len(cluster_theme_map)} entries)",
          file=sys.stderr)

    return reducer, centroids, cluster_theme_map


def assign_phase(conn, reducer, centroids, cluster_theme_map, batch_size=50000):
    """Transform all current claims into fixed UMAP space; bulk-UPDATE theme_id."""
    k = len(centroids)
    total = 0
    batch_num = 0

    while True:
        batch_num += 1
        print(f"\n  Batch {batch_num}: loading up to {batch_size} claims (offset={total})...",
              file=sys.stderr)

        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.id::text, c.embedding::text
                FROM claims c
                WHERE c.embedding IS NOT NULL
                  AND c.is_current = true
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

        # UMAP transform into FIXED coordinate space (never re-fit)
        print("  UMAP transforming...", file=sys.stderr)
        reduced = reducer.transform(embs).astype(np.float32)
        reduced_norm = normalize(reduced, norm="l2")
        del embs
        gc.collect()

        # Nearest centroid: (batch, k) distance matrix → argmin per row
        print(f"  Computing distances to {k} centroids...", file=sys.stderr)
        distances = np.linalg.norm(reduced_norm[:, None] - centroids[None, :], axis=2)
        nearest = np.argmin(distances, axis=1)
        del reduced, reduced_norm, distances
        gc.collect()

        # Bulk-UPDATE claims.theme_id
        print("  Writing theme_id to DB...", file=sys.stderr)
        with conn.cursor() as cur:
            psycopg2.extras.execute_batch(
                cur,
                "UPDATE claims SET theme_id = %s, updated_at = NOW() WHERE id = %s",
                [
                    (cluster_theme_map[str(int(nearest[i]))], claim_ids[i])
                    for i in range(len(claim_ids))
                ],
                page_size=1000,
            )
        conn.commit()

        del nearest, claim_ids
        gc.collect()

        total += len(rows)
        print(f"  Claims assigned so far: {total}", file=sys.stderr)

    return total


# ── Phase 3: Recompute 1536-dim centroids + counts ───────────────────────

def recompute_phase(conn):
    """Set claim_themes.centroid = mean(member embeddings) and claim_count."""
    print("\nPhase 3: Recomputing 1536-dim centroids and claim counts...",
          file=sys.stderr)

    with conn.cursor() as cur:
        cur.execute("""
            UPDATE claim_themes ct SET
              centroid = (
                  SELECT avg(c.embedding)::vector(1536)
                  FROM claims c
                  WHERE c.theme_id = ct.id AND c.embedding IS NOT NULL
              ),
              claim_count = (
                  SELECT count(*) FROM claims c WHERE c.theme_id = ct.id
              ),
              updated_at = NOW()
        """)
        cur.execute("""
            SELECT ct.id, ct.label, ct.claim_count
            FROM claim_themes ct
            ORDER BY ct.claim_count DESC
        """)
        rows = cur.fetchall()
    conn.commit()

    themes = []
    for tid, label, count in rows:
        themes.append({"id": str(tid), "label": label, "claim_count": count})
        print(f"  {label}: {count} claims", file=sys.stderr)

    return themes


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UMAP-based claim clustering → claim_themes + claims.theme_id")
    parser.add_argument("--database-url",
                        default=os.environ.get("DATABASE_URL"),
                        help="PostgreSQL DSN (or set DATABASE_URL env var)")
    parser.add_argument("--sample-size", type=int, default=50000,
                        help="Seed sample size for UMAP fit (default 50000)")
    parser.add_argument("--atomic-only", action="store_true",
                        help="Seed only from decomposes_to leaf claims (V2 behaviour); "
                             "default samples across ALL current+embedded claims")
    parser.add_argument("--reproducible", action="store_true",
                        help="Force UMAP random_state=42 (single-threaded, reproducible); "
                             "default omits the seed to use all cores")
    parser.add_argument("--batch-size", type=int, default=50000,
                        help="Claims per assign batch (default 50000)")
    parser.add_argument("--k", type=int, default=None,
                        help="Force k; omit to auto-select via silhouette (8-20)")
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR,
                        help="Directory for persisted artifacts")
    parser.add_argument("--seed-only", action="store_true",
                        help="Only run Phase 1 (fit + persist)")
    parser.add_argument("--assign-only", action="store_true",
                        help="Only run Phase 2 (load + assign)")
    parser.add_argument("--no-wipe", action="store_true",
                        help="Skip wiping prior claim_themes during seed phase")
    args = parser.parse_args()

    if not args.database_url:
        print("ERROR: --database-url or DATABASE_URL env var required", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(args.database_url)

    # ── Phase 1 ──────────────────────────────────────────────────────────
    if not args.assign_only:
        k, cluster_theme_map = seed_phase(
            conn,
            sample_size=args.sample_size,
            k_arg=args.k,
            state_dir=args.state_dir,
            no_wipe=args.no_wipe,
            atomic_only=args.atomic_only,
            reproducible=args.reproducible,
        )

        if args.seed_only:
            print(json.dumps({
                "status": "seeded",
                "k": k,
                "state_dir": args.state_dir,
                "themes": list(cluster_theme_map.values()),
            }, indent=2))
            conn.close()
            return
    else:
        print("Loading artifacts for assign-only run...", file=sys.stderr)
        reducer, centroids, cluster_theme_map = load_artifacts(args.state_dir)
        k = len(centroids)

    # ── Phase 2 ──────────────────────────────────────────────────────────
    if not args.seed_only:
        print(f"\nPhase 2: Assigning all claims "
              f"(k={k}, batch_size={args.batch_size})...", file=sys.stderr)

        # For assign-only we already loaded artifacts above; for full run load them
        if not args.assign_only:
            reducer, centroids, _ = load_artifacts(args.state_dir)

        total = assign_phase(conn, reducer, centroids, cluster_theme_map,
                             batch_size=args.batch_size)

        # ── Phase 3 ──────────────────────────────────────────────────────
        themes = recompute_phase(conn)

        print(json.dumps({
            "status": "complete",
            "k": k,
            "claims_assigned": total,
            "themes": themes,
        }, indent=2))

    conn.close()


if __name__ == "__main__":
    main()
