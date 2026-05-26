#!/usr/bin/env python3
"""Evidential clustering using Dempster-Shafer mass functions.

Ported from EpigraphV2/scripts/evidential_clustering.py — RESEARCH script,
not part of the production maintain_themes loop. Uses compound claim
structure: atomic claims inherit their parent's proto-cluster, siblings
share assignment, cross-parent edges (CORROBORATES, same_as, contradicts)
merge or split proto-clusters. Output lands in `claim_clusters` +
`cluster_labels` (read by the diverse-select retrieval path).

Why "research": DST combination over claim parentage + graph edges as a
clustering signal may produce better centroids than pure-embedding
k-means for stance-sensitive domains, but the algorithmic choices
(initial_k, iteration count, evidence weights) aren't yet operator-
validated. Run alongside `maintain_themes.py`, not as a replacement.

Direct DB INSERT — `epigraph_admin` role required; no API endpoint for
bulk cluster writes exists. Permitted per CLAUDE.md's "operations not
yet exposed via API" carve-out.

Usage:
    DATABASE_URL=postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph \\
        python3 scripts/evidential_clustering.py --limit 500
    # With agent filter:
    python3 scripts/evidential_clustering.py --limit 500 --agent-filter 'textbook-extractor:%'
"""

DEFAULT_DATABASE_URL = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph"

import argparse
import json
import math
import os
import sys
import uuid
from collections import defaultdict

import numpy as np
import psycopg2
import psycopg2.extras
from sklearn.cluster import MiniBatchKMeans

psycopg2.extras.register_uuid()


# ── Mass function operations ─────────────────────────────────────────────

def combine_two(m1: dict, m2: dict) -> tuple[dict, float]:
    """Dempster's rule of combination."""
    combined = defaultdict(float)
    conflict = 0.0
    for a, ma in m1.items():
        for b, mb in m2.items():
            intersection = a & b
            product = ma * mb
            if not intersection:
                conflict += product
            else:
                combined[intersection] += product
    if conflict >= 0.999:
        theta = max(m1.keys() | m2.keys(), key=len)
        return {theta: 1.0}, 1.0
    norm = 1.0 / (1.0 - conflict)
    return {k: v * norm for k, v in combined.items() if v * norm > 0.001}, conflict


def combine_all(masses: list[dict]) -> tuple[dict, float]:
    """Combine multiple mass functions. Returns (combined, max_K)."""
    if not masses:
        return {}, 0.0
    result = masses[0]
    max_k = 0.0
    for m in masses[1:]:
        result, k = combine_two(result, m)
        max_k = max(max_k, k)
    return result, max_k


def belief_plausibility(mass: dict, h: frozenset) -> tuple[float, float]:
    bel = sum(m for k, m in mass.items() if k <= h)
    pl = sum(m for k, m in mass.items() if k & h)
    return bel, pl


# ── Data loading ─────────────────────────────────────────────────────────

def load_atomic_with_parents(conn, limit=500, agent_filter=None):
    """Load atomic claims with their parent compound claims.

    Returns:
        atoms: list of (id, embedding)
        parent_map: {atomic_id → parent_id}
        parent_embeddings: {parent_id → embedding}
        sibling_groups: {parent_id → [atomic_id, ...]}
        cross_parent_edges: [(parent_a, parent_b, relationship)]
    """
    where = ""
    if agent_filter:
        where = f"AND c.agent_id IN (SELECT id FROM agents WHERE display_name LIKE '{agent_filter}')"

    # Sample ALL children from a set of rich parents (dense sibling groups).
    # Pick parents with 3+ children that have NOT been clustered yet,
    # randomly select enough parents to reach ~limit atoms.
    query = f"""
        WITH already_clustered_parents AS (
            SELECT DISTINCT e.source_id as pid
            FROM claim_clusters cc
            JOIN edges e ON e.target_id = cc.claim_id
                AND e.relationship = 'decomposes_to'
                AND e.source_type = 'claim' AND e.target_type = 'claim'
        ),
        parent_sizes AS (
            SELECT source_id as pid, COUNT(*) as n
            FROM edges
            WHERE relationship = 'decomposes_to' AND source_type = 'claim' AND target_type = 'claim'
              AND source_id NOT IN (SELECT pid FROM already_clustered_parents)
            GROUP BY source_id
            HAVING COUNT(*) >= 3
            ORDER BY random()
        ),
        selected_parents AS (
            SELECT pid, n, SUM(n) OVER (ORDER BY pid) as running_total
            FROM parent_sizes
        ),
        capped_parents AS (
            SELECT pid FROM selected_parents WHERE running_total <= {limit} + 30
        )
        SELECT c.id::text, c.embedding::text, e.source_id::text as parent_id
        FROM claims c
        JOIN edges e ON e.target_id = c.id
            AND e.relationship = 'decomposes_to'
            AND e.target_type = 'claim' AND e.source_type = 'claim'
        WHERE c.embedding IS NOT NULL AND c.is_current = true
          AND e.source_id IN (SELECT pid FROM capped_parents)
          AND NOT EXISTS (
              SELECT 1 FROM edges e2
              WHERE e2.source_id = c.id AND e2.relationship = 'decomposes_to'
                AND e2.source_type = 'claim'
          )
          {where}
    """

    atoms = []  # (id, embedding_vector)
    parent_map = {}  # atomic_id → parent_id
    parent_ids = set()

    with conn.cursor() as cur:
        cur.execute(query)
        for aid, emb_str, pid in cur:
            atoms.append((aid, json.loads(emb_str)))
            parent_map[aid] = pid
            parent_ids.add(pid)

    print(f"  {len(atoms)} atomic claims from {len(parent_ids)} parents", file=sys.stderr)

    # Load parent embeddings
    parent_embeddings = {}
    if parent_ids:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id::text, embedding::text FROM claims WHERE id = ANY(%s::uuid[]) AND embedding IS NOT NULL",
                (list(parent_ids),)
            )
            for pid, emb_str in cur:
                parent_embeddings[pid] = json.loads(emb_str)

    print(f"  {len(parent_embeddings)} parents with embeddings", file=sys.stderr)

    # Build sibling groups
    sibling_groups = defaultdict(list)
    for aid, pid in parent_map.items():
        sibling_groups[pid].append(aid)

    # Load cross-parent edges
    cross_edges = []
    if parent_ids:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source_id::text, target_id::text, relationship
                FROM edges
                WHERE source_type = 'claim' AND target_type = 'claim'
                  AND source_id = ANY(%s::uuid[]) AND target_id = ANY(%s::uuid[])
                  AND relationship IN ('CORROBORATES', 'same_as', 'contradicts',
                                       'refines', 'supports', 'same_source',
                                       'supersedes', 'derives_from')
            """, (list(parent_ids), list(parent_ids)))
            cross_edges = [(s, t, r) for s, t, r in cur]

    print(f"  {len(cross_edges)} cross-parent edges", file=sys.stderr)

    return atoms, parent_map, parent_embeddings, sibling_groups, cross_edges


# ── Core algorithm ───────────────────────────────────────────────────────

def run_evidential_clustering(atoms, parent_map, parent_embeddings, sibling_groups,
                                cross_edges, initial_k=8, iterations=3):
    """Hierarchical evidential clustering.

    Phase 1: Cluster parent compound claims → proto-clusters
    Phase 2: Assign atomic claims via parent + sibling + cross-parent evidence
    Phase 3: Iterate with DS combination to refine + split
    """
    # Phase 1: Cluster the parent embeddings
    parents_with_emb = [(pid, emb) for pid, emb in parent_embeddings.items()]
    if len(parents_with_emb) < initial_k:
        initial_k = max(2, len(parents_with_emb))

    parent_ids_ordered = [p[0] for p in parents_with_emb]
    parent_emb_matrix = np.array([p[1] for p in parents_with_emb], dtype=np.float32)

    print(f"\nPhase 1: Clustering {len(parent_ids_ordered)} parent claims into {initial_k} proto-clusters...",
          file=sys.stderr)

    km = MiniBatchKMeans(n_clusters=initial_k, n_init=3, random_state=42, batch_size=min(256, len(parent_emb_matrix)))
    parent_labels = km.fit_predict(parent_emb_matrix)
    parent_cluster = {pid: int(label) for pid, label in zip(parent_ids_ordered, parent_labels)}
    n_clusters = initial_k

    # Build cross-parent affinity: which proto-clusters should merge?
    merge_evidence = defaultdict(lambda: defaultdict(float))  # cluster_a → cluster_b → weight
    split_evidence = defaultdict(lambda: defaultdict(float))
    for src, tgt, rel in cross_edges:
        if src in parent_cluster and tgt in parent_cluster:
            ca, cb = parent_cluster[src], parent_cluster[tgt]
            if ca != cb:
                if rel in ('CORROBORATES', 'same_as', 'same_source', 'refines', 'supports', 'derives_from'):
                    merge_evidence[ca][cb] += 1.0
                    merge_evidence[cb][ca] += 1.0
                elif rel in ('contradicts',):
                    split_evidence[ca][cb] += 1.0
                    split_evidence[cb][ca] += 1.0

    print(f"  Cross-parent merge signals: {sum(sum(v.values()) for v in merge_evidence.values()):.0f}",
          file=sys.stderr)
    print(f"  Cross-parent split signals: {sum(sum(v.values()) for v in split_evidence.values()):.0f}",
          file=sys.stderr)

    # Phase 2: Assign atomic claims
    atom_ids = [a[0] for a in atoms]
    atom_embeddings = np.array([a[1] for a in atoms], dtype=np.float32)

    print(f"\nPhase 2: Assigning {len(atom_ids)} atomic claims...", file=sys.stderr)

    # For each iteration, build mass functions and combine
    beliefs = {}  # atom_id → {cluster → {belief, plausibility, ignorance}}
    conflicts = {}  # atom_id → max_K

    for iteration in range(iterations):
        print(f"\n  Iteration {iteration + 1}/{iterations}", file=sys.stderr)
        theta = frozenset(range(n_clusters))

        for i, aid in enumerate(atom_ids):
            masses = []

            # Evidence 1: Parent assignment (strong — parent was clustered)
            pid = parent_map.get(aid)
            if pid and pid in parent_cluster:
                pc = parent_cluster[pid]
                masses.append({frozenset({pc}): 0.7, theta: 0.3})

            # Evidence 2: Sibling consensus (if siblings have prior beliefs)
            if pid and iteration > 0:
                sibs = sibling_groups.get(pid, [])
                sib_votes = defaultdict(float)
                for sib in sibs:
                    if sib != aid and sib in beliefs:
                        for c in range(n_clusters):
                            sib_votes[c] += beliefs[sib][c]["belief"]
                total_votes = sum(sib_votes.values())
                if total_votes > 0.1:
                    m = {}
                    for c, v in sib_votes.items():
                        w = 0.5 * (v / total_votes)
                        if w > 0.001:
                            m[frozenset({c})] = w
                    m[theta] = 1.0 - sum(m.values())
                    masses.append(m)

            # Evidence 3: Cross-parent merge/split evidence
            if pid and pid in parent_cluster:
                pc = parent_cluster[pid]
                if pc in merge_evidence:
                    for other_c, weight in merge_evidence[pc].items():
                        # Evidence that this claim could also belong to the merged cluster
                        strength = min(0.3, 0.05 * weight)
                        m = {frozenset({pc, other_c}): strength, theta: 1.0 - strength}
                        masses.append(m)

            # Evidence 4: Embedding distance to centroids (weak, for tie-breaking)
            if len(km.cluster_centers_) == n_clusters:
                dists = np.linalg.norm(atom_embeddings[i] - km.cluster_centers_, axis=1)
                inv = np.exp(-3.0 * dists / (dists.mean() + 1e-10))
                inv_sum = inv.sum()
                m = {}
                for c in range(n_clusters):
                    w = 0.2 * (inv[c] / (inv_sum + 1e-10))
                    if w > 0.001:
                        m[frozenset({c})] = w
                m[theta] = 1.0 - sum(m.values())
                masses.append(m)

            # Combine
            if masses:
                combined, max_k = combine_all(masses)
            else:
                combined = {theta: 1.0}
                max_k = 0.0

            # Extract beliefs
            bel_dict = {}
            for c in range(n_clusters):
                h = frozenset({c})
                bel, pl = belief_plausibility(combined, h)
                bel_dict[c] = {"belief": float(bel), "plausibility": float(pl),
                               "ignorance": float(pl - bel)}
            beliefs[aid] = bel_dict
            conflicts[aid] = float(max_k)

        # Report
        cluster_sizes = defaultdict(int)
        cluster_ign = defaultdict(list)
        for aid in atom_ids:
            best = max(range(n_clusters), key=lambda c: beliefs[aid][c]["belief"])
            cluster_sizes[best] += 1
            cluster_ign[best].append(beliefs[aid][best]["ignorance"])

        for c in sorted(cluster_sizes.keys()):
            avg_ign = np.mean(cluster_ign[c]) if cluster_ign[c] else 1.0
            avg_bel = np.mean([beliefs[aid][c]["belief"] for aid in atom_ids
                              if max(range(n_clusters), key=lambda x: beliefs[aid][x]["belief"]) == c])
            print(f"    Cluster {c}: size={cluster_sizes[c]}, avg_bel={avg_bel:.3f}, avg_ign={avg_ign:.3f}",
                  file=sys.stderr)

        high_k = sum(1 for k in conflicts.values() if k > 0.3)
        print(f"    High-K conflicts: {high_k}", file=sys.stderr)

    return beliefs, conflicts, n_clusters, parent_cluster


def store_results(conn, atom_ids, beliefs, conflicts, n_clusters, parent_cluster,
                   sibling_groups, run_id):
    """Write results to claim_clusters and cluster_labels."""
    with conn.cursor() as cur:
        for aid in atom_ids:
            best = max(range(n_clusters), key=lambda c: beliefs[aid][c]["belief"])
            bel = beliefs[aid][best]["belief"]
            pl = beliefs[aid][best]["plausibility"]
            ign = beliefs[aid][best]["ignorance"]
            cur.execute("""
                INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, second_centroid_dist,
                                            boundary_ratio, silhouette_score, cluster_run_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (claim_id) DO UPDATE SET
                    cluster_id = EXCLUDED.cluster_id, centroid_distance = EXCLUDED.centroid_distance,
                    second_centroid_dist = EXCLUDED.second_centroid_dist,
                    boundary_ratio = EXCLUDED.boundary_ratio,
                    silhouette_score = EXCLUDED.silhouette_score,
                    cluster_run_id = EXCLUDED.cluster_run_id, computed_at = NOW()
            """, (aid, best, float(pl), float(ign), float(ign), float(bel), run_id))

        # Label clusters by sampling top-belief members' content
        for c in range(n_clusters):
            top = sorted(atom_ids, key=lambda a: -beliefs[a][c]["belief"])[:5]
            cur.execute("SELECT substring(content for 100) FROM claims WHERE id = ANY(%s::uuid[])", (top,))
            texts = [r[0] for r in cur.fetchall()]
            size = sum(1 for a in atom_ids
                       if max(range(n_clusters), key=lambda x: beliefs[a][x]["belief"]) == c)
            label = f"DS: {'; '.join(texts)}"
            cur.execute("""
                INSERT INTO cluster_labels (cluster_run_id, cluster_id, label, sample_count)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cluster_run_id, cluster_id) DO UPDATE SET
                    label = EXCLUDED.label, sample_count = EXCLUDED.sample_count
            """, (run_id, c, label, size))

    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Evidential clustering with compound claim structure")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
        help=f"Postgres URL (default: {DEFAULT_DATABASE_URL})",
    )
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--k", type=int, default=8, help="Initial proto-clusters for parent claims")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--agent-filter", type=str, default=None)
    parser.add_argument("--atomic-only", action="store_true", help="(default behavior, kept for compat)")
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    run_id = str(uuid.uuid4())

    print("Loading atomic claims with parent structure...", file=sys.stderr)
    atoms, parent_map, parent_embeddings, sibling_groups, cross_edges = load_atomic_with_parents(
        conn, limit=args.limit, agent_filter=args.agent_filter
    )

    if len(atoms) < 10:
        print(f"Only {len(atoms)} atomic claims, need more", file=sys.stderr)
        sys.exit(1)

    beliefs, conflicts, n_clusters, parent_cluster = run_evidential_clustering(
        atoms, parent_map, parent_embeddings, sibling_groups, cross_edges,
        initial_k=args.k, iterations=args.iterations
    )

    atom_ids = [a[0] for a in atoms]
    print(f"\nStoring results (run_id={run_id})...", file=sys.stderr)
    store_results(conn, atom_ids, beliefs, conflicts, n_clusters, parent_cluster,
                   sibling_groups, run_id)

    result = {
        "status": "complete",
        "run_id": run_id,
        "claims_clustered": len(atoms),
        "parents_used": len(parent_embeddings),
        "n_clusters": n_clusters,
        "cross_parent_edges": len(cross_edges),
        "high_k_claims": sum(1 for k in conflicts.values() if k > 0.3),
    }
    print(json.dumps(result))
    conn.close()


if __name__ == "__main__":
    main()
