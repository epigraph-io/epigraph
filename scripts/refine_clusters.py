#!/usr/bin/env python3
"""Interactive cluster refinement via human-labeled boundary claims.

Ported from EpigraphV2/scripts/refine_clusters.py — interactive,
human-in-the-loop, NOT batchable. An operator runs it, reads sample
claims, and types sub-labels in real time. Output writes to
`claim_clusters` + `cluster_labels` under a new run_id.

Workflow:
1. Pick a cluster (--cluster-id)
2. Show boundary + core claims; operator proposes sub-label names
3. Operator labels ~30 boundary claims by index
4. Train logistic regression on embeddings of labeled claims
5. Re-assign every claim in the cluster using the trained classifier

Direct DB INSERT — `epigraph_admin` role required (no API endpoint
for bulk claim_clusters writes), same as evidential_clustering.py.

Usage:
    DATABASE_URL=postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph \\
        python3 scripts/refine_clusters.py --cluster-id 2
"""

DEFAULT_DATABASE_URL = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph"

import argparse
import json
import os
import sys
import uuid

import numpy as np
import psycopg2
import psycopg2.extras
from sklearn.linear_model import LogisticRegression

psycopg2.extras.register_uuid()


def get_connection(database_url: str):
    return psycopg2.connect(database_url)


def load_cluster_embeddings(conn, cluster_id: int, run_id: str):
    """Load claim IDs, content, and embeddings for a given cluster."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.id::text, c.content, c.embedding::text, cc.boundary_ratio, cc.silhouette_score
            FROM claim_clusters cc
            JOIN claims c ON c.id = cc.claim_id
            WHERE cc.cluster_id = %s AND cc.cluster_run_id = %s
              AND c.embedding IS NOT NULL
            ORDER BY cc.boundary_ratio DESC
        """, (cluster_id, run_id))
        rows = cur.fetchall()

    if not rows:
        return [], [], np.array([]), [], []

    ids = [r[0] for r in rows]
    contents = [r[1] for r in rows]
    embeddings = np.array([json.loads(r[2]) for r in rows], dtype=np.float32)
    boundary_ratios = [r[3] for r in rows]
    silhouettes = [r[4] for r in rows]
    return ids, contents, embeddings, boundary_ratios, silhouettes


def propose_sublabels(contents: list[str], n_samples: int = 10) -> list[str]:
    """Propose sub-labels by showing diverse samples from the cluster."""
    # Show first N (highest boundary ratio = most ambiguous) and last N (most central)
    border = contents[:n_samples]
    core = contents[-n_samples:] if len(contents) > n_samples else []

    print("\n=== CORE claims (most central to cluster) ===", file=sys.stderr)
    for i, c in enumerate(core):
        print(f"  [{i}] {c[:120]}", file=sys.stderr)

    print("\n=== BORDER claims (most ambiguous) ===", file=sys.stderr)
    for i, c in enumerate(border):
        print(f"  [{i}] {c[:120]}", file=sys.stderr)

    return border, core


def interactive_label(conn, cluster_id: int, run_id: str):
    """Interactive labeling session. Returns (labeled_ids, labels, sublabel_names)."""
    ids, contents, embeddings, br, sil = load_cluster_embeddings(conn, cluster_id, run_id)
    if not ids:
        print("No claims in cluster", file=sys.stderr)
        return [], [], []

    print(f"\nCluster {cluster_id}: {len(ids)} claims", file=sys.stderr)
    print(f"Boundary ratio: min={min(br):.3f}, max={max(br):.3f}, mean={np.mean(br):.3f}", file=sys.stderr)
    print(f"Silhouette: min={min(sil):.3f}, max={max(sil):.3f}, mean={np.mean(sil):.3f}", file=sys.stderr)

    # Show samples for human to propose sub-labels
    propose_sublabels(contents)

    print("\n--- Propose sub-label names (comma-separated, e.g. 'mechanosynthesis,DNA nanotech') ---", file=sys.stderr)
    sublabel_input = input("Sub-labels: ").strip()
    sublabels = [s.strip() for s in sublabel_input.split(",")]

    if len(sublabels) < 2:
        print("Need at least 2 sub-labels to split a cluster", file=sys.stderr)
        return [], [], []

    print(f"\nSub-labels: {sublabels}", file=sys.stderr)
    print(f"Now label some claims. For each, enter the sub-label number (0-{len(sublabels)-1}) or 's' to skip.", file=sys.stderr)

    # Show boundary claims for labeling (most ambiguous first)
    n_to_label = min(30, len(ids))
    labeled_ids = []
    labels = []

    for i in range(n_to_label):
        print(f"\n[{i+1}/{n_to_label}] {contents[i][:150]}", file=sys.stderr)
        for j, sl in enumerate(sublabels):
            print(f"  {j}: {sl}", file=sys.stderr)

        choice = input("Label: ").strip()
        if choice == 's':
            continue
        try:
            label_idx = int(choice)
            if 0 <= label_idx < len(sublabels):
                labeled_ids.append(ids[i])
                labels.append(label_idx)
        except ValueError:
            continue

    return labeled_ids, labels, sublabels


def train_and_apply(conn, cluster_id: int, run_id: str,
                    labeled_ids: list[str], labels: list[int],
                    sublabel_names: list[str]):
    """Train logistic regression on labeled claims, re-assign entire cluster."""
    ids, contents, embeddings, br, sil = load_cluster_embeddings(conn, cluster_id, run_id)

    # Build training set from labeled claims
    id_to_idx = {cid: i for i, cid in enumerate(ids)}
    X_train = []
    y_train = []
    for lid, label in zip(labeled_ids, labels):
        if lid in id_to_idx:
            X_train.append(embeddings[id_to_idx[lid]])
            y_train.append(label)

    X_train = np.array(X_train)
    y_train = np.array(y_train)

    print(f"\nTraining on {len(X_train)} labeled claims across {len(sublabel_names)} sub-labels", file=sys.stderr)

    # Check we have at least 2 classes represented
    unique_labels = set(y_train)
    if len(unique_labels) < 2:
        print("ERROR: Need labels from at least 2 sub-labels to train", file=sys.stderr)
        return

    clf = LogisticRegression(max_iter=1000, C=1.0)
    clf.fit(X_train, y_train)

    # Score on training data
    train_acc = clf.score(X_train, y_train)
    print(f"Training accuracy: {train_acc:.2%}", file=sys.stderr)

    # Predict all claims in the cluster
    predictions = clf.predict(embeddings)
    probas = clf.predict_proba(embeddings)

    # Show distribution
    for i, name in enumerate(sublabel_names):
        count = int((predictions == i).sum())
        print(f"  Sub-label '{name}': {count} claims", file=sys.stderr)

    # Confidence distribution
    max_probs = probas.max(axis=1)
    print(f"  Prediction confidence: min={max_probs.min():.3f}, mean={max_probs.mean():.3f}, max={max_probs.max():.3f}", file=sys.stderr)

    confirm = input("\nApply these assignments? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Aborted", file=sys.stderr)
        return

    # Write new cluster assignments
    # New sub-cluster IDs: original_cluster_id * 100 + sub_label_index
    new_run_id = str(uuid.uuid4())

    with conn.cursor() as cur:
        for i, cid in enumerate(ids):
            sub_cluster = cluster_id * 100 + int(predictions[i])
            new_boundary = 1.0 - float(max_probs[i])  # low confidence = high boundary
            cur.execute("""
                INSERT INTO claim_clusters
                    (claim_id, cluster_id, centroid_distance, second_centroid_dist,
                     boundary_ratio, silhouette_score, cluster_run_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (claim_id) DO UPDATE SET
                    cluster_id = EXCLUDED.cluster_id,
                    centroid_distance = EXCLUDED.centroid_distance,
                    second_centroid_dist = EXCLUDED.second_centroid_dist,
                    boundary_ratio = EXCLUDED.boundary_ratio,
                    silhouette_score = EXCLUDED.silhouette_score,
                    cluster_run_id = EXCLUDED.cluster_run_id,
                    computed_at = NOW()
            """, (cid, sub_cluster, float(probas[i, int(predictions[i])]),
                  float(sorted(probas[i])[-2]) if len(sublabel_names) > 1 else 0.0,
                  new_boundary, float(sil[i]), new_run_id))

        # Write sub-cluster labels
        for j, name in enumerate(sublabel_names):
            sub_id = cluster_id * 100 + j
            count = int((predictions == j).sum())
            cur.execute("""
                INSERT INTO cluster_labels (cluster_run_id, cluster_id, label, sample_count)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cluster_run_id, cluster_id) DO UPDATE SET
                    label = EXCLUDED.label, sample_count = EXCLUDED.sample_count
            """, (new_run_id, sub_id, f"Refined: {name}", count))

    conn.commit()

    result = {
        "status": "refined",
        "cluster_id": cluster_id,
        "run_id": new_run_id,
        "sublabels": sublabel_names,
        "counts": {name: int((predictions == i).sum()) for i, name in enumerate(sublabel_names)},
        "training_accuracy": round(train_acc, 4),
        "claims_reassigned": len(ids),
    }
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description="Interactive cluster refinement")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
        help=f"Postgres URL (default: {DEFAULT_DATABASE_URL})",
    )
    parser.add_argument("--cluster-id", type=int, required=True)
    parser.add_argument("--run-id", default=None, help="Cluster run ID (default: latest)")
    args = parser.parse_args()

    conn = get_connection(args.database_url)

    if not args.run_id:
        with conn.cursor() as cur:
            cur.execute("SELECT cluster_run_id FROM claim_clusters LIMIT 1")
            row = cur.fetchone()
            if not row:
                print("No clusters found", file=sys.stderr)
                sys.exit(1)
            args.run_id = str(row[0])

    labeled_ids, labels, sublabel_names = interactive_label(conn, args.cluster_id, args.run_id)

    if not labeled_ids:
        print("No labels collected, exiting", file=sys.stderr)
        sys.exit(0)

    train_and_apply(conn, args.cluster_id, args.run_id, labeled_ids, labels, sublabel_names)
    conn.close()


if __name__ == "__main__":
    main()
