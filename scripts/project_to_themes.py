#!/usr/bin/env python3
"""Project a Model-B cluster run into the active Model-A theme model.

For the chosen run (default: latest by cluster_centroids.created_at), wipe the
current claim_themes, then for each cluster create one claim_themes row whose
centroid is the TRUE 1536-d mean of its members' embeddings (recall does
pgvector search on this column), set claims.theme_id, and record the
cluster_id<->theme_id lineage in claim_themes.properties.

Atomicity: the entire projection (wipe + re-insert) executes in a SINGLE
transaction committed once at the end. A partial-state window is avoided: if
anything fails mid-loop the rollback restores the previous theme state intact.

Empty-run guard: if the run_id has no claim_clusters rows (e.g. a --seed-only
run that writes cluster_centroids but not claim_clusters), a ValueError is
raised BEFORE any mutation so no data is lost.
"""
import argparse
import json
import sys

import theme_lib


def theme_properties(run_id, cluster_id):
    """Lineage metadata stored on each projected theme."""
    return {"source": "cluster_run", "cluster_run_id": str(run_id), "cluster_id": int(cluster_id)}


def latest_run_id(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT cluster_run_id::text FROM cluster_centroids "
                    "ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
    if not row:
        print("ERROR: no cluster runs found in cluster_centroids", file=sys.stderr)
        sys.exit(1)
    return row[0]


def project_run(conn, run_id):
    """Replace claim_themes with one theme per cluster in `run_id`.

    Executes atomically in a single transaction: reads clusters first, guards
    against an empty run, then wipes and re-builds in one committed batch.
    """
    # Step 1: read clusters BEFORE any mutation (fixes empty-run guard ordering).
    with conn.cursor() as cur:
        cur.execute("""
            SELECT cc.cluster_id, COALESCE(cl.label, 'auto-' || cc.cluster_id::text)
            FROM (SELECT DISTINCT cluster_id FROM claim_clusters WHERE cluster_run_id = %s) cc
            LEFT JOIN cluster_labels cl
              ON cl.cluster_run_id = %s AND cl.cluster_id = cc.cluster_id
            ORDER BY cc.cluster_id
        """, (run_id, run_id))
        clusters = cur.fetchall()

    # Step 2: guard BEFORE any wipe — a seed-only run has no claim_clusters rows.
    if not clusters:
        raise ValueError(
            f"run {run_id} has no claim_clusters rows (seed-only run?); "
            "refusing to wipe claim_themes"
        )

    # Step 3: single transaction — wipe + full re-build + one commit at the end.
    created = 0
    with conn.cursor() as cur:
        # Clean slate (targeted — only currently-themed claims are touched).
        cur.execute("UPDATE claims SET theme_id = NULL WHERE theme_id IS NOT NULL")
        cur.execute("DELETE FROM claim_themes")

        for cluster_id, label in clusters:
            # Create the theme with the true 1536-d centroid = mean of members.
            # HAVING count(*) > 0 prevents inserting a row with a NULL centroid
            # when every member has embedding IS NULL.
            cur.execute("""
                INSERT INTO claim_themes (label, description, claim_count, centroid, properties)
                SELECT %s, '', count(*),
                       avg(c.embedding)::vector(1536),
                       %s::jsonb
                FROM claims c
                JOIN claim_clusters cc ON cc.claim_id = c.id
                WHERE cc.cluster_run_id = %s AND cc.cluster_id = %s
                  AND c.embedding IS NOT NULL
                HAVING count(*) > 0
                RETURNING id
            """, (label, json.dumps(theme_properties(run_id, cluster_id)), run_id, cluster_id))
            row = cur.fetchone()
            if row is None:
                # All members had NULL embeddings — skip this cluster to avoid
                # inserting a NULL centroid that would break pgvector recall.
                continue
            theme_id = row[0]

            # Point member claims at the new theme.
            cur.execute("""
                UPDATE claims SET theme_id = %s, updated_at = NOW()
                WHERE id IN (SELECT claim_id FROM claim_clusters
                             WHERE cluster_run_id = %s AND cluster_id = %s)
            """, (theme_id, run_id, cluster_id))
            created += 1

    # Single commit outside the loop: the wipe and all inserts land atomically.
    conn.commit()

    print(f"  Projected {created} themes from run {run_id}", file=sys.stderr)
    return created


def main():
    parser = argparse.ArgumentParser(description="Project a cluster run into claim_themes")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--run-id", default=None, help="Cluster run (default: latest)")
    args = parser.parse_args()

    conn = theme_lib.connect(args.database_url)
    theme_lib.set_statement_timeout(conn, ms=900000)
    run_id = args.run_id or latest_run_id(conn)
    created = project_run(conn, run_id)
    print(json.dumps({"status": "projected", "run_id": run_id, "themes": created}))
    conn.close()


if __name__ == "__main__":
    main()
