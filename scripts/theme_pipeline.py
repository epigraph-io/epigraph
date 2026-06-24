#!/usr/bin/env python3
"""Orchestrate the theme-clustering grow-loop + discrete steps.

Subcommands:
  grow      base -> (discover -> split high-variance clusters)* -> project -> label
  discover  report split candidates for the latest run (no writes)
  project   run project_to_themes for the latest/--run-id run
  label     run label_themes_llm

All grow writes happen in Model B under one consolidated run_id; project
materialises Model A; label names it. --dry-run reports the plan without writing.
"""
import argparse
import json
import subprocess
import sys

import theme_lib
import cluster_claims
import refine_clusters
import project_to_themes


def cluster_stats(conn, run_id):
    """Per-cluster size + p95 distance + mean boundary_ratio for the run."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT cluster_id, count(*),
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY centroid_distance),
                   avg(boundary_ratio)
            FROM claim_clusters WHERE cluster_run_id = %s GROUP BY cluster_id
        """, (run_id,))
        return [
            {"cluster_id": c, "size": n, "p95_dist": float(p or 0), "mean_boundary": float(b or 0)}
            for c, n, p, b in cur.fetchall()
        ]


def select_clusters_to_split(stats, min_size=2000, p95_threshold=0.5, boundary_threshold=0.5):
    """High-variance, large-enough clusters worth splitting."""
    return sorted(
        s["cluster_id"] for s in stats
        if s["size"] >= min_size
        and (s["p95_dist"] >= p95_threshold or s["mean_boundary"] >= boundary_threshold)
    )


def stop_reason(current_k, target_k, iterations, max_iter, n_selected):
    """Return a stop string, or None to continue."""
    if current_k >= target_k:
        return "target_k reached"
    if n_selected == 0:
        return "no split candidates"
    if iterations >= max_iter:
        return "max_iter reached"
    return None


def current_k(conn, run_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(DISTINCT cluster_id) FROM claim_clusters WHERE cluster_run_id=%s",
                    (run_id,))
        return cur.fetchone()[0]


def grow(conn, args):
    # --from-run-id resumes the split/project/label phases on an existing base
    # run (skips the ~40-min base assign); otherwise start a fresh consolidated run.
    if getattr(args, "from_run_id", None):
        run_id = args.from_run_id
        print(f"== resuming run {run_id} (skipping base clustering) ==", file=sys.stderr)
    else:
        run_id = theme_lib.new_run_id()
        print(f"== base clustering (run {run_id}) ==", file=sys.stderr)
        reducer, centroids, k = cluster_claims.seed_phase(
            conn, args.sample_size, args.k, run_id, all_claims=args.all_claims)
        cluster_claims.assign_batch(conn, reducer, centroids, run_id, batch_size=args.batch_size)

    iterations = 0
    while True:
        stats = cluster_stats(conn, run_id)
        selected = select_clusters_to_split(stats, min_size=args.min_size)
        reason = stop_reason(current_k(conn, run_id), args.target_k, iterations,
                             args.max_iter, len(selected))
        print(f"  iter {iterations}: k={current_k(conn, run_id)} candidates={len(selected)} "
              f"stop={reason}", file=sys.stderr)
        if reason:
            print(f"  grow stopped: {reason}", file=sys.stderr)
            break
        if args.dry_run:
            print(f"  [dry-run] would split clusters {selected}", file=sys.stderr)
            break
        for cid in selected:
            refine_clusters.auto_refine(conn, cid, run_id, min_sub_size=args.min_size // 4)
        iterations += 1

    if args.dry_run:
        return {"status": "dry-run", "run_id": run_id, "k": current_k(conn, run_id)}

    project_to_themes.project_run(conn, run_id)
    subprocess.run([sys.executable, "scripts/label_themes_llm.py", "--relabel-all"], check=False)
    return {"status": "grown", "run_id": run_id, "k": current_k(conn, run_id)}


def main():
    p = argparse.ArgumentParser(description="Theme-clustering orchestrator")
    p.add_argument("command", choices=["grow", "discover", "project", "label"])
    p.add_argument("--database-url", default=None)
    p.add_argument("--sample-size", type=int, default=5000)
    p.add_argument("--batch-size", type=int, default=20000)
    p.add_argument("--k", type=int, default=None)
    p.add_argument("--all-claims", action="store_true")
    p.add_argument("--target-k", type=int, default=72)
    p.add_argument("--min-size", type=int, default=2000)
    p.add_argument("--max-iter", type=int, default=8)
    p.add_argument("--run-id", default=None)
    p.add_argument("--from-run-id", default=None,
                   help="grow: resume split/project/label on an existing base run (skip base)")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    conn = theme_lib.connect(args.database_url)
    theme_lib.set_statement_timeout(conn, ms=900000)

    if args.command == "grow":
        print(json.dumps(grow(conn, args)))
    elif args.command == "discover":
        run_id = args.run_id or project_to_themes.latest_run_id(conn)
        print(json.dumps({"run_id": run_id,
                          "candidates": select_clusters_to_split(cluster_stats(conn, run_id),
                                                                 min_size=args.min_size)}))
    elif args.command == "project":
        run_id = args.run_id or project_to_themes.latest_run_id(conn)
        print(json.dumps({"status": "projected", "run_id": run_id,
                          "themes": project_to_themes.project_run(conn, run_id)}))
    elif args.command == "label":
        subprocess.run([sys.executable, "scripts/label_themes_llm.py", "--relabel-all"], check=False)
    conn.close()


if __name__ == "__main__":
    main()
