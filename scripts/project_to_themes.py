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

Full-rebuild guard (backlog 18ae37e7): theme ids are run-scoped. Every
projection deletes every claim_themes row and mints new ids, and the per-run
views built on those ids reference claim_themes ON DELETE CASCADE: the graph
neighbourhoods, the shared Atlas layout and every Atlas map's levels (public
and team) go with the wipe. So when claim_themes is not empty the projection
refuses, before any mutation, unless the caller passes
--i-understand-full-rebuild (`confirm_full_rebuild=True`). Either way it
counts and prints the rows the cascade drops, and after the projection it
prints the steps that rebuild those views (`REBUILD_STEPS`;
docs/ops/theme-v2-promotion-runbook.md). Nothing may persist a theme id across
a projection.
"""
import argparse
import json
import sys

from psycopg2 import sql

import theme_lib

FULL_REBUILD_FLAG = "--i-understand-full-rebuild"

# What a projection leaves to rebuild, in order. The first four are the
# rebuild after a theme-cap split (theme_cap_split.REBUILD_STEPS;
# docs/runbooks/atlas-nightly.md): a new clustering run writes neighbourhoods
# for every theme, its placeholder names are labelled, and a new layout run
# places the themes. The Atlas maps (migration 210's atlas_map_levels, the
# public map and every team map) are written by the atlas_meaning and
# atlas_links builders, not by atlas_layout, so each map listed under "maps"
# gets the operator build, then a nightly pass.
REBUILD_STEPS = [
    """enqueue_job --job '{"ClusterGraph":{"resolution":1.0,"retain_runs":3}}' --unique""",
    "drain_jobs",
    "python3 scripts/label_themes_llm.py --neighborhoods",
    "atlas_layout --apply",
    "for each map M (public, team:<group>): atlas_meaning export --map M, "
    "atlas_meaning_core.py compute, atlas_links export --map M, atlas_links_core.py compute, "
    "atlas_links apply --map M --apply (docs/runbooks/atlas-nightly.md, "
    "\"Before the first night: the operator build\")",
    "atlas_nightly --apply --map M, for each map rebuilt above",
]


class FullRebuildRefused(RuntimeError):
    """A projection over existing themes without --i-understand-full-rebuild."""


def cascading_tables(conn):
    """Every (schema, table) whose rows are deleted when claim_themes rows are:
    the referencing foreign keys declared ON DELETE CASCADE, read from the
    catalog so a table added later is counted without editing this list."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT n.nspname::text, c.relname::text
            FROM pg_catalog.pg_constraint k
            JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE k.contype = 'f' AND k.confdeltype = 'c'
              AND k.confrelid = 'public.claim_themes'::regclass
            ORDER BY 1, 2
        """)
        return [tuple(r) for r in cur.fetchall()]


def rebuild_impact(conn):
    """What emptying claim_themes drops right now: the theme count, the rows
    of each cascading table, and the Atlas maps that lose their levels."""
    tables = cascading_tables(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM claim_themes")
        themes = cur.fetchone()[0]
        cascade = {}
        for schema, table in tables:
            cur.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(schema, table)))
            cascade[f"{schema}.{table}"] = cur.fetchone()[0]
        maps = []
        if ("public", "atlas_map_levels") in tables:
            cur.execute("""
                SELECT DISTINCT CASE WHEN visibility = 'public' THEN 'public'
                                     ELSE 'team:' || owner_group_id::text END
                FROM public.atlas_map_levels ORDER BY 1
            """)
            maps = [r[0] for r in cur.fetchall()]
    return {"themes": themes, "cascade": cascade, "maps": maps}


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def describe_impact(impact):
    lines = [f"  claim_themes: {_plural(impact['themes'], 'theme')} (every theme id changes)"]
    lines += [f"  {table}: {_plural(n, 'row')}" for table, n in impact["cascade"].items()]
    lines.append("  maps losing their levels: " + (", ".join(impact["maps"]) or "none"))
    return "\n".join(lines)


def describe_rebuild():
    return "\n".join(f"  {i}. {step}" for i, step in enumerate(REBUILD_STEPS, 1))


def check_full_rebuild(conn, confirm):
    """Refuse a projection that would empty a non-empty claim_themes unless
    `confirm`. Reads only; returns the impact for the caller to report."""
    impact = rebuild_impact(conn)
    if impact["themes"] and not confirm:
        raise FullRebuildRefused(
            "refusing a full theme rebuild: it deletes every claim_themes row, and the rows "
            "below go with them through their ON DELETE CASCADE foreign keys:\n"
            f"{describe_impact(impact)}\n"
            f"Re-run with {FULL_REBUILD_FLAG} to rebuild anyway, then run:\n"
            f"{describe_rebuild()}"
        )
    return impact


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


def project_run(conn, run_id, *, confirm_full_rebuild=False):
    """Replace claim_themes with one theme per cluster in `run_id`.

    Executes atomically in a single transaction: reads clusters first, guards
    against an empty run and an unconfirmed full rebuild, then wipes and
    re-builds in one committed batch.
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

    # Step 3: guard BEFORE any wipe — existing themes go only when confirmed,
    # and the rows their cascade drops are counted in this transaction.
    impact = check_full_rebuild(conn, confirm_full_rebuild)
    print("  Full theme rebuild; the wipe drops:\n" + describe_impact(impact), file=sys.stderr)

    # Step 4: single transaction — wipe + full re-build + one commit at the end.
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
    print("  Theme ids are new. REQUIRED next, to rebuild the views built on them:\n"
          + describe_rebuild(), file=sys.stderr)
    return created


def main():
    parser = argparse.ArgumentParser(description="Project a cluster run into claim_themes")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--run-id", default=None, help="Cluster run (default: latest)")
    parser.add_argument(FULL_REBUILD_FLAG, dest="confirm_full_rebuild", action="store_true",
                        help="replace existing themes; their graph neighbourhoods, Atlas "
                             "layout and Atlas map levels are deleted with them")
    args = parser.parse_args()

    conn = theme_lib.connect(args.database_url)
    theme_lib.set_statement_timeout(conn, ms=900000)
    run_id = args.run_id or latest_run_id(conn)
    try:
        created = project_run(conn, run_id, confirm_full_rebuild=args.confirm_full_rebuild)
    except FullRebuildRefused as e:
        conn.rollback()
        conn.close()
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"status": "projected", "run_id": run_id, "themes": created,
                      "rebuild_next": REBUILD_STEPS}))
    conn.close()


if __name__ == "__main__":
    main()
