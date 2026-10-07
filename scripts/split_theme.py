#!/usr/bin/env python3
"""Split one oversized theme into k themes by k-means over its own members.

The theme-v2 pipeline caps a theme at DEFAULT_MAX_SIZE (8,000) claims, but that
cap is enforced only while `theme_pipeline.py grow` builds a run. Claims
assigned to their nearest theme afterwards (assign-unthemed, or a re-projection
followed by an assign) can push a theme back over it. This script splits that
one theme in place, without re-clustering the corpus:

  1. load the theme's member embeddings;
  2. k-means (k=2 by default) on the L2-normalised embeddings, so Euclidean
     distance tracks the cosine distance the themes are built on;
  3. in ONE transaction: the largest part keeps the theme's id; every other
     part becomes a new claim_themes row and its members move to it; each part's
     centroid and claim_count are recomputed from its members.

Every part gets the placeholder label `cluster-split-<theme8>-<part>` and an
empty description, so a default `label_themes_llm.py` run names them (the
parent's name described the whole theme, not either part). Lineage is kept in
`properties`: the parent's cluster_run_id / cluster_id are copied and a
`split_part` index is added, so `(cluster_run_id, cluster_id, split_part)` stays
a stable key for anything that must survive re-labelling.

A re-projection of the source cluster run undoes the split, as it undoes every
change made after the run: claim_clusters is not touched here.

Run as the maintenance role (MAINTENANCE_DATABASE_URL): claims has forced RLS,
and an application connection would see and move only a subset of the members.

Usage:
    python3 scripts/split_theme.py --label "Nanoscale Surface Science And Engineering" --dry-run
    python3 scripts/split_theme.py --theme-id <uuid> [--k 2] [--min-part 500]
"""

import argparse
import json
import sys

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import normalize

import theme_lib  # noqa: E402  (scripts/ is on sys.path when run as a script)


def placeholder_label(theme_id, part):
    """The label a split part carries until label_themes_llm names it."""
    return f"cluster-split-{str(theme_id)[:8]}-{part}"


def resolve_theme(conn, theme_id=None, label=None):
    """Return (id, label, properties) for exactly one theme, by id or exact label."""
    with conn.cursor() as cur:
        if theme_id:
            cur.execute("SELECT id::text, label, properties FROM claim_themes WHERE id = %s",
                        (theme_id,))
        else:
            cur.execute("SELECT id::text, label, properties FROM claim_themes WHERE label = %s",
                        (label,))
        rows = cur.fetchall()
    if len(rows) != 1:
        raise ValueError(f"expected exactly one theme, found {len(rows)}")
    return rows[0]


def plan_split(conn, theme_id, k=2, min_part=500, seed=42):
    """Partition a theme's embedded members into k parts, largest first.

    Returns a list of k lists of claim ids. Raises ValueError, before anything
    is written, when any part would be smaller than `min_part`.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, embedding::text FROM claims "
            "WHERE theme_id = %s AND embedding IS NOT NULL ORDER BY id",
            (theme_id,),
        )
        rows = cur.fetchall()
    if len(rows) < k * min_part:
        raise ValueError(f"theme has {len(rows)} embedded members; "
                         f"cannot make {k} parts of at least {min_part}")
    ids = [r[0] for r in rows]
    x = normalize(theme_lib.parse_embeddings([r[1] for r in rows]))
    labels = KMeans(n_clusters=k, n_init=10, random_state=seed).fit_predict(x)
    parts = [[ids[i] for i in np.flatnonzero(labels == p)] for p in range(k)]
    parts.sort(key=len, reverse=True)
    if len(parts[-1]) < min_part:
        raise ValueError(f"smallest part has {len(parts[-1])} claims (< {min_part}); "
                         "refusing a lopsided split")
    return parts


def apply_split(conn, theme_id, properties, parts):
    """Write a plan from plan_split in one transaction. Returns [(theme_id, size), ...]."""
    base = dict(properties or {})
    base["split_of"] = str(theme_id)
    result = []
    with conn.cursor() as cur:
        for part, members in enumerate(parts):
            props = dict(base, split_part=part)
            if part == 0:
                target = theme_id
                cur.execute(
                    "UPDATE claim_themes SET label = %s, description = '', properties = %s::jsonb "
                    "WHERE id = %s",
                    (placeholder_label(theme_id, part), json.dumps(props), theme_id),
                )
            else:
                cur.execute(
                    "INSERT INTO claim_themes (label, description, claim_count, centroid, properties) "
                    "VALUES (%s, '', 0, NULL, %s::jsonb) RETURNING id::text",
                    (placeholder_label(theme_id, part), json.dumps(props)),
                )
                target = cur.fetchone()[0]
                cur.execute(
                    "UPDATE claims SET theme_id = %s, updated_at = NOW() "
                    "WHERE id = ANY(%s::uuid[]) AND theme_id = %s",
                    (target, members, theme_id),
                )
            result.append((target, len(members)))
        # Only after every move: each centroid is the mean of the part's own
        # members, as project_to_themes computes it. Recomputing part 0 inside
        # the loop would average over the members still waiting to move.
        for target, _ in result:
            cur.execute(
                "UPDATE claim_themes ct SET centroid = s.c, claim_count = s.n "
                "FROM (SELECT avg(embedding)::vector(1536) c, count(*) n FROM claims "
                "      WHERE theme_id = %s AND embedding IS NOT NULL) s "
                "WHERE ct.id = %s",
                (target, target),
            )
    conn.commit()
    return result


def main():
    parser = argparse.ArgumentParser(description="Split one oversized theme by k-means")
    parser.add_argument("--database-url", default=None)
    who = parser.add_mutually_exclusive_group(required=True)
    who.add_argument("--theme-id")
    who.add_argument("--label", help="exact claim_themes.label")
    parser.add_argument("--k", type=int, default=2)
    parser.add_argument("--min-part", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true",
                        help="print the part sizes and a few member excerpts; write nothing")
    args = parser.parse_args()

    conn = theme_lib.connect(args.database_url)
    theme_lib.set_statement_timeout(conn, ms=900000)
    theme_id, label, properties = resolve_theme(conn, args.theme_id, args.label)
    print(f"  theme {theme_id} ({label})", file=sys.stderr)
    parts = plan_split(conn, theme_id, k=args.k, min_part=args.min_part)
    print(f"  part sizes: {[len(p) for p in parts]}", file=sys.stderr)

    if args.dry_run:
        with conn.cursor() as cur:
            for part, members in enumerate(parts):
                cur.execute("SELECT left(content, 100) FROM claims WHERE id = ANY(%s::uuid[]) "
                            "ORDER BY id LIMIT 5", (members,))
                print(f"  part {part}:", file=sys.stderr)
                for (text,) in cur.fetchall():
                    print(f"    - {text}", file=sys.stderr)
        print(json.dumps({"status": "dry-run", "theme_id": theme_id,
                          "sizes": [len(p) for p in parts]}))
        conn.close()
        return

    result = apply_split(conn, theme_id, properties, parts)
    print(json.dumps({"status": "split", "parent": theme_id,
                      "themes": [{"id": t, "claims": n} for t, n in result]}))
    conn.close()


if __name__ == "__main__":
    main()
