#!/usr/bin/env python3
"""Seed claim_themes from textbook L1 sections.

For each textbook L1 claim:
  1. Compute centroid as mean of L1 + decomposes_to descendants' embeddings
     (1536d and 3072d if populated).
  2. Use claude -p to emit a short label (<=60 chars) and description
     (<=250 chars) from the L1 content + descendant atom samples.
  3. INSERT into claim_themes with properties.source_textbook_claim_id.
  4. Backfill claims.theme_id on the L1 and all decomposes_to descendants.

Drops existing auto-NN themes ONLY after a successful seed run (Step 5 in
this script), to free the 500 claims currently in auto-NN themes for the
anchor pass in Task 7.

Idempotent: skips L1 claims whose source_textbook_claim_id already exists
in claim_themes.properties.

Per spec 2026-05-18-cross-source-anchor-design.md §Component 2.

BACKLOG — raw SQL used here because the API surface is incomplete:
  * POST /api/v1/themes/create-with-centroid exists but only accepts a
    1536d centroid and has no `properties` field. To use it we'd need
    to extend the request struct with `properties: Option<JsonValue>` and
    `centroid_3072: Option<Vec<f64>>` (small Rust change in
    crates/epigraph-api/src/routes/crud.rs::CreateThemeWithCentroidRequest
    + `ClaimThemeRepository::set_centroid_3072` + a properties merge).
  * The drop-auto path (DELETE FROM claim_themes WHERE label LIKE 'auto-%')
    has no API equivalent. POST /api/v1/themes/build-from-corpus has a
    `wipe_first` parameter that drops all themes for a given label_prefix,
    but it also re-runs k-means; we just want the delete. Need
    DELETE /api/v1/themes/by-label-prefix or similar.
  * Bulk theme_id assignment (UPDATE claims SET theme_id = ...) goes
    through the same path the existing POST /api/v1/themes/reassign uses
    via ClaimThemeRepository::bulk_assign, but reassign auto-decides which
    theme based on embedding distance — it can't be told to use a specific
    target. Need POST /api/v1/themes/:id/assign-claims.

These three gaps should be filed as feature requests against
crates/epigraph-api. Until they land, this script writes claim_themes
and claims.theme_id directly via psycopg2 as a documented exception.

Usage:
    python3 scripts/seed_themes_from_textbooks.py --dry-run --limit 5
    python3 scripts/seed_themes_from_textbooks.py --limit 50
    python3 scripts/seed_themes_from_textbooks.py --drop-auto-after
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from typing import Optional

import psycopg2
import psycopg2.extras

DEFAULT_DATABASE_URL = (
    "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph"
)

LABEL_PROMPT = """\
You are labeling a textbook section that will serve as a "concept anchor" \
in a knowledge graph. Paper claims will be attached to this anchor if they \
instantiate the concept it describes.

Section content:
{section_content}

Three sample atomic claims from this section:
{atoms}

Respond with ONLY a JSON object:
{{"label": "<= 60 chars: short concept name (e.g., 'Bernoulli's Equation — Streamline Form')>",
  "description": "<= 250 chars: what concept this anchor covers and what kind of paper claim would instantiate it>"}}

Do not include any other text.\
"""


def fetch_textbook_l1_claims(conn, limit: Optional[int]) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    q = (
        "SELECT id, content "
        "FROM claims "
        "WHERE is_current = true "
        "  AND properties->>'source_type' = 'Textbook' "
        "  AND properties->>'level' = '1' "
        "  AND id NOT IN ( "
        "    SELECT (properties->>'source_textbook_claim_id')::uuid "
        "    FROM claim_themes "
        "    WHERE properties ? 'source_textbook_claim_id' "
        "  ) "
        "ORDER BY created_at ASC"
    )
    if limit:
        q += f" LIMIT {int(limit)}"
    cur.execute(q)
    return list(cur.fetchall())


def fetch_descendant_ids(conn, root_id: str) -> list[str]:
    cur = conn.cursor()
    cur.execute(
        "WITH RECURSIVE walk(id) AS ( "
        "  SELECT %s::uuid "
        "  UNION "
        "  SELECT e.target_id FROM edges e JOIN walk w ON e.source_id = w.id "
        "  WHERE e.relationship = 'decomposes_to' "
        ") SELECT id FROM walk",
        (root_id,),
    )
    return [str(r[0]) for r in cur.fetchall()]


def fetch_embeddings(conn, ids: list[str], dim: int) -> list[list[float]]:
    if not ids:
        return []
    col = "embedding" if dim == 1536 else "embedding_3072"
    cur = conn.cursor()
    cur.execute(
        f"SELECT {col}::text FROM claims WHERE id = ANY(%s::uuid[]) AND {col} IS NOT NULL",
        (ids,),
    )
    out: list[list[float]] = []
    for row in cur.fetchall():
        s = row[0]
        if s is None:
            continue
        vec = [float(x) for x in s.strip("[]").split(",")]
        out.append(vec)
    return out


def mean_vector(vecs: list[list[float]]) -> Optional[list[float]]:
    if not vecs:
        return None
    n = len(vecs)
    dim = len(vecs[0])
    out = [0.0] * dim
    for v in vecs:
        for i, x in enumerate(v):
            out[i] += x
    return [x / n for x in out]


def fetch_sample_atoms(conn, root_id: str, k: int = 3) -> list[str]:
    cur = conn.cursor()
    cur.execute(
        "WITH RECURSIVE walk(id) AS ( "
        "  SELECT %s::uuid "
        "  UNION "
        "  SELECT e.target_id FROM edges e JOIN walk w ON e.source_id = w.id "
        "  WHERE e.relationship = 'decomposes_to' "
        ") SELECT c.content FROM walk JOIN claims c ON c.id = walk.id "
        "WHERE c.properties->>'level' = '3' "
        "ORDER BY random() LIMIT %s",
        (root_id, k),
    )
    return [r[0] for r in cur.fetchall()]


def label_via_claude(section_content: str, atoms: list[str]) -> dict:
    atom_block = "\n".join(f"- {a[:300]}" for a in atoms) or "(none)"
    prompt = LABEL_PROMPT.format(section_content=section_content[:2000], atoms=atom_block)
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude exit {proc.returncode}: {proc.stderr[:400]}")
    envelope = json.loads(proc.stdout)
    text = envelope.get("result") if isinstance(envelope, dict) else None
    if not text:
        raise RuntimeError(f"empty claude result: {envelope}")
    text = text.strip().strip("`").lstrip("json").strip()
    parsed = json.loads(text)
    label = parsed["label"][:60]
    description = parsed["description"][:250]
    return {"label": label, "description": description}


def insert_theme(conn, label: str, description: str, centroid_1536: Optional[list[float]],
                 centroid_3072: Optional[list[float]], source_textbook_claim_id: str) -> str:
    cur = conn.cursor()
    c1 = "[" + ",".join(str(x) for x in centroid_1536) + "]" if centroid_1536 else None
    c2 = "[" + ",".join(str(x) for x in centroid_3072) + "]" if centroid_3072 else None
    cur.execute(
        "INSERT INTO claim_themes (label, description, centroid, centroid_3072, properties) "
        "VALUES (%s, %s, %s::vector, %s::vector, %s::jsonb) RETURNING id",
        (label, description, c1, c2,
         json.dumps({"source_textbook_claim_id": source_textbook_claim_id, "seeded_by": "textbook_l1"})),
    )
    return str(cur.fetchone()[0])


def assign_theme(conn, theme_id: str, claim_ids: list[str]) -> int:
    if not claim_ids:
        return 0
    cur = conn.cursor()
    cur.execute("UPDATE claims SET theme_id = %s WHERE id = ANY(%s::uuid[])", (theme_id, claim_ids))
    return cur.rowcount


def update_theme_count(conn, theme_id: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "UPDATE claim_themes SET claim_count = "
        "  (SELECT COUNT(*) FROM claims WHERE theme_id = claim_themes.id) "
        "WHERE id = %s",
        (theme_id,),
    )


def drop_auto_themes(conn) -> int:
    cur = conn.cursor()
    cur.execute("UPDATE claims SET theme_id = NULL WHERE theme_id IN "
                "(SELECT id FROM claim_themes WHERE label LIKE 'auto-%')")
    cur.execute("DELETE FROM claim_themes WHERE label LIKE 'auto-%' RETURNING id")
    return len(cur.fetchall())


def seed_one(section: dict, args: argparse.Namespace) -> dict:
    """Worker for one textbook L1 section.

    Opens its own psycopg2 connection (psycopg2 connections are not
    thread-safe). Catches exceptions and returns a status dict so the
    main thread can report them without losing parallel progress.
    """
    sid = str(section["id"])
    content = section["content"] or ""
    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False
    try:
        descendants = fetch_descendant_ids(conn, sid)
        emb_1536 = mean_vector(fetch_embeddings(conn, descendants, 1536))
        emb_3072 = mean_vector(fetch_embeddings(conn, descendants, 3072))
        if not emb_1536 and not emb_3072:
            return {"status": "skip", "sid": sid, "reason": "no descendants with embeddings"}
        atoms = fetch_sample_atoms(conn, sid)
        try:
            label_obj = label_via_claude(content, atoms)
        except Exception as e:
            return {"status": "err", "sid": sid, "error": str(e)}
        label = label_obj["label"]
        description = label_obj["description"]
        if args.dry_run:
            return {"status": "dry", "sid": sid, "label": label}
        theme_id = insert_theme(conn, label, description, emb_1536, emb_3072, sid)
        n_assigned = assign_theme(conn, theme_id, descendants)
        update_theme_count(conn, theme_id)
        conn.commit()
        return {
            "status": "ok",
            "sid": sid,
            "label": label,
            "theme_id": theme_id,
            "n_assigned": n_assigned,
        }
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--drop-auto-after", action="store_true",
                    help="DELETE existing auto-NN themes after seeding completes (frees their 500 claim assignments).")
    ap.add_argument("--concurrency", type=int, default=8,
                    help="Number of parallel worker threads (default 8).")
    args = ap.parse_args()

    # Main-thread connection: used only for the initial section list and the
    # final --drop-auto-after audit. Each worker opens its own connection.
    main_conn = psycopg2.connect(args.database_url)
    main_conn.autocommit = False

    sections = fetch_textbook_l1_claims(main_conn, args.limit)
    if not sections:
        print("No unprocessed textbook L1 sections found.")
    else:
        print(f"Found {len(sections)} textbook L1 sections to seed. "
              f"Concurrency: {args.concurrency}")

    n_created = 0
    n_skipped = 0
    n_err = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(seed_one, s, args): s for s in sections}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                s = futures[fut]
                print(f"[fatal] {s.get('id', '?')}: {e}", file=sys.stderr)
                n_err += 1
                continue
            if res["status"] == "ok":
                print(f"[seed] {res['sid']} :: {res['label']}")
                print(f"       theme_id={res['theme_id']} assigned {res['n_assigned']} claims")
                n_created += 1
            elif res["status"] == "dry":
                print(f"[seed-dry] {res['sid']} :: {res['label']}")
                n_created += 1
            elif res["status"] == "skip":
                print(f"[skip] {res['sid']}: {res['reason']}")
                n_skipped += 1
            elif res["status"] == "err":
                print(f"[err] {res['sid']}: {res['error']}", file=sys.stderr)
                n_err += 1

    print(f"\nSeeded {n_created} themes; skipped {n_skipped}; errors {n_err}.")

    if args.drop_auto_after and not args.dry_run:
        # Capture audit first
        cur = main_conn.cursor()
        cur.execute("SELECT id, label, claim_count FROM claim_themes WHERE label LIKE 'auto-%'")
        rows = cur.fetchall()
        print(f"\nDropping {len(rows)} auto-NN themes:")
        for r in rows:
            print(f"  {r[0]} {r[1]} claim_count={r[2]}")
        n_dropped = drop_auto_themes(main_conn)
        main_conn.commit()
        print(f"Dropped {n_dropped} auto-NN themes.")

    main_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
