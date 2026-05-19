#!/usr/bin/env python3
"""Anchor paper L3 atoms to textbook themes (and, for frontier papers, to
review-paper L2 paragraphs) via HNSW shortlist + claude is-instance-of judge.

For each paper claim:
  1. Embed not required — claim already has an embedding column.
  2. HNSW lookup against claim_themes.centroid → top-K theme candidates.
  3. For each candidate over threshold, run claude judge:
     "does this paper claim instantiate this textbook concept?"
  4. Highest-confidence yes -> claims.theme_id (primary anchor).
  5. Other yes/maybe verdicts -> INSTANTIATES edges with confidence + anchor_label.
  6. Frontier papers: also run an anchor pass over review-paper L2 paragraph
     embeddings; emit INSTANTIATES edges into review L2 targets.

Idempotent: skip paper claims whose properties.anchored_at is set.
Resumable: --limit + --skip-anchored cursoring.

Per spec 2026-05-18-cross-source-anchor §§Components 3 + 4.

Usage:
    python3 scripts/anchor_papers_to_themes.py --layer textbook --limit 50 --dry-run
    python3 scripts/anchor_papers_to_themes.py --layer textbook
    python3 scripts/anchor_papers_to_themes.py --layer review
    python3 scripts/anchor_papers_to_themes.py --layer both
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)

JUDGE_MODEL = "claude-haiku-4-5"  # informational only; the CLI picks the model

JUDGE_PROMPT = """\
You are deciding whether a paper claim is an instance of a textbook concept.

PAPER CLAIM:
{paper}

TEXTBOOK CONCEPT:
label: {label}
description: {description}

Question: does the paper claim instantiate (specialize, exemplify, or apply) \
the textbook concept? Be strict — coincidental keyword overlap is not \
instantiation.

Respond with ONLY a JSON object:
{{"verdict": "yes" | "maybe" | "no",
  "confidence": 0.0-1.0,
  "refined_anchor_label": "<= 60 chars: the bridging concept name (e.g. 'adatom mobility vs. temperature'); short and grep-able"}}

Do not include any other text.\
"""


def fetch_paper_claims(conn, layer: str, level: int, limit: Optional[int]) -> list[dict]:
    """Returns paper claims at given level that have embeddings and aren't yet anchored.

    Walks `decomposes_to` upward (leaf → root) tracking the original seed id so
    each row's `ancestor_id` is the deepest L0 reachable from that seed.
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # --layer review only needs frontier seed claims (review papers can't
    # anchor to themselves via the review-L2 bridge layer).
    seed_filter = ""
    if layer == "review":
        seed_filter = "AND ancestor.properties->>'document_type' = 'frontier'"
    q = f"""
        WITH RECURSIVE up(orig_id, cur_id, depth) AS (
          SELECT c.id, c.id, 0
          FROM claims c
          WHERE c.is_current = true
            AND c.properties->>'source_type' = 'Paper'
            AND c.properties->>'level' = '{level}'
            AND c.embedding IS NOT NULL
            AND (c.properties->>'anchored_at') IS NULL
          UNION ALL
          SELECT u.orig_id, e.source_id, u.depth + 1
          FROM edges e JOIN up u ON e.target_id = u.cur_id
          WHERE e.relationship = 'decomposes_to' AND u.depth < 5
        ),
        roots AS (
          SELECT DISTINCT ON (orig_id) orig_id, cur_id AS root_id
          FROM up
          ORDER BY orig_id, depth DESC
        )
        SELECT c.id, c.content,
               roots.root_id AS ancestor_id,
               ancestor.properties->>'document_type' AS doc_type
        FROM roots
        JOIN claims c ON c.id = roots.orig_id
        JOIN claims ancestor ON ancestor.id = roots.root_id
        WHERE TRUE {seed_filter}
        ORDER BY c.created_at ASC
    """
    if limit:
        q += f" LIMIT {int(limit)}"
    cur.execute(q)
    return list(cur.fetchall())


def hnsw_theme_candidates(conn, claim_id: str, top_k: int = 8, min_sim: float = 0.45) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT t.id, t.label, t.description, "
        "       t.properties->>'source_textbook_claim_id' AS source_textbook_claim_id, "
        "       1 - (t.centroid <=> c.embedding) AS sim "
        "FROM claim_themes t, claims c "
        "WHERE c.id = %s "
        "  AND t.centroid IS NOT NULL "
        "  AND t.properties ? 'source_textbook_claim_id' "
        "  AND 1 - (t.centroid <=> c.embedding) >= %s "
        "ORDER BY t.centroid <=> c.embedding "
        "LIMIT %s",
        (claim_id, min_sim, top_k),
    )
    return list(cur.fetchall())


def hnsw_review_l2_candidates(conn, claim_id: str, top_k: int = 8, min_sim: float = 0.45) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT rc.id, rc.content AS label, '' AS description, "
        "       rc.id::text AS source_textbook_claim_id, "
        "       1 - (rc.embedding <=> c.embedding) AS sim "
        "FROM claims c, claims rc "
        "JOIN edges e ON e.target_id = rc.id "
        "JOIN claims ancestor ON ancestor.id = e.source_id "
        "WHERE c.id = %s "
        "  AND rc.is_current = true "
        "  AND rc.properties->>'source_type' = 'Paper' "
        "  AND rc.properties->>'level' = '2' "
        "  AND rc.embedding IS NOT NULL "
        "  AND e.relationship = 'decomposes_to' "
        "  AND ancestor.properties->>'document_type' = 'review' "
        "  AND 1 - (rc.embedding <=> c.embedding) >= %s "
        "ORDER BY rc.embedding <=> c.embedding "
        "LIMIT %s",
        (claim_id, min_sim, top_k),
    )
    return list(cur.fetchall())


def judge_via_claude(paper_text: str, label: str, description: str) -> dict:
    prompt = JUDGE_PROMPT.format(paper=paper_text[:1500], label=label[:60], description=description[:250])
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True, text=True, timeout=90, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude exit {proc.returncode}: {proc.stderr[:300]}")
    envelope = json.loads(proc.stdout)
    text = envelope.get("result") if isinstance(envelope, dict) else None
    if not text:
        raise RuntimeError(f"empty claude result: {envelope}")
    text = text.strip().strip("`").lstrip("json").strip()
    parsed = json.loads(text)
    if parsed.get("verdict") not in {"yes", "maybe", "no"}:
        raise RuntimeError(f"bad verdict: {parsed}")
    return parsed


def insert_instantiates_edge(conn, source_id: str, target_id: str,
                             confidence: float, anchor_label: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, "
        "                   relationship, properties) "
        "VALUES (%s, %s, 'claim', 'claim', 'INSTANTIATES', %s::jsonb) "
        "ON CONFLICT DO NOTHING",
        (source_id, target_id,
         json.dumps({
             "confidence": confidence,
             "anchor_label": anchor_label,
             "judge_model": JUDGE_MODEL,
             "created_at": datetime.now(timezone.utc).isoformat(),
         })),
    )


def set_primary_theme(conn, claim_id: str, theme_id: str) -> None:
    cur = conn.cursor()
    cur.execute("UPDATE claims SET theme_id = %s WHERE id = %s", (theme_id, claim_id))


def mark_anchored(conn, claim_id: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "UPDATE claims SET properties = properties || %s::jsonb WHERE id = %s",
        (json.dumps({"anchored_at": datetime.now(timezone.utc).isoformat()}), claim_id),
    )


def anchor_one(conn, claim: dict, layer: str, top_k: int, min_sim: float,
               maybe_threshold: float, dry_run: bool) -> None:
    cid = str(claim["id"])
    content = claim["content"] or ""
    doc_type = claim["doc_type"] or "frontier"

    targets: list[tuple[str, dict]] = []
    if layer in {"textbook", "both"}:
        for cand in hnsw_theme_candidates(conn, cid, top_k=top_k, min_sim=min_sim):
            targets.append(("textbook", cand))
    if layer in {"review", "both"} and doc_type == "frontier":
        for cand in hnsw_review_l2_candidates(conn, cid, top_k=top_k, min_sim=min_sim):
            targets.append(("review", cand))

    if not targets:
        print(f"[noshort] {cid} :: {content[:60]}")
        if not dry_run:
            mark_anchored(conn, cid)
            conn.commit()
        return

    verdicts: list[tuple[str, dict, dict]] = []
    for layer_name, cand in targets:
        try:
            v = judge_via_claude(content, cand["label"] or "", cand["description"] or "")
        except Exception as e:
            print(f"[err] {cid} -> {cand['id']}: {e}", file=sys.stderr)
            continue
        verdicts.append((layer_name, cand, v))

    yes_or_strong_maybe = [
        (ln, c, v) for ln, c, v in verdicts
        if v["verdict"] == "yes" or (v["verdict"] == "maybe" and float(v.get("confidence", 0)) >= maybe_threshold)
    ]
    if not yes_or_strong_maybe:
        print(f"[noanchor] {cid} :: {content[:60]}")
        if not dry_run:
            mark_anchored(conn, cid)
            conn.commit()
        return

    yes_or_strong_maybe.sort(key=lambda t: float(t[2].get("confidence", 0)), reverse=True)
    primary_layer, primary_cand, primary_verdict = yes_or_strong_maybe[0]

    print(f"[anchor] {cid} -> {primary_layer}:{primary_cand['id']} "
          f"({primary_verdict['verdict']} conf={primary_verdict.get('confidence', 0):.2f}) "
          f"{primary_verdict.get('refined_anchor_label', '')[:50]}")

    if dry_run:
        return

    # Primary: textbook theme → theme_id; review L2 → INSTANTIATES only (no theme_id flip).
    if primary_layer == "textbook":
        set_primary_theme(conn, cid, primary_cand["id"])
        textbook_l1 = primary_cand["source_textbook_claim_id"]
        if textbook_l1:
            insert_instantiates_edge(conn, cid, textbook_l1,
                                     float(primary_verdict.get("confidence", 0.5)),
                                     primary_verdict.get("refined_anchor_label", primary_cand["label"]))
    else:
        insert_instantiates_edge(conn, cid, primary_cand["id"],
                                 float(primary_verdict.get("confidence", 0.5)),
                                 primary_verdict.get("refined_anchor_label", primary_cand["label"]))

    # Secondaries
    for layer_name, cand, v in yes_or_strong_maybe[1:]:
        target_id = cand["source_textbook_claim_id"] if layer_name == "textbook" else cand["id"]
        if not target_id:
            continue
        insert_instantiates_edge(conn, cid, target_id,
                                 float(v.get("confidence", 0.5)),
                                 v.get("refined_anchor_label", cand["label"]))

    mark_anchored(conn, cid)
    conn.commit()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--layer", choices=["textbook", "review", "both"], default="both")
    ap.add_argument("--level", type=int, default=3, help="Paper claim level to anchor (default 3 = atoms).")
    ap.add_argument("--top-k", type=int, default=8)
    ap.add_argument("--min-sim", type=float, default=0.45)
    ap.add_argument("--maybe-threshold", type=float, default=0.6)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    claims = fetch_paper_claims(conn, args.layer, args.level, args.limit)
    print(f"Anchoring {len(claims)} paper L{args.level} claims (layer={args.layer}).")

    for c in claims:
        try:
            anchor_one(conn, c, args.layer, args.top_k, args.min_sim,
                       args.maybe_threshold, args.dry_run)
        except Exception as e:
            print(f"[fatal] {c['id']}: {e}", file=sys.stderr)
            conn.rollback()

    return 0


if __name__ == "__main__":
    sys.exit(main())
