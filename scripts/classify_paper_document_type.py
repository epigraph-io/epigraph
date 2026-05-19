#!/usr/bin/env python3
"""Classify each paper L0 claim as 'review' or 'frontier'.

Sets properties.document_type and properties.document_type_confidence on
the L0 claim row via a PATCH through the EpiGraph claims API. Descendants
inherit at query time via decomposes_to walk; no denormalisation.

LLM: spawns `claude -p` per paper. Per feedback_claude_cli_oauth.md we never
import the Anthropic SDK directly.

Idempotent: skips L0 papers that already have a document_type set.
Per spec 2026-05-18-cross-source-anchor-design.md §Component 1.

Usage:
    python3 scripts/classify_paper_document_type.py
    python3 scripts/classify_paper_document_type.py --limit 5 --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Optional

import psycopg2
import psycopg2.extras

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _api_client import EpiGraphClient

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)

PROMPT_TEMPLATE = """\
You are classifying an academic paper as either a REVIEW article or a FRONTIER \
(primary research) article. A review article synthesizes existing literature, \
typically cites many primary sources, and integrates findings across a subfield. \
A frontier article reports new experimental, observational, or theoretical results.

Title: {title}

Opening content:
{opening}

Respond with ONLY a JSON object of the form:
{{"document_type": "review" | "frontier", "confidence": 0.0-1.0, "reason": "one short sentence"}}

Do not include any other text.\
"""


def fetch_paper_l0_claims(conn, limit: Optional[int]) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    q = (
        "SELECT id, content, properties "
        "FROM claims "
        "WHERE is_current = true "
        "  AND properties->>'source_type' = 'Paper' "
        "  AND properties->>'level' = '0' "
        "  AND (properties->>'document_type') IS NULL "
        "ORDER BY created_at ASC"
    )
    if limit:
        q += f" LIMIT {int(limit)}"
    cur.execute(q)
    return list(cur.fetchall())


def fetch_first_l1_child(conn, parent_id: str) -> Optional[str]:
    cur = conn.cursor()
    cur.execute(
        "SELECT c.content FROM edges e JOIN claims c ON c.id = e.target_id "
        "WHERE e.source_id = %s AND e.relationship = 'decomposes_to' "
        "  AND c.properties->>'level' = '1' "
        "ORDER BY e.created_at ASC LIMIT 1",
        (parent_id,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def classify_via_claude(title: str, opening: str) -> dict:
    prompt = PROMPT_TEMPLATE.format(title=title, opening=opening[:2000])
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude CLI exit {proc.returncode}: {proc.stderr[:400]}")
    envelope = json.loads(proc.stdout)
    text = envelope.get("result") if isinstance(envelope, dict) else None
    if not text:
        raise RuntimeError(f"claude returned empty result: {envelope}")
    text = text.strip().strip("`").lstrip("json").strip()
    parsed = json.loads(text)
    if parsed.get("document_type") not in {"review", "frontier"}:
        raise RuntimeError(f"unexpected document_type: {parsed}")
    return parsed


def patch_claim(api: EpiGraphClient, claim_id: str, document_type: str, confidence: float, reason: str) -> None:
    """PATCH /api/v1/claims/:id to merge document_type metadata into properties."""
    resp = api.patch(
        f"/api/v1/claims/{claim_id}",
        json={
            "properties": {
                "document_type": document_type,
                "document_type_confidence": confidence,
                "document_type_reason": reason,
            }
        },
    )
    resp.raise_for_status()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true", help="classify but do not write")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    # Initialize API client for PATCH writes (requires claims:write scope for bearer auth).
    api = EpiGraphClient(scopes=["claims:write"])

    papers = fetch_paper_l0_claims(conn, args.limit)
    if not papers:
        print("No unclassified paper L0 claims found.")
        return 0
    print(f"Found {len(papers)} paper L0 claims to classify.")

    for p in papers:
        claim_id = str(p["id"])
        title = (p["content"] or "")[:300]
        opening = fetch_first_l1_child(conn, claim_id) or title
        try:
            result = classify_via_claude(title, opening)
        except Exception as e:
            print(f"[err] {claim_id}: {e}", file=sys.stderr)
            continue
        dt = result["document_type"]
        conf = float(result.get("confidence", 0.5))
        reason = result.get("reason", "")
        print(f"[{dt:8s} conf={conf:.2f}] {claim_id} :: {title[:80]}")
        if not args.dry_run:
            patch_claim(api, claim_id, dt, conf, reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
