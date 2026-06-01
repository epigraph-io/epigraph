#!/usr/bin/env python3
"""Label claim themes with LLM-generated summaries via Claude CLI.

For each theme, samples the top-10 nearest claims, sends them to Claude
via the nested CLI pattern (Write tool for output), and stores the
generated label + description back in claim_themes.

Uses the nested CLI file-write pattern from epiclaw-release/bridge-dev:
- Claude CLI result field is always empty in nested sessions
- Instruct Claude to Write a JSON result file
- Poll for the result file
- Use --dangerously-skip-permissions for unattended Write tool use

Usage:
    DATABASE_URL=postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph \
    python3 scripts/label_themes_llm.py

    # Dry run — show prompts without calling LLM
    python3 scripts/label_themes_llm.py --dry-run
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid

import psycopg2
import psycopg2.extras

psycopg2.extras.register_uuid()

RESULT_DIR = "/tmp/theme_labels"


def load_themes_with_samples(conn, limit=None):
    """Load themes and their top-10 nearest claims."""
    themes = []
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        sql = "SELECT id, label, description, claim_count FROM claim_themes ORDER BY claim_count DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        cur.execute(sql)
        for theme in cur.fetchall():
            theme_id = theme["id"]
            # Get top-10 claims assigned to this theme
            cur.execute("""
                SELECT substring(c.content for 200) as content,
                       a.display_name as agent
                FROM claims c
                JOIN agents a ON c.agent_id = a.id
                WHERE c.theme_id = %s
                  AND c.embedding IS NOT NULL
                ORDER BY c.embedding <=> (SELECT centroid FROM claim_themes WHERE id = %s)
                LIMIT 10
            """, (theme_id, theme_id))
            samples = cur.fetchall()
            themes.append({
                "id": str(theme_id),
                "current_label": theme["label"],
                "claim_count": theme["claim_count"],
                "samples": [{"content": s["content"], "agent": s["agent"]} for s in samples],
            })
    return themes


def build_prompt(theme):
    """Build the LLM prompt for theme labeling."""
    samples_text = "\n".join(
        f"  {i+1}. [{s['agent']}] {s['content']}"
        for i, s in enumerate(theme["samples"])
    )

    result_path = os.path.join(RESULT_DIR, f"theme_{theme['id'][:8]}.json")

    return f"""You are labeling a topic cluster in an epistemic knowledge graph.

This cluster contains {theme['claim_count']} claims. Here are the 10 most representative:

{samples_text}

Generate a concise topic label (3-8 words) and a one-sentence description of what this cluster covers.

Write your response as a JSON file to: {result_path}

The JSON must have exactly these fields:
{{
  "label": "short topic name (3-8 words)",
  "description": "One sentence describing the cluster's subject matter, methodology focus, or domain."
}}

Write ONLY the JSON file. No other output.""", result_path


def call_claude_cli(prompt, result_path, timeout=120):
    """Call Claude CLI with the nested file-write pattern."""
    try:
        proc = subprocess.run(
            ["claude", "-p", prompt,
             "--output-format", "json",
             "--model", "claude-haiku-4-5-20251001",
             "--max-turns", "1",
             "--dangerously-skip-permissions"],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd="/home/jeremy/epigraph",
        )
    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT after {timeout}s", file=sys.stderr)
        return None

    # Poll for the result file (CLI writes it via Write tool)
    for _ in range(10):
        if os.path.exists(result_path):
            with open(result_path) as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    pass
        time.sleep(1)

    print(f"    Result file not found: {result_path}", file=sys.stderr)
    return None


def update_theme(conn, theme_id, label, description):
    """Store the LLM-generated label and description."""
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE claim_themes
            SET label = %s, description = %s, updated_at = NOW()
            WHERE id = %s
        """, (label, description, theme_id))
    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Label themes with LLM summaries")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only label the top N themes by claim count")
    parser.add_argument("--relabel", action="store_true",
                        help="Re-label every theme, even ones already named")
    args = parser.parse_args()

    if not args.database_url:
        print("ERROR: --database-url or DATABASE_URL required", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(args.database_url)
    os.makedirs(RESULT_DIR, exist_ok=True)

    print("Loading themes with sample claims...", file=sys.stderr)
    themes = load_themes_with_samples(conn, limit=args.limit)
    print(f"  {len(themes)} themes to label", file=sys.stderr)

    labeled = 0
    failed = 0

    for i, theme in enumerate(themes):
        # Label only placeholder themes (auto-NN from cluster_themes.py); skip
        # anything already given a human/LLM name so re-runs are idempotent.
        # (--relabel forces re-labeling of every theme.)
        current = theme["current_label"]
        if not args.relabel and not re.match(r"^auto-\d+$", current):
            print(f"\nTheme {i+1}/{len(themes)}: SKIP (already named: {current})", file=sys.stderr)
            continue

        print(f"\nTheme {i+1}/{len(themes)}: {theme['claim_count']} claims "
              f"(current: {current[:50]}...)", file=sys.stderr)

        prompt, result_path = build_prompt(theme)

        if args.dry_run:
            print(f"  [DRY RUN] Would call Claude CLI", file=sys.stderr)
            print(f"  Samples: {len(theme['samples'])}", file=sys.stderr)
            continue

        # Clean previous result
        if os.path.exists(result_path):
            os.remove(result_path)

        result = call_claude_cli(prompt, result_path)

        if result and "label" in result and "description" in result:
            update_theme(conn, theme["id"], result["label"], result["description"])
            print(f"  -> {result['label']}: {result['description'][:80]}", file=sys.stderr)
            labeled += 1
        else:
            print(f"  FAILED — no valid JSON result", file=sys.stderr)
            failed += 1

    print(f"\nDone: {labeled} labeled, {failed} failed", file=sys.stderr)
    conn.close()


if __name__ == "__main__":
    main()
