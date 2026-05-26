#!/usr/bin/env python3
"""Label claim themes with LLM-generated summaries via Claude CLI.

Ported from EpigraphV2/scripts/label_themes_llm.py. For each theme, sample
the top-10 nearest claims, send to Claude via the nested-CLI file-write
pattern, and store the generated label + description back to claim_themes.

API gap: public does not (yet) expose a PATCH endpoint for theme metadata,
so writes go through psycopg2 with the `epigraph_admin` role — per
CLAUDE.md, that role is reserved for "operations not yet exposed via API."
Until a PATCH /api/v1/themes/:id route lands, this script needs admin DB
creds. Reads of theme rows + sample claim content also use the same
connection for query consistency.

Why nested-CLI file-write (not stdout): Claude CLI's `result` field is
empty when invoked from inside another agent's session. The bridge-dev
pattern is to instruct the model to Write a JSON file, then poll for it
on disk. `--dangerously-skip-permissions` is required so the Write tool
runs unattended.

Usage:
    DATABASE_URL=postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph \\
    python3 scripts/label_themes_llm.py

    # Limit how many themes to label
    python3 scripts/label_themes_llm.py --limit 20

    # Dry run — show prompts without calling LLM
    python3 scripts/label_themes_llm.py --dry-run

    # Pin Claude CLI's cwd (defaults to the repo containing this script)
    python3 scripts/label_themes_llm.py --cli-cwd /path/to/workdir

Environment:
    DATABASE_URL  - Postgres connection string. epigraph_admin is required
                    for the UPDATE; epigraph_ro is sufficient for --dry-run.
"""

import argparse
import json
import os
import subprocess
import sys
import time

import psycopg2
import psycopg2.extras

psycopg2.extras.register_uuid()

DEFAULT_DATABASE_URL = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph"
RESULT_DIR = "/tmp/theme_labels"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CLI_CWD = os.path.dirname(SCRIPT_DIR)  # repo root


def load_themes_with_samples(conn, limit=None):
    """Load themes (ordered by claim_count desc) and their top-10 nearest claims."""
    themes = []
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        sql = """
            SELECT id, label, description, claim_count
            FROM claim_themes
            WHERE centroid IS NOT NULL
            ORDER BY claim_count DESC
        """
        if limit:
            sql += f" LIMIT {int(limit)}"
        cur.execute(sql)
        for theme in cur.fetchall():
            theme_id = theme["id"]
            # Top-10 claims most central to this theme. Joining on agents is
            # cosmetic (label includes the source for human review); the
            # LEFT JOIN keeps claims whose agent row has been pruned.
            cur.execute(
                """
                SELECT substring(c.content for 200) AS content,
                       COALESCE(a.display_name, 'unknown') AS agent
                FROM claims c
                LEFT JOIN agents a ON c.agent_id = a.id
                WHERE c.theme_id = %s
                  AND c.embedding IS NOT NULL
                ORDER BY c.embedding <=> (SELECT centroid FROM claim_themes WHERE id = %s)
                LIMIT 10
                """,
                (theme_id, theme_id),
            )
            samples = cur.fetchall()
            themes.append({
                "id": str(theme_id),
                "current_label": theme["label"] or "",
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

    prompt = f"""You are labeling a topic cluster in an epistemic knowledge graph.

This cluster contains {theme['claim_count']} claims. Here are the 10 most representative:

{samples_text}

Generate a concise topic label (3-8 words) and a one-sentence description of what this cluster covers.

Write your response as a JSON file to: {result_path}

The JSON must have exactly these fields:
{{
  "label": "short topic name (3-8 words)",
  "description": "One sentence describing the cluster's subject matter, methodology focus, or domain."
}}

Write ONLY the JSON file. No other output."""
    return prompt, result_path


def call_claude_cli(prompt, result_path, cwd, timeout=120):
    """Call Claude CLI with the nested file-write pattern."""
    try:
        subprocess.run(
            [
                "claude", "-p", prompt,
                "--output-format", "json",
                "--max-turns", "1",
                "--dangerously-skip-permissions",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT after {timeout}s", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("    ERROR: `claude` CLI not on PATH", file=sys.stderr)
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
    """Store the LLM-generated label and description (admin-role UPDATE)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE claim_themes
            SET label = %s, description = %s, updated_at = NOW()
            WHERE id = %s
            """,
            (label, description, theme_id),
        )
    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Label themes with LLM summaries")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
        help=f"Postgres URL (default: {DEFAULT_DATABASE_URL})",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Only label the top N themes by claim count",
    )
    parser.add_argument(
        "--cli-cwd", default=DEFAULT_CLI_CWD,
        help=f"Working directory for the Claude CLI subprocess "
             f"(default: {DEFAULT_CLI_CWD})",
    )
    parser.add_argument(
        "--relabel-all", action="store_true",
        help="Re-label every theme; default skips themes whose current label "
             "looks like an LLM-generated short string already.",
    )
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    os.makedirs(RESULT_DIR, exist_ok=True)

    print("Loading themes with sample claims...", file=sys.stderr)
    themes = load_themes_with_samples(conn, limit=args.limit)
    print(f"  {len(themes)} themes to consider", file=sys.stderr)

    labeled = 0
    skipped = 0
    failed = 0

    for i, theme in enumerate(themes):
        current = theme["current_label"]
        # Heuristic from V2: skip themes whose label is already short and
        # doesn't look like a placeholder ("auto-XX" stays in scope because
        # it's < 60 chars but lacks "defined as" — explicit fix below).
        is_placeholder = (
            not current
            or current.startswith("auto-")
            or len(current) >= 60
            or "is defined as" in current
            or "defined as:" in current
        )
        if not args.relabel_all and not is_placeholder:
            print(
                f"\nTheme {i+1}/{len(themes)}: SKIP (already labeled: {current})",
                file=sys.stderr,
            )
            skipped += 1
            continue

        print(
            f"\nTheme {i+1}/{len(themes)}: {theme['claim_count']} claims "
            f"(current: {current[:50] or '<none>'})",
            file=sys.stderr,
        )

        prompt, result_path = build_prompt(theme)

        if args.dry_run:
            print(f"  [DRY RUN] Would call Claude CLI", file=sys.stderr)
            print(f"  Samples: {len(theme['samples'])}", file=sys.stderr)
            continue

        # Clean previous result
        if os.path.exists(result_path):
            os.remove(result_path)

        result = call_claude_cli(prompt, result_path, cwd=args.cli_cwd)

        if result and "label" in result and "description" in result:
            update_theme(conn, theme["id"], result["label"], result["description"])
            print(
                f"  -> {result['label']}: {result['description'][:80]}",
                file=sys.stderr,
            )
            labeled += 1
        else:
            print(f"  FAILED — no valid JSON result", file=sys.stderr)
            failed += 1

    print(
        f"\nDone: {labeled} labeled, {skipped} skipped, {failed} failed",
        file=sys.stderr,
    )
    conn.close()


if __name__ == "__main__":
    main()
