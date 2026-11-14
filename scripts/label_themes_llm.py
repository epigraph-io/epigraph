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

    # Name the graph neighbourhoods of the latest clustering run instead
    # (graph_neighborhoods.label, served by GET /api/v1/graph/themes/:id/expand)
    python3 scripts/label_themes_llm.py --neighborhoods [--run-id <uuid>]

Neighbourhoods: the clustering job (epigraph-jobs cluster_graph) writes a fresh
set of `graph_neighborhoods` rows on every run, each labelled `neighborhood-N`,
and the expand route serves only the latest run. Run `--neighborhoods` after
each clustering run; until then that run's neighbourhoods show their
placeholders. Samples are public members only (theme_lib.public_label_source),
as for themes.

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
import uuid

import psycopg2
import psycopg2.extras

import theme_lib  # noqa: E402  (scripts/ is on sys.path when run as a script)
from maintenance_dsn import maintenance_dsn

psycopg2.extras.register_uuid()

DEFAULT_DATABASE_URL = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph"
RESULT_DIR = "/tmp/theme_labels"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CLI_CWD = os.path.dirname(SCRIPT_DIR)  # repo root
# Stored for a theme with no public member: there is no text every viewer may
# read to name it from (theme_lib.public_label_source). is_placeholder_label
# matches it, so a later run labels it once a public member joins.
NO_PUBLIC_MEMBER_LABEL = theme_lib.NO_PUBLIC_MEMBER_LABEL


def load_themes_with_samples(conn, limit=None):
    """Load themes (ordered by claim_count desc) and their top-10 nearest
    PUBLIC claims (theme_lib.public_label_source). A theme with no public
    member comes back with no samples."""
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
            # Top-10 public claims most central to this theme. Joining on
            # agents is cosmetic (label includes the source for human review);
            # the LEFT JOIN keeps claims whose agent row has been pruned. Only
            # public, non-intake members are sampled: the stored label and
            # description are shown to every viewer of any member
            # (theme_lib.public_label_source).
            cur.execute(
                f"""
                SELECT substring(c.content for 200) AS content,
                       COALESCE(a.display_name, 'unknown') AS agent
                FROM claims c
                LEFT JOIN agents a ON c.agent_id = a.id
                WHERE c.theme_id = %s
                  AND c.embedding IS NOT NULL
                  AND {theme_lib.public_label_source("c")}
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


def build_prompt(theme, kind="theme"):
    """Build the LLM prompt for theme (or, with kind="neighborhood", graph
    neighbourhood) labeling. The kind also prefixes the result file, so a
    theme and a neighbourhood never share one."""
    samples_text = "\n".join(
        f"  {i+1}. [{s['agent']}] {s['content']}"
        for i, s in enumerate(theme["samples"])
    )

    result_path = os.path.join(RESULT_DIR, f"{kind}_{theme['id'][:8]}.json")
    what = "topic cluster" if kind == "theme" else "sub-topic neighbourhood of a topic"

    prompt = f"""You are labeling a {what} in an epistemic knowledge graph.

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
                "--model", "claude-haiku-4-5-20251001",
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


def is_placeholder_label(label):
    """True when `label` is not a real LLM-written name and should be (re)labelled.

    Heuristic from V2: a short label is taken as already named unless it is a
    generated placeholder. Placeholders are `auto-NN` (theme_cluster),
    `cluster-NN` (the cluster_labels fallback that project_to_themes copies
    onto a theme, and split_theme's `cluster-split-...` parts),
    NO_PUBLIC_MEMBER_LABEL (a theme no public member could name), and long or
    definitional strings (the semicolon-joined nearest-claim excerpts).
    """
    return (
        not label
        or label == NO_PUBLIC_MEMBER_LABEL
        or label.startswith("auto-")
        or label.startswith("cluster-")
        or len(label) >= 60
        or "is defined as" in label
        or "defined as:" in label
    )


def _is_uuid(text):
    try:
        uuid.UUID(text)
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def is_neighborhood_placeholder_label(label):
    """True when a graph neighbourhood's label is not a real name.

    Every theme placeholder (is_placeholder_label), plus the clustering job's
    `neighborhood-N` and a bare UUID (the dominant frame id an older job
    stored as the label).
    """
    return (
        is_placeholder_label(label)
        or label.startswith("neighborhood-")
        or _is_uuid(label)
    )


def latest_cluster_run(conn):
    """The clustering run the expand route serves (ClusterRunRepository::latest:
    newest completed_at), or None."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT run_id::text FROM graph_cluster_runs ORDER BY completed_at DESC LIMIT 1"
        )
        row = cur.fetchone()
    return row[0] if row else None


def load_neighborhoods_with_samples(conn, run_id, limit=None):
    """Load run `run_id`'s graph neighbourhoods (largest first) and up to 10 of
    each one's current PUBLIC members (theme_lib.public_label_source), highest
    pignistic probability first. `claim_count` is the number of such members,
    so nothing about private members reaches the prompt. A neighbourhood with
    no public member comes back with no samples."""
    out = []
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        sql = """
            SELECT id, label FROM graph_neighborhoods
            WHERE run_id = %s
            ORDER BY size DESC, id
        """
        if limit:
            sql += f" LIMIT {int(limit)}"
        cur.execute(sql, (run_id,))
        for nbr in cur.fetchall():
            cur.execute(
                f"""
                SELECT substring(c.content for 200) AS content,
                       COALESCE(a.display_name, 'unknown') AS agent,
                       COUNT(*) OVER () AS public_members
                FROM claim_neighborhood_membership m
                JOIN claims c ON c.id = m.claim_id
                LEFT JOIN agents a ON c.agent_id = a.id
                WHERE m.run_id = %s AND m.neighborhood_id = %s
                  AND c.is_current
                  AND {theme_lib.public_label_source("c")}
                ORDER BY c.pignistic_prob DESC NULLS LAST, c.id
                LIMIT 10
                """,
                (run_id, nbr["id"]),
            )
            samples = cur.fetchall()
            out.append({
                "id": str(nbr["id"]),
                "current_label": nbr["label"] or "",
                "claim_count": samples[0]["public_members"] if samples else 0,
                "samples": [{"content": s["content"], "agent": s["agent"]} for s in samples],
            })
    return out


def update_neighborhood(conn, neighborhood_id, label):
    """Store a neighbourhood's label (admin-role UPDATE)."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE graph_neighborhoods SET label = %s WHERE id = %s",
            (label, neighborhood_id),
        )
    conn.commit()


def label_neighborhoods(conn, run_id, limit=None, relabel_all=False, dry_run=False,
                        cli_cwd=DEFAULT_CLI_CWD):
    """Name run `run_id`'s neighbourhoods from public members only. Returns
    (labeled, placeholders, skipped, failed)."""
    nbrs = load_neighborhoods_with_samples(conn, run_id, limit=limit)
    print(f"  {len(nbrs)} neighbourhoods in run {run_id}", file=sys.stderr)
    labeled = placeholders = skipped = failed = 0
    for i, nbr in enumerate(nbrs):
        current = nbr["current_label"]
        if not relabel_all and not is_neighborhood_placeholder_label(current):
            skipped += 1
            continue
        print(f"\nNeighbourhood {i+1}/{len(nbrs)} (current: {current[:50] or '<none>'})",
              file=sys.stderr)
        if not nbr["samples"]:
            if dry_run:
                print(f"  [DRY RUN] Would store {NO_PUBLIC_MEMBER_LABEL}", file=sys.stderr)
                continue
            update_neighborhood(conn, nbr["id"], NO_PUBLIC_MEMBER_LABEL)
            placeholders += 1
            continue
        prompt, result_path = build_prompt(nbr, kind="neighborhood")
        if dry_run:
            print(f"  [DRY RUN] Would call Claude CLI ({len(nbr['samples'])} samples)",
                  file=sys.stderr)
            continue
        if os.path.exists(result_path):
            os.remove(result_path)
        result = call_claude_cli(prompt, result_path, cwd=cli_cwd)
        if result and result.get("label"):
            update_neighborhood(conn, nbr["id"], result["label"])
            print(f"  -> {result['label']}", file=sys.stderr)
            labeled += 1
        else:
            print("  FAILED — no valid JSON result", file=sys.stderr)
            failed += 1
    return labeled, placeholders, skipped, failed


def main():
    parser = argparse.ArgumentParser(description="Label themes with LLM summaries")
    parser.add_argument(
        "--database-url",
        default=maintenance_dsn(DEFAULT_DATABASE_URL),
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
    parser.add_argument(
        "--neighborhoods", action="store_true",
        help="Label the graph neighbourhoods of one clustering run "
             "(graph_neighborhoods.label) instead of themes",
    )
    parser.add_argument(
        "--run-id", default=None,
        help="With --neighborhoods: the graph_cluster_runs run to label "
             "(default: the latest, the one the expand route serves)",
    )
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    os.makedirs(RESULT_DIR, exist_ok=True)

    if args.neighborhoods:
        run_id = args.run_id or latest_cluster_run(conn)
        if run_id is None:
            print("No clustering run: nothing to label", file=sys.stderr)
            conn.close()
            return
        labeled, placeholders, skipped, failed = label_neighborhoods(
            conn, run_id, limit=args.limit, relabel_all=args.relabel_all,
            dry_run=args.dry_run, cli_cwd=args.cli_cwd,
        )
        print(
            f"\nDone: {labeled} labeled, {placeholders} without a public member, "
            f"{skipped} skipped, {failed} failed",
            file=sys.stderr,
        )
        conn.close()
        return

    print("Loading themes with sample claims...", file=sys.stderr)
    themes = load_themes_with_samples(conn, limit=args.limit)
    print(f"  {len(themes)} themes to consider", file=sys.stderr)

    labeled = 0
    placeholders = 0
    skipped = 0
    failed = 0

    for i, theme in enumerate(themes):
        current = theme["current_label"]
        if not args.relabel_all and not is_placeholder_label(current):
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

        if not theme["samples"]:
            # No public member: store the placeholder (replacing any label an
            # earlier run built from private text) and make no LLM call.
            if args.dry_run:
                print(f"  [DRY RUN] Would store {NO_PUBLIC_MEMBER_LABEL}", file=sys.stderr)
                continue
            update_theme(conn, theme["id"], NO_PUBLIC_MEMBER_LABEL, "")
            print(f"  -> {NO_PUBLIC_MEMBER_LABEL} (no public member)", file=sys.stderr)
            placeholders += 1
            continue

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
        f"\nDone: {labeled} labeled, {placeholders} without a public member, "
        f"{skipped} skipped, {failed} failed",
        file=sys.stderr,
    )
    conn.close()


if __name__ == "__main__":
    main()
