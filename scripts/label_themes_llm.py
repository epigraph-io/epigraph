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

Why nested-CLI file-write, with stdout as the second source: Claude CLI's
`result` field is empty when invoked from inside another agent's session, so
the prompt asks the model to Write a JSON file and the script polls for it on
disk (`--dangerously-skip-permissions` lets the Write tool run unattended;
`--tools Write` makes it the only tool, and the CLI gets no database
credentials in its environment: call_claude_cli).
Outside such a session the model often answers inline instead (backlog
b6191a3c: about two answers in three on a --relabel-all run), so when no file
appears call_claude_cli reads the first JSON value in the envelope's `result`.
Either way the answer must be a dict with a non-empty string `label` and a
string `description` (valid_label_answer); anything else is refused.

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

Exit status: 0 when every theme (or neighbourhood) considered was labelled,
given the placeholder or skipped; EXIT_SOME_FAILED when at least one got no
valid answer and kept its old label. theme_pipeline reports a label step as
failed from this status alone, so a partial failure must not exit 0.
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
# How long call_claude_cli keeps looking for a result file the model wrote with
# its Write tool, when it answered neither on disk nor inline.
RESULT_POLL_ATTEMPTS = 10
RESULT_POLL_INTERVAL = 1.0
# Stored for a theme with no public member: there is no text every viewer may
# read to name it from (theme_lib.public_label_source). is_placeholder_label
# matches it, so a later run labels it once a public member joins.
NO_PUBLIC_MEMBER_LABEL = theme_lib.NO_PUBLIC_MEMBER_LABEL
# Exit status when at least one theme or neighbourhood got no valid answer.
EXIT_SOME_FAILED = 1


def exit_status(failed):
    """The process exit status for a run that left `failed` items unlabelled."""
    return EXIT_SOME_FAILED if failed else 0


def load_themes_with_samples(conn, limit=None):
    """Load EVERY theme (ordered by claim_count desc) and its top-10 nearest
    PUBLIC current claims (theme_lib.public_label_source). A theme with no
    public member comes back with no samples.

    Every theme, whatever its centroid: a theme whose centroid is 3072-d only
    (seed_themes_from_textbooks, for a section embedded only at 3072-d) or
    absent shows its stored label like any other, so --relabel-all must reach
    it too. Members are ranked by distance to the 1536-d centroid, else to the
    3072-d one, then by id, so a member with no embedding of the theme's
    dimension is still sampled, after the ranked ones. is_current is stated
    rather than implied by `embedding IS NOT NULL` (a superseded claim has no
    embedding)."""
    themes = []
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        sql = """
            SELECT id, label, description, claim_count
            FROM claim_themes
            ORDER BY claim_count DESC, id
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
                CROSS JOIN claim_themes t
                WHERE t.id = %s
                  AND c.theme_id = t.id
                  AND c.is_current
                  AND {theme_lib.public_label_source("c")}
                ORDER BY COALESCE(c.embedding <=> t.centroid,
                                  c.embedding_3072 <=> t.centroid_3072) NULLS LAST,
                         c.id
                LIMIT 10
                """,
                (theme_id,),
            )
            samples = cur.fetchall()
            themes.append({
                "id": str(theme_id),
                "current_label": theme["label"] or "",
                "claim_count": theme["claim_count"],
                "samples": [{"content": s["content"], "agent": s["agent"]} for s in samples],
            })
    return themes


# The placeholder values the prompt's schema shows. A model that echoes the
# schema back has not answered, so valid_label_answer refuses this label.
TEMPLATE_LABEL = "short topic name (3-8 words)"
TEMPLATE_DESCRIPTION = (
    "One sentence describing the cluster's subject matter, methodology focus, or domain."
)


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
  "label": "{TEMPLATE_LABEL}",
  "description": "{TEMPLATE_DESCRIPTION}"
}}

Write ONLY the JSON file. No other output."""
    return prompt, result_path


def valid_label_answer(answer):
    """`answer` when it is a usable label answer, else None: a dict whose
    `label` is a non-empty string other than the prompt's placeholder
    (TEMPLATE_LABEL) and whose `description` is a string."""
    if (
        isinstance(answer, dict)
        and isinstance(answer.get("label"), str)
        and answer["label"].strip()
        and answer["label"].strip() != TEMPLATE_LABEL
        and isinstance(answer.get("description"), str)
    ):
        return answer
    return None


def inline_label_answer(stdout):
    """The label answer the model gave inline, from `claude -p --output-format
    json` stdout, or None.

    stdout is the CLI's envelope; only its `result` string is the model's
    answer (the envelope is itself the first object on stdout, so stdout is
    never scanned raw). An error envelope is refused. In `result` the answer is
    the first top-level JSON value (one that starts at a `{` or `[`, which
    skips prose and a code fence around it) that valid_label_answer accepts.
    A value it refuses (a `[1]` citation, an echo of the prompt's schema) is
    skipped WHOLE, never searched inside, so a list wrapping a well-formed
    answer is still refused.
    """
    try:
        envelope = json.loads(stdout)
    except (TypeError, ValueError):
        return None
    if not isinstance(envelope, dict) or envelope.get("is_error"):
        return None
    text = envelope.get("result")
    if not isinstance(text, str):
        return None
    decoder = json.JSONDecoder()
    i = 0
    while i < len(text):
        if text[i] not in "{[":
            i += 1
            continue
        try:
            answer, end = decoder.raw_decode(text, i)
        except ValueError:
            i += 1
            continue
        if valid_label_answer(answer) is not None:
            return answer
        i = end
    return None


def _read_result_file(result_path):
    """The label answer in `result_path`, or None if it is absent, not JSON
    yet (still being written) or not a valid answer."""
    if not os.path.exists(result_path):
        return None
    with open(result_path) as f:
        try:
            return valid_label_answer(json.load(f))
        except json.JSONDecodeError:
            return None


# Environment variables never handed to the Claude CLI: the database
# credentials this script (and theme_pipeline's label step) run with.
_CLI_SECRET_ENV = ("PGPASSWORD",)


def claude_cli_env(environ=None):
    """The Claude CLI's environment: this process's, minus database credentials.

    The prompt quotes member text that any public-claim author controls, so
    the CLI is given only the Write tool (`--tools Write` in call_claude_cli);
    that is what stops an injected prompt from running commands. Dropping
    every *DATABASE_URL* variable and PGPASSWORD as well means a model that
    did get a shell would not find the DSN by listing its own environment.
    It is not a boundary on its own: a same-user process can still read its
    parent's /proc environ and cmdline. HOME, PATH and the CLI's own auth
    state pass through unchanged.
    """
    environ = os.environ if environ is None else environ
    return {
        k: v for k, v in environ.items()
        if "DATABASE_URL" not in k.upper() and k.upper() not in _CLI_SECRET_ENV
    }


def call_claude_cli(prompt, result_path, cwd, timeout=120):
    """Call Claude CLI and return its label answer ({label, description}) or None.

    The answer is taken from the result file the prompt asks the model to
    Write, else from the model's inline answer on stdout (inline_label_answer),
    else from the file once it appears within the poll window.

    The CLI runs with `--tools Write`: Write is the only tool the file-answer
    path needs, and `--dangerously-skip-permissions` would otherwise let a
    prompt injected through member text run Bash unattended. Its environment
    carries no database credentials (claude_cli_env).
    """
    try:
        proc = subprocess.run(
            [
                "claude", "-p", prompt,
                "--output-format", "json",
                "--model", "claude-haiku-4-5-20251001",
                "--max-turns", "1",
                "--tools", "Write",
                "--dangerously-skip-permissions",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env=claude_cli_env(),
        )
    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT after {timeout}s", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("    ERROR: `claude` CLI not on PATH", file=sys.stderr)
        return None

    answer = _read_result_file(result_path)
    if answer is not None:
        return answer
    answer = inline_label_answer(proc.stdout)
    if answer is not None:
        return answer

    # Neither yet: poll for the file (CLI writes it via the Write tool).
    for _ in range(RESULT_POLL_ATTEMPTS):
        time.sleep(RESULT_POLL_INTERVAL)
        answer = _read_result_file(result_path)
        if answer is not None:
            return answer

    print(f"    No valid answer: result file not found ({result_path}) "
          f"and no usable inline answer", file=sys.stderr)
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
    the newest completed run with algo = 'louvain'), or None.

    A louvain_bridge run (POST /api/v1/clusters/build-from-bridges) has no
    graph_neighborhoods rows and is never the run expand serves, so it must
    not be picked here either: labelling it would label nothing while expand
    kept serving the Louvain run's neighborhood-N placeholders."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT run_id::text FROM graph_cluster_runs WHERE algo = 'louvain' "
            "ORDER BY completed_at DESC LIMIT 1"
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
        if result:
            update_neighborhood(conn, nbr["id"], result["label"])
            print(f"  -> {result['label']}", file=sys.stderr)
            labeled += 1
        else:
            print("  FAILED — no valid JSON result", file=sys.stderr)
            failed += 1
    return labeled, placeholders, skipped, failed


def main():
    """Run the labeller; return the process exit status (exit_status)."""
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
             "(default: the latest Louvain run, the one the expand route serves)",
    )
    args = parser.parse_args()

    conn = psycopg2.connect(args.database_url)
    os.makedirs(RESULT_DIR, exist_ok=True)

    if args.neighborhoods:
        run_id = args.run_id or latest_cluster_run(conn)
        if run_id is None:
            print("No clustering run: nothing to label", file=sys.stderr)
            conn.close()
            return 0
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
        return exit_status(failed)

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

        if result:
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
    return exit_status(failed)


if __name__ == "__main__":
    sys.exit(main())
