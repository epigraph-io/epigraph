#!/usr/bin/env python3
"""Migrate flat workflow claims to hierarchical WorkflowExtraction payloads.

Phase C of the flat-workflow consolidation plan (refs #36): dry-run only.
Reads the dumped 144-workflow set plus 21 lineage edges, builds
WorkflowExtraction JSON payloads for the trivial-bucket workflows (~90 of
144), validates each against the Rust schema in
`crates/epigraph-ingest/src/workflow/schema.rs`, and writes the candidates to
per-workflow JSON files plus an index summary.

The script makes ZERO API calls and ZERO database writes. The `--apply`
flag is intentionally a stub that raises NotImplementedError; a follow-up
will wire the apply path.

Usage:
    python3 scripts/migrate_flat_workflows.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_INPUT_DIR = Path("/tmp/workflow-consolidation")
DEFAULT_OUTPUT_DIR = Path("/tmp/workflow-consolidation/dry-run")

# 12 rich re-author candidates (8-char prefix match per plan §4)
RICH_PREFIXES: tuple[str, ...] = (
    "0cc9d0d9",
    "7d68dd9d",
    "a04928e5",
    "47cc53fd",
    "b386b95b",
    "331960ee",
    "6d809147",
    "1808d794",
    "028c08c9",
    "e7f893c6",
    "389667fc",
    "0e13d2e9",
)

SLUG_MAX_LEN = 80


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def slugify(text: str) -> str:
    """Lowercase ASCII slug; non-alnum -> hyphen; trim hyphens; max 80."""
    if not text:
        return "untitled"
    # ASCII fold (drop non-ASCII)
    ascii_text = text.encode("ascii", "ignore").decode("ascii")
    lowered = ascii_text.lower()
    hyphenated = re.sub(r"[^a-z0-9]+", "-", lowered)
    trimmed = hyphenated.strip("-")
    truncated = trimmed[:SLUG_MAX_LEN].rstrip("-")
    return truncated or "untitled"


def parse_content(raw: Any) -> dict[str, Any] | None:
    """Parse the JSON-serialized content text. Returns None if not a dict."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def extract_structured(workflow: dict[str, Any]) -> dict[str, Any]:
    """Return a dict with the workflow's structured fields.

    Tries content (parsed as JSON) first, falls back to properties for
    workflows whose content is the literal "WORKFLOW: <goal>" sentinel.
    """
    out: dict[str, Any] = {}
    parsed = parse_content(workflow.get("content"))
    if parsed is not None:
        out.update(parsed)

    props = workflow.get("properties") or {}
    # Fields that may live on properties for the "WORKFLOW: ..." workflows
    for key in ("goal", "steps", "tags", "prerequisites", "expected_outcome"):
        if not out.get(key) and props.get(key) is not None:
            out[key] = props[key]
    return out


def extract_step_text(step: Any) -> tuple[str, str]:
    """Return (text, format_kind) where format_kind is one of
    'bare_string', 'object_text', 'other'.
    """
    if isinstance(step, str):
        return step, "bare_string"
    if isinstance(step, dict):
        if isinstance(step.get("text"), str):
            return step["text"], "object_text"
        # Try a couple of plausible alternates before giving up
        for alt in ("compound", "step", "description"):
            v = step.get(alt)
            if isinstance(v, str) and v:
                return v, "other"
        return "", "other"
    return str(step) if step is not None else "", "other"


# --------------------------------------------------------------------------
# Bucketing
# --------------------------------------------------------------------------


def classify(
    workflow: dict[str, Any],
    predecessor_ids: set[str],
) -> str:
    """Return one of: 'lineage', 'dedup', 'rich', 'trivial'."""
    wid = workflow["id"]
    props = workflow.get("properties") or {}
    labels = workflow.get("labels") or []

    if wid in predecessor_ids:
        return "lineage"
    if props.get("deduped_into") or "deduped" in labels:
        return "dedup"
    if any(wid.startswith(p) for p in RICH_PREFIXES):
        return "rich"
    return "trivial"


# --------------------------------------------------------------------------
# Slug assignment (over the entire 144-workflow universe)
# --------------------------------------------------------------------------


def assign_slugs(
    workflows: list[dict[str, Any]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Compute deterministic, collision-resolved slugs for ALL workflows.

    Returns (id -> slug map, list of collision records).

    Workflows are sorted by (created_at, id) so the slug taken first by a
    given base is stable across runs. Trivial collisions append `-v{gen}`,
    further collisions append `-{id[:6]}`.
    """
    ordered = sorted(workflows, key=lambda w: (w.get("created_at") or "", w["id"]))
    id_to_slug: dict[str, str] = {}
    slug_to_first_id: dict[str, str] = {}
    collisions_by_base: dict[str, list[str]] = {}

    for w in ordered:
        wid = w["id"]
        structured = extract_structured(w)
        goal = structured.get("goal") or ""
        if not goal:
            # Use the freeform content as a slug seed if there's no goal
            content = w.get("content") or ""
            goal = content if isinstance(content, str) else ""
        base = slugify(goal)

        if base not in slug_to_first_id:
            id_to_slug[wid] = base
            slug_to_first_id[base] = wid
            continue

        # Collision: append -v{generation}
        gen = (w.get("properties") or {}).get("generation", 0)
        candidate = f"{base}-v{gen}"
        if candidate in slug_to_first_id and slug_to_first_id[candidate] != wid:
            # Still colliding -> append -{id[:6]}
            candidate = f"{candidate}-{wid[:6]}"
        # Truncate again if we've blown 80 chars
        candidate = candidate[:SLUG_MAX_LEN].rstrip("-")
        id_to_slug[wid] = candidate
        slug_to_first_id.setdefault(candidate, wid)
        collisions_by_base.setdefault(base, [slug_to_first_id[base]]).append(wid)

    collisions = [
        {"slug": base, "ids": ids}
        for base, ids in collisions_by_base.items()
    ]
    return id_to_slug, collisions


# --------------------------------------------------------------------------
# Payload builder
# --------------------------------------------------------------------------


def build_payload(
    workflow: dict[str, Any],
    slug: str,
    parent_slug: str | None,
    step_format_counter: dict[str, int],
) -> tuple[dict[str, Any] | None, str | None, int]:
    """Return (payload | None, error | None, step_count).

    Validates the assembled payload structure; on validation failure
    returns (None, error_message, step_count_so_far).
    """
    structured = extract_structured(workflow)
    goal = structured.get("goal")
    if not goal or not isinstance(goal, str):
        return None, "missing or non-string goal", 0

    raw_steps = structured.get("steps") or []
    if not isinstance(raw_steps, list) or not raw_steps:
        return None, "missing or empty steps list", 0

    step_objects: list[dict[str, Any]] = []
    for raw_step in raw_steps:
        text, kind = extract_step_text(raw_step)
        step_format_counter[kind] = step_format_counter.get(kind, 0) + 1
        if not text.strip():
            # Skip empty steps rather than emit "compound": ""
            continue
        step_objects.append(
            {
                "compound": text,
                "rationale": "",
                "operations": [],
                "generality": [],
                "confidence": 0.8,
            }
        )

    if not step_objects:
        return None, "all steps empty after extraction", 0

    props = workflow.get("properties") or {}
    metadata = {
        "prerequisites": structured.get("prerequisites") or [],
        "flat_claim_id": workflow["id"],
        "use_count": int(props.get("use_count") or 0),
        "original_signature": props.get("signature"),
    }

    tags = structured.get("tags") or []
    if not isinstance(tags, list):
        tags = []

    expected_outcome = structured.get("expected_outcome")
    if not isinstance(expected_outcome, str):
        expected_outcome = None

    payload: dict[str, Any] = {
        "source": {
            "canonical_name": slug,
            "goal": goal,
            "generation": int(props.get("generation") or 0),
            "parent_canonical_name": parent_slug,
            "authors": [],
            "expected_outcome": expected_outcome,
            "tags": [t for t in tags if isinstance(t, str)],
            "metadata": metadata,
        },
        # `thesis` and `thesis_derivation` are #[serde(default)] in the Rust
        # schema; omitting them lets the deserializer fill in defaults.
        "phases": [
            {
                "title": "Execution",
                "summary": "",
                "steps": step_objects,
            }
        ],
        "relationships": [],
    }

    err = validate_payload(payload)
    if err:
        return None, err, len(step_objects)
    return payload, None, len(step_objects)


def validate_payload(payload: dict[str, Any]) -> str | None:
    """Lightweight structural validator mirroring required schema fields."""
    src = payload.get("source")
    if not isinstance(src, dict):
        return "source must be an object"
    if not isinstance(src.get("canonical_name"), str) or not src["canonical_name"]:
        return "source.canonical_name missing or empty"
    if not isinstance(src.get("goal"), str) or not src["goal"]:
        return "source.goal missing or empty"

    phases = payload.get("phases")
    if not isinstance(phases, list) or not phases:
        return "phases must be a non-empty list"
    for i, ph in enumerate(phases):
        if not isinstance(ph, dict):
            return f"phases[{i}] not an object"
        if not isinstance(ph.get("title"), str) or not ph["title"]:
            return f"phases[{i}].title missing"
        steps = ph.get("steps")
        if not isinstance(steps, list) or not steps:
            return f"phases[{i}].steps missing or empty"
        for j, st in enumerate(steps):
            if not isinstance(st, dict):
                return f"phases[{i}].steps[{j}] not an object"
            if not isinstance(st.get("compound"), str) or not st["compound"]:
                return f"phases[{i}].steps[{j}].compound missing or empty"
    return None


# --------------------------------------------------------------------------
# Main dry-run
# --------------------------------------------------------------------------


def run_dry(
    input_dir: Path,
    output_dir: Path,
) -> int:
    workflows_path = input_dir / "workflows.json"
    edges_path = input_dir / "lineage_edges.json"

    workflows = json.loads(workflows_path.read_text())
    edges = json.loads(edges_path.read_text())

    predecessor_ids: set[str] = {e["predecessor_id"] for e in edges}
    successor_to_predecessor: dict[str, str] = {}
    for e in edges:
        # If a successor has multiple predecessors, keep the first
        # encountered (deterministic given input ordering).
        successor_to_predecessor.setdefault(e["successor_id"], e["predecessor_id"])

    # 1. Compute slugs for every workflow up front (for parent refs).
    id_to_slug, collisions = assign_slugs(workflows)

    # 2. Bucket and emit.
    output_dir.mkdir(parents=True, exist_ok=True)

    counts = {
        "trivial": 0,
        "lineage": 0,
        "dedup": 0,
        "rich": 0,
    }
    written = 0
    failures: list[dict[str, Any]] = []
    step_format = {"bare_string": 0, "object_text": 0, "other": 0}
    total_steps = 0
    max_steps = 0

    for w in workflows:
        bucket = classify(w, predecessor_ids)
        counts[bucket] += 1
        if bucket != "trivial":
            continue

        wid = w["id"]
        slug = id_to_slug[wid]

        parent_slug: str | None = None
        pred_id = successor_to_predecessor.get(wid)
        if pred_id:
            parent_slug = id_to_slug.get(pred_id)

        payload, err, step_count = build_payload(
            w, slug, parent_slug, step_format
        )
        if err:
            failures.append({"id": wid, "error": err})
            continue

        out_path = output_dir / f"{wid}.json"
        out_path.write_text(json.dumps(payload, indent=2))
        written += 1
        total_steps += step_count
        max_steps = max(max_steps, step_count)

    index = {
        "count_in_bucket": counts["trivial"],
        "count_written": written,
        "count_skipped_lineage": counts["lineage"],
        "count_skipped_dedup": counts["dedup"],
        "count_skipped_rich": counts["rich"],
        "count_validation_failures": len(failures),
        "validation_failures": failures,
        "slug_collisions": collisions,
        "step_format_distribution": step_format,
        "max_steps": max_steps,
        "total_steps": total_steps,
    }
    (output_dir / "_index.json").write_text(json.dumps(index, indent=2))

    print(json.dumps(index, indent=2))
    print(f"\nWrote {written} payloads to {output_dir}")
    return 0


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Build candidate WorkflowExtraction JSONs into the output dir.",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="(stub) Actually persist the migrated workflows. Not yet wired.",
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"Directory containing workflows.json and lineage_edges.json "
        f"(default: {DEFAULT_INPUT_DIR}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to write per-workflow JSONs into "
        f"(default: {DEFAULT_OUTPUT_DIR}).",
    )
    args = parser.parse_args(argv)

    if args.apply:
        raise NotImplementedError(
            "--apply is a deliberate stub. A follow-up PR will wire the "
            "actual hierarchical ingest path. Use --dry-run for now."
        )

    return run_dry(args.input_dir, args.output_dir)


if __name__ == "__main__":
    sys.exit(main())
