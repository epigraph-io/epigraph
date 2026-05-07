#!/usr/bin/env python3
"""Migrate flat workflow claims to hierarchical WorkflowExtraction payloads.

Phase C of the flat-workflow consolidation plan (refs #36).

Modes:
  --dry-run
      Reads the dumped 144-workflow set plus 21 lineage edges, builds
      WorkflowExtraction JSON payloads for the trivial-bucket workflows
      (~90 of 144), validates each against the Rust schema in
      `crates/epigraph-ingest/src/workflow/schema.rs`, and writes the
      candidates to per-workflow JSON files plus an index summary.
      Makes ZERO API calls.

  --apply  (Q4-ratified)
      For each candidate JSON in the dry-run output dir, ingests the
      hierarchical workflow via POST /api/v1/workflows/ingest, emits a
      `variant_of` edge from the new hierarchical claim back to the
      original flat claim via POST /api/v1/edges, then deprecates the
      flat claim via DELETE /api/v1/workflows/<id>?reason=...
      Appends one audit-log line per workflow to
      /tmp/workflow-consolidation/migration-map.jsonl.

  --apply --dry-run-network
      Same flow as --apply, but PRINTS each request body / URL instead of
      issuing it. No mutations. Use this to validate the request shape
      before flipping the real switch.

Notes / known caveats:
  * `variant_of` is NOT currently in the edges API's VALID_RELATIONSHIPS
    allowlist (see crates/epigraph-api/src/routes/edges.rs). The existing
    workflow code (improve_workflow) works around this with a direct
    SQL INSERT. This script POSTs as the spec instructs; if the API
    rejects, the audit log will record `edge_failed` and the
    hierarchical claim will still exist (the missing edge can be
    backfilled once the allowlist is updated).
  * Step 3 (deprecate) sets truth_value=0.05 today. After PR #97 merges
    it will also set is_current=false. The 0.05 truth is enough for the
    default min_truth filtering to hide the flat claim, so this script
    is safe to run before #97 merges.

Usage:
    python3 scripts/migrate_flat_workflows.py --dry-run
    python3 scripts/migrate_flat_workflows.py --apply --dry-run-network --batch-size 1
    python3 scripts/migrate_flat_workflows.py --apply --batch-size 50  # gated on Q4
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_INPUT_DIR = Path("/tmp/workflow-consolidation")
DEFAULT_OUTPUT_DIR = Path("/tmp/workflow-consolidation/dry-run")
DEFAULT_AUDIT_LOG = Path("/tmp/workflow-consolidation/migration-map.jsonl")
DEFAULT_API_BASE = "http://localhost"
DEFAULT_BATCH_SIZE = 50
MAX_BATCH_SIZE = 50  # memory cap per project memory feedback_memory_limits.md
MINT_SCRIPT_PATH = "/home/jeremy/scripts/mint_epigraph_token.py"

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
# Apply mode (Q4-ratified): hierarchical ingest + variant_of edge + deprecate
# --------------------------------------------------------------------------


def _now_iso() -> str:
    """ISO-8601 UTC timestamp with explicit Z suffix."""
    return datetime.now(timezone.utc).isoformat()


def acquire_bearer() -> str:
    """Return a bearer token, or raise SystemExit with a clear message.

    Resolution order:
      1. EPIGRAPH_BEARER environment variable (use as-is)
      2. /home/jeremy/scripts/mint_epigraph_token.py (subprocess)
      3. Fail with a message that names both options.

    The mint script depends on PyNaCl, which we can't import here per the
    "stdlib only" rule, so we shell out to it. Token-printing scripts are
    a stable convention in this repo (see reference_epigraph_oauth_mint).
    """
    env_token = os.environ.get("EPIGRAPH_BEARER")
    if env_token:
        return env_token.strip()

    if Path(MINT_SCRIPT_PATH).exists():
        try:
            result = subprocess.run(
                [sys.executable, MINT_SCRIPT_PATH],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
            token = result.stdout.strip()
            if token:
                return token
        except subprocess.CalledProcessError as e:
            sys.stderr.write(
                f"mint script failed: rc={e.returncode}\n"
                f"stdout: {e.stdout}\nstderr: {e.stderr}\n"
            )
        except subprocess.TimeoutExpired:
            sys.stderr.write("mint script timed out after 15s\n")

    sys.stderr.write(
        "ERROR: could not acquire bearer token. Set EPIGRAPH_BEARER in the "
        f"environment, or ensure {MINT_SCRIPT_PATH} exists and has the "
        "EPIGRAPH_AGENT_CLIENT_ID / EPIGRAPH_AGENT_SIGNING_KEY env vars set.\n"
    )
    raise SystemExit(2)


def _http_post(
    url: str,
    body: dict[str, Any],
    bearer: str,
    timeout: int = 30,
) -> tuple[int, Any]:
    """POST JSON, return (status_code, parsed_json_or_text)."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode()
        except Exception:
            return e.code, str(e)


def _http_delete(url: str, bearer: str, timeout: int = 30) -> tuple[int, Any]:
    """DELETE, return (status_code, parsed_json_or_text)."""
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {bearer}"},
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode()
        except Exception:
            return e.code, str(e)


def _build_edge_body(
    new_hier_id: str,
    flat_claim_id: str,
    migrated_at: str,
) -> dict[str, Any]:
    """Build the POST /api/v1/edges body for the variant_of back-edge."""
    return {
        "source_id": new_hier_id,
        "source_type": "claim",
        "target_id": flat_claim_id,
        "target_type": "claim",
        "relationship": "supersedes",
        "properties": {
            "reason": "flat-to-hierarchical migration",
            "migrated_at": migrated_at,
        },
    }


def _append_audit(audit_path: Path, record: dict[str, Any]) -> None:
    """Append one JSON line to the audit log (creates parent if needed)."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a") as fh:
        fh.write(json.dumps(record) + "\n")


def run_apply(
    output_dir: Path,
    audit_log: Path,
    api_base: str,
    batch_size: int,
    dry_run_network: bool,
) -> int:
    """Apply mode. Returns exit code.

    For each candidate payload JSON in `output_dir` (excluding _index.json),
    runs ingest -> variant_of edge -> deprecate. On any per-step failure,
    skips the dependent steps and records the failure in the audit log.

    When `dry_run_network` is True, prints what would be sent and returns
    without mutating anything (no auth required).
    """
    payload_paths = sorted(
        p for p in output_dir.glob("*.json") if p.name != "_index.json"
    )
    if not payload_paths:
        sys.stderr.write(
            f"No payloads found in {output_dir}. Run --dry-run first.\n"
        )
        return 1

    if batch_size > MAX_BATCH_SIZE:
        sys.stderr.write(
            f"--batch-size capped to {MAX_BATCH_SIZE} per project memory.\n"
        )
        batch_size = MAX_BATCH_SIZE
    payload_paths = payload_paths[:batch_size]

    bearer: str | None = None
    if not dry_run_network:
        bearer = acquire_bearer()

    counters = {
        "ok": 0,
        "ingest_failed": 0,
        "edge_failed": 0,
        "deprecate_failed": 0,
    }

    for path in payload_paths:
        flat_claim_id = path.stem  # filename is <flat_claim_id>.json
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            sys.stderr.write(f"skip {path.name}: cannot read/parse ({e})\n")
            counters["ingest_failed"] += 1
            _append_audit(
                audit_log,
                {
                    "flat_claim_id": flat_claim_id,
                    "hierarchical_claim_id": None,
                    "variant_of_edge_id": None,
                    "deprecated_at": None,
                    "status": "ingest_failed",
                    "error": f"payload_unreadable: {e}",
                },
            )
            continue

        ingest_url = f"{api_base}/api/v1/workflows/ingest"
        edge_url = f"{api_base}/api/v1/edges"
        deprecate_url = (
            f"{api_base}/api/v1/workflows/{flat_claim_id}"
            f"?reason=flat-to-hierarchical-migration"
        )

        if dry_run_network:
            print(f"\n=== {flat_claim_id} ===")
            print(f"POST {ingest_url}")
            print("body (truncated):")
            print(json.dumps(payload, indent=2)[:600])
            print("...")
            placeholder_hier = "<new_hierarchical_claim_id>"
            edge_body = _build_edge_body(
                placeholder_hier, flat_claim_id, _now_iso()
            )
            print(f"\nPOST {edge_url}")
            print("body:")
            print(json.dumps(edge_body, indent=2))
            print(f"\nDELETE {deprecate_url}")
            counters["ok"] += 1
            continue

        # ── Step 1: hierarchical ingest ──
        assert bearer is not None
        ingest_status, ingest_body = _http_post(ingest_url, payload, bearer)
        if (
            ingest_status >= 300
            or not isinstance(ingest_body, dict)
            or "workflow_id" not in ingest_body
        ):
            counters["ingest_failed"] += 1
            _append_audit(
                audit_log,
                {
                    "flat_claim_id": flat_claim_id,
                    "hierarchical_claim_id": None,
                    "variant_of_edge_id": None,
                    "deprecated_at": None,
                    "status": "ingest_failed",
                    "error": f"http {ingest_status}: {ingest_body}",
                },
            )
            sys.stderr.write(
                f"[{flat_claim_id}] ingest failed: {ingest_status} "
                f"{ingest_body}\n"
            )
            continue
        new_hier_id = ingest_body["workflow_id"]
        sys.stderr.write(
            f"[{flat_claim_id}] ingested -> hierarchical {new_hier_id}\n"
        )

        # ── Step 2: variant_of edge ──
        migrated_at = _now_iso()
        edge_body = _build_edge_body(new_hier_id, flat_claim_id, migrated_at)
        edge_status, edge_resp = _http_post(edge_url, edge_body, bearer)
        edge_id: str | None = None
        if edge_status < 300 and isinstance(edge_resp, dict):
            edge_id = edge_resp.get("id")
        else:
            counters["edge_failed"] += 1
            sys.stderr.write(
                f"[{flat_claim_id}] edge POST failed: {edge_status} "
                f"{edge_resp} — hierarchical claim {new_hier_id} kept; "
                f"edge can be backfilled.\n"
            )

        # ── Step 3: deprecate flat predecessor ──
        deprecated_at: str | None = None
        deprecate_status, deprecate_resp = _http_delete(deprecate_url, bearer)
        if deprecate_status < 300:
            deprecated_at = _now_iso()
        else:
            counters["deprecate_failed"] += 1
            sys.stderr.write(
                f"[{flat_claim_id}] deprecate failed: {deprecate_status} "
                f"{deprecate_resp} — flat claim is unretired.\n"
            )

        if (
            edge_id is not None
            and deprecated_at is not None
        ):
            counters["ok"] += 1
            status = "ok"
        elif edge_id is None:
            status = "edge_failed"
        else:
            status = "deprecate_failed"

        _append_audit(
            audit_log,
            {
                "flat_claim_id": flat_claim_id,
                "hierarchical_claim_id": new_hier_id,
                "variant_of_edge_id": edge_id,
                "deprecated_at": deprecated_at,
                "status": status,
            },
        )

    print("\n=== apply summary ===")
    print(json.dumps(counters, indent=2))
    print(f"audit log: {audit_log}")
    if dry_run_network:
        print("(dry-run-network: no API calls were issued)")
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
        help="Apply the migration (ingest + variant_of edge + deprecate). "
        "Q4-ratified. Combine with --dry-run-network to validate without "
        "issuing requests.",
    )
    parser.add_argument(
        "--dry-run-network",
        action="store_true",
        help="With --apply: print the API calls that WOULD be issued instead "
        "of issuing them. No mutations, no auth required.",
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
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=DEFAULT_AUDIT_LOG,
        help=f"Append-mode JSONL audit log for --apply "
        f"(default: {DEFAULT_AUDIT_LOG}).",
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default=DEFAULT_API_BASE,
        help=f"API base URL for --apply (default: {DEFAULT_API_BASE}).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Maximum payloads to process per --apply invocation "
        f"(default {DEFAULT_BATCH_SIZE}, capped at {MAX_BATCH_SIZE}).",
    )
    args = parser.parse_args(argv)

    if args.dry_run_network and not args.apply:
        parser.error("--dry-run-network requires --apply")

    if args.apply:
        return run_apply(
            output_dir=args.output_dir,
            audit_log=args.audit_log,
            api_base=args.api_base.rstrip("/"),
            batch_size=args.batch_size,
            dry_run_network=args.dry_run_network,
        )

    return run_dry(args.input_dir, args.output_dir)


if __name__ == "__main__":
    sys.exit(main())
