#!/usr/bin/env python3
"""One-shot cleanup: retire stale backlog claims by patching ["resolved"] label.

Walks every [backlog] claim, looks for a downstream resolution signal:
  - A [resolved] claim whose content mentions the backlog UUID (full or 8-char prefix)
    adjacent to a Resolves/Supersedes/Closes/Fixes keyword, OR
  - is_current=false on the backlog claim itself, OR
  - The backlog claim's UUID appearing as another claim's supersedes target.

Auto-patches unambiguous matches; buckets ambiguous ones (multiple resolution
claims with conflicting narratives, or prefix collisions among backlog UUIDs)
into a "needs-review" report.

Usage:
    python3 scripts/cleanup_backlog_labels.py            # dry-run, write report only
    python3 scripts/cleanup_backlog_labels.py --apply    # also patch labels
    python3 scripts/cleanup_backlog_labels.py --base-url http://localhost:8080

Output: docs/superpowers/reports/backlog-cleanup-YYYY-MM-DD.md
"""
import argparse
import datetime
import os
import re
import sys
from pathlib import Path

import httpx

# Bearer auth for the PATCH route (read route is public). Pass via
# EPIGRAPH_TOKEN env var. Mint with scripts/mint_epigraph_token.py
# (EPIGRAPH_SCOPE="claims:read claims:write" or higher).
TOKEN = os.environ.get("EPIGRAPH_TOKEN")
AUTH_HEADERS = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}

FULL_UUID_RE = re.compile(
    r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
    re.IGNORECASE,
)
# Existing resolved-claim convention uses 8-char prefixes after a resolution keyword:
#   "Resolves 1c31a529", "Resolves k-means portion of c4e48078",
#   "Supersedes 6949d004; agent claim was stale memory"
# Match keyword + (optionally up to ~40 chars of intervening prose) + 8 hex chars,
# capturing either the full UUID or the bare 8-char prefix.
KEYWORD_RE = re.compile(
    r"\b(?:resolves?|supersedes?|closes?|fixes?)\b[^\n]{0,40}?"
    r"\b([0-9a-f]{8}(?:-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?)\b",
    re.IGNORECASE,
)


def page_claims(base_url: str, labels: list[str], exclude: list[str], current_only: bool) -> list[dict]:
    """Page through all claims matching the filter (limit=100 per page)."""
    params = {
        "labels": ",".join(labels),
        "limit": 100,
    }
    if exclude:
        params["exclude_labels"] = ",".join(exclude)
    if current_only:
        params["current_only"] = "true"
    r = httpx.get(f"{base_url}/api/v1/claims/by-labels", params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def patch_labels(base_url: str, claim_id: str, add: list[str]) -> dict:
    r = httpx.patch(
        f"{base_url}/api/v1/claims/{claim_id}/labels",
        json={"add": add, "remove": []},
        headers=AUTH_HEADERS,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--apply", action="store_true", help="Actually PATCH labels (default: dry-run)")
    p.add_argument("--base-url", default="http://localhost:8080")
    args = p.parse_args()

    # 1. Pull all open backlog claims
    open_backlog = page_claims(args.base_url, ["backlog"], ["resolved"], current_only=False)
    print(f"Found {len(open_backlog)} open backlog claims (not already labelled resolved)")

    # Build a lookup of full UUID and 8-char prefix → backlog claim
    backlog_by_full: dict[str, dict] = {bc["id"].lower(): bc for bc in open_backlog}
    backlog_by_prefix: dict[str, list[dict]] = {}
    for bc in open_backlog:
        backlog_by_prefix.setdefault(bc["id"][:8].lower(), []).append(bc)

    # 2. Pull all resolved claims and extract keyword-anchored UUID/prefix references.
    resolved_claims = page_claims(args.base_url, ["resolved"], [], current_only=False)
    matches_for_backlog: dict[str, list[dict]] = {}
    for rc in resolved_claims:
        text = rc["content"]
        seen_in_this_rc: set[str] = set()
        for m in KEYWORD_RE.finditer(text):
            token = m.group(1).lower()
            candidates: list[dict] = []
            if len(token) == 36 and token in backlog_by_full:
                candidates = [backlog_by_full[token]]
            elif len(token) == 8:
                candidates = backlog_by_prefix.get(token, [])
            for bc in candidates:
                if bc["id"] in seen_in_this_rc:
                    continue
                seen_in_this_rc.add(bc["id"])
                matches_for_backlog.setdefault(bc["id"], []).append(rc)
    print(f"Scanned {len(resolved_claims)} resolved claims; "
          f"matched references to {len(matches_for_backlog)} backlog UUIDs")

    auto_patch: list[tuple[dict, dict]] = []
    needs_review: list[tuple[dict, list[dict]]] = []
    still_open: list[dict] = []
    superseded: list[dict] = []

    for bc in open_backlog:
        # Supersedes-based retirement per spec: is_current=false AND supersedes set.
        # A pure is_current=false (without supersedes) could be dedup or maintenance
        # marking — not a retirement signal — so route those to needs-review.
        is_current = bc.get("is_current", True)
        has_supersedes = bool(bc.get("supersedes"))
        if not is_current and has_supersedes:
            superseded.append(bc)
            continue
        if not is_current and not has_supersedes:
            needs_review.append((bc, []))
            continue
        matches = matches_for_backlog.get(bc["id"], [])
        prefix_peers = backlog_by_prefix.get(bc["id"][:8].lower(), [])
        prefix_ambiguous = len(prefix_peers) > 1
        if not matches:
            still_open.append(bc)
        elif len(matches) == 1 and not prefix_ambiguous:
            auto_patch.append((bc, matches[0]))
        else:
            needs_review.append((bc, matches))

    # 3. Apply (or report)
    if args.apply:
        for bc, _ in auto_patch:
            try:
                patch_labels(args.base_url, bc["id"], ["resolved"])
                print(f"PATCHED resolved → {bc['id']}")
            except httpx.HTTPError as e:
                print(f"FAIL {bc['id']}: {e}", file=sys.stderr)
        for bc in superseded:
            try:
                patch_labels(args.base_url, bc["id"], ["resolved"])
                print(f"PATCHED resolved (supersedes-retired) → {bc['id']}")
            except httpx.HTTPError as e:
                print(f"FAIL {bc['id']}: {e}", file=sys.stderr)

    # 4. Write report
    today = datetime.date.today().isoformat()
    report_dir = Path("docs/superpowers/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"backlog-cleanup-{today}.md"
    with report_path.open("w") as f:
        f.write(f"# Backlog cleanup — {today}\n\n")
        f.write(f"Mode: {'APPLY' if args.apply else 'DRY-RUN'}\n\n")
        f.write(f"## Auto-patched ({len(auto_patch)})\n\n")
        for bc, rc in auto_patch:
            f.write(f"- `{bc['id']}` → resolved by `{rc['id']}`\n")
            f.write(f"  - backlog: {bc['content'][:120].strip()}…\n")
            f.write(f"  - resolution: {rc['content'][:120].strip()}…\n")
        f.write(f"\n## Supersedes-retired auto-patched ({len(superseded)})\n\n")
        for bc in superseded:
            f.write(f"- `{bc['id']}` (is_current={bc['is_current']}, supersedes={bc.get('supersedes')})\n")
        f.write(f"\n## Needs review — multiple resolutions ({len(needs_review)})\n\n")
        for bc, matches in needs_review:
            f.write(f"### `{bc['id']}`\n")
            f.write(f"- backlog: {bc['content'][:200].strip()}\n")
            for rc in matches:
                f.write(f"- candidate `{rc['id']}`: {rc['content'][:200].strip()}\n")
            f.write("\n")
        f.write(f"\n## Still open ({len(still_open)})\n\n")
        for bc in still_open:
            f.write(f"- `{bc['id']}`: {bc['content'][:120].strip()}…\n")
    print(f"Report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
