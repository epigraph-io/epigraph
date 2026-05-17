#!/usr/bin/env python3
"""Daily reconciler: catch backlog items that were resolved via free-text
"Resolves <UUID>" claims without using the resolve_backlog_item tool.

Scans open backlog claims, looks for [resolved] claims created in the past
RECON_WINDOW_DAYS that mention the backlog UUID. PATCHes unambiguous matches.
Ambiguous matches are appended to docs/superpowers/reports/reconciler-needs-review.log
for human triage.

Schedule: daily. Idempotent. Safe to run repeatedly.
"""
import argparse
import datetime
import os
import re
import sys
from pathlib import Path

import httpx

# Shared with cleanup_backlog_labels.py — same convention.
KEYWORD_RE = re.compile(
    r"\b(?:resolves?|supersedes?|closes?|fixes?)\b[^\n]{0,40}?"
    r"\b([0-9a-f]{8}(?:-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?)\b",
    re.IGNORECASE,
)
RECON_WINDOW_DAYS = int(os.environ.get("RECON_WINDOW_DAYS", "7"))


def page_claims(base_url: str, labels: list[str], exclude: list[str]) -> list[dict]:
    params = {"labels": ",".join(labels), "limit": 100}
    if exclude:
        params["exclude_labels"] = ",".join(exclude)
    r = httpx.get(f"{base_url}/api/v1/claims/by-labels", params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def patch_labels(base_url: str, claim_id: str, add: list[str]) -> dict:
    r = httpx.patch(
        f"{base_url}/api/v1/claims/{claim_id}/labels",
        json={"add": add, "remove": []},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def main() -> int:
    p = argparse.ArgumentParser()
    # Default DRY-RUN. Cron entry MUST pass --apply explicitly.
    p.add_argument("--apply", action="store_true", help="Actually PATCH labels (default: dry-run)")
    p.add_argument("--base-url", default=os.environ.get("EPIGRAPH_API", "http://localhost:8080"))
    args = p.parse_args()

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=RECON_WINDOW_DAYS)
    open_backlog = page_claims(args.base_url, ["backlog"], ["resolved"])
    backlog_by_full = {bc["id"].lower(): bc for bc in open_backlog}
    backlog_by_prefix: dict[str, list[dict]] = {}
    for bc in open_backlog:
        backlog_by_prefix.setdefault(bc["id"][:8].lower(), []).append(bc)

    # Page resolved claims; warn if we hit the limit.
    resolved_page = page_claims(args.base_url, ["resolved"], [])
    if len(resolved_page) >= 100:
        print(
            f"WARN: resolved page returned {len(resolved_page)} (page cap). "
            "Older resolution claims may be missed — extend the HTTP route with "
            "created_after or paginate.",
            file=sys.stderr,
        )
    resolved_recent = [
        rc for rc in resolved_page
        if datetime.datetime.fromisoformat(rc["created_at"].replace("Z", "+00:00")) >= cutoff
    ]

    matches_for_backlog: dict[str, list[dict]] = {}
    for rc in resolved_recent:
        seen_in_this_rc: set[str] = set()
        for m in KEYWORD_RE.finditer(rc["content"]):
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

    log_path = Path("docs/superpowers/reports/reconciler-needs-review.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    patched = 0
    review = 0
    for bc in open_backlog:
        matches = matches_for_backlog.get(bc["id"], [])
        prefix_peers = backlog_by_prefix.get(bc["id"][:8].lower(), [])
        prefix_ambiguous = len(prefix_peers) > 1
        if not matches:
            continue
        if len(matches) == 1 and not prefix_ambiguous:
            if args.apply:
                try:
                    patch_labels(args.base_url, bc["id"], ["resolved"])
                    patched += 1
                except httpx.HTTPError as e:
                    print(f"FAIL {bc['id']}: {e}", file=sys.stderr)
        else:
            with log_path.open("a") as f:
                f.write(
                    f"{datetime.datetime.utcnow().isoformat()} AMBIGUOUS {bc['id']} "
                    f"matches={[m['id'] for m in matches]} prefix_peers={len(prefix_peers)}\n"
                )
            review += 1

    print(f"Reconciler: patched={patched} needs_review={review} apply={args.apply}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
