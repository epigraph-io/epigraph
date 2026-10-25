#!/usr/bin/env python3
"""Fuzzy / semantic dedup pass over the claims table.

Consumes a precomputed semantic-dedup.json snapshot (cosine >= threshold over
claim embeddings) produced by the GUI's offline analysis. For each group, picks
a canonical claim and marks every other member a duplicate of it through the
API, `POST /api/v1/claims/{dup}/dedup {"canonical_id": ...}`: the same act as
MCP `mark_duplicate`. That act retires the duplicate (`supersedes = canonical`,
`is_current = false`, both embeddings nulled), writes its `same_as` identity
edge carrying `properties.dedup` (so `unmark_duplicate` can reverse it and
`label_dedup_index_view` reads it), and runs the administrative cascade that
moves its evidence, edges and mass functions onto the canonical with a revert
record, plus the belief re-derivation.

The database is READ ONLY here (a read-only session): it picks canonicals and
skips members already retired. Until 2026-10 the script marked duplicates with
its own SQL (a raw `UPDATE claims` and hand-written, lossy re-pointing), which
wrote no identity edge, so those marks cannot be un-marked and the index view
does not see them. Backfilling identity edges for marks made that way is a
separate operator task, not this script's.

This is the *S3 fuzzy* layer (cross-agent semantic equivalence). The S2
content-hash-keyed dedup that gates migration 107 is a separate tool.

Default mode is dry-run: it reports what it would mark and sends nothing.
`--execute` needs a bearer token (`--token`, or EPIGRAPH_TOKEN) and refuses to
start without one. The endpoint needs the `claims:write` scope and write
authority over both claims, so a cross-agent cluster needs a token that also
carries `claims:admin`. Each duplicate is one
request; a refused one (HTTP status and body) is reported, the rest of the run
continues, and the run exits 1.

Usage:
    python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json
    EPIGRAPH_TOKEN=... python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute
    EPIGRAPH_TOKEN=... python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute --limit 100

Skips:
- A member that is not current, or already carries a `supersedes` pointer, is
  never picked as the canonical; as a duplicate it is skipped and counted as
  `duplicates_skipped_already_superseded` (the endpoint refuses that case too),
  unless it is already marked onto this cluster's canonical (an earlier run),
  which is passed over silently.
- A request that gets no HTTP answer (refused, reset, timed out) counts as a
  refusal for that duplicate; the cluster's other marks still count.
- A member labelled `deduped` (a pre-2026-10 mark by this script) is treated
  the same way.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field

import psycopg2
import psycopg2.extras

from maintenance_dsn import maintenance_dsn

DEFAULT_API_BASE = "http://127.0.0.1:8080"
DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)
DEFAULT_INPUT_PATH = "/home/jeremy/epigraph-gui/public/semantic-dedup.json"


@dataclass
class ClusterStats:
    canonical_id: str
    duplicate_count: int = 0
    duplicates_marked: int = 0
    duplicates_refused: int = 0
    duplicates_skipped_already_superseded: int = 0
    refusals: list[str] = field(default_factory=list)


@dataclass
class TotalStats:
    clusters_processed: int = 0
    clusters_skipped_already_deduped: int = 0
    clusters_failed: int = 0
    duplicates: int = 0
    duplicates_marked: int = 0
    duplicates_refused: int = 0
    duplicates_skipped_already_superseded: int = 0
    failures: list[str] = field(default_factory=list)


def load_groups(path: str) -> list[dict]:
    with open(path) as fh:
        snapshot = json.load(fh)
    if "groups" not in snapshot:
        sys.exit(f"input {path} missing 'groups' field")
    return snapshot["groups"]


def pick_canonical(cur, member_ids: list[str], suggested_rep: str) -> str | None:
    """Pick the canonical claim id for a cluster.

    Only a live member (exists, current) can be the canonical; the `deduped`
    label of a pre-2026-10 mark counts only while the claim is retired. Prefers the rep id from the input snapshot when it is live;
    otherwise picks by (trace_count, mf_count, edge_count) descending. Returns
    None only when no member is live: a cluster with one live member is still
    handed to `merge_cluster`, which reports the members it skips (a member
    already superseded by another claim is counted, not hidden).
    """
    cur.execute(
        """
        SELECT c.id::text,
               COALESCE('deduped' = ANY(c.labels), false) AS is_deduped,
               (SELECT count(*) FROM reasoning_traces WHERE claim_id = c.id) AS trace_count,
               (SELECT count(*) FROM mass_functions  WHERE claim_id = c.id) AS mf_count,
               (SELECT count(*) FROM edges WHERE source_id = c.id OR target_id = c.id) AS edge_count,
               COALESCE(c.is_current, true) AS is_current
        FROM claims c
        WHERE c.id = ANY(%s::uuid[])
        """,
        (member_ids,),
    )
    rows = [
        {
            "id": r[0],
            "is_deduped": r[1],
            "trace_count": r[2],
            "mf_count": r[3],
            "edge_count": r[4],
            "is_current": r[5],
        }
        for r in cur.fetchall()
    ]
    # The `deduped` label a pre-2026-10 mark left counts only while the claim
    # is retired (so `is_current` alone decides): an un-marked legacy claim
    # (operator ruling R-7) is current again, label and all, and live.
    live = [r for r in rows if r["is_current"]]
    if not live:
        return None  # no member can be the canonical
    suggested = next((r for r in live if r["id"] == suggested_rep), None)
    if suggested is not None:
        return suggested["id"]
    live.sort(key=lambda r: (-r["trace_count"], -r["mf_count"], -r["edge_count"]))
    return live[0]["id"]


def post_dedup(
    api_base: str, token: str, dup_id: str, canonical_id: str, timeout: float = 60.0
) -> tuple[int, str]:
    """POST /api/v1/claims/{dup}/dedup. Returns (HTTP status, response body).

    A request that gets no HTTP answer (connection refused or reset, timeout)
    returns status 0 and the error text, so the caller counts it as a refusal
    for that duplicate and keeps the marks already made in the cluster.
    """
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/api/v1/claims/{dup_id}/dedup",
        data=json.dumps(
            {"canonical_id": canonical_id, "reason": "fuzzy_dedup_claims semantic cluster"}
        ).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except (urllib.error.URLError, OSError) as e:
        # URLError covers refused/unresolvable; OSError covers a reset or a
        # timeout mid-response (http.client raises those unwrapped).
        return 0, f"no HTTP response: {e}"


def merge_cluster(
    cur,
    canonical_id: str,
    member_ids: list[str],
    api_base: str | None = None,
    token: str | None = None,
) -> ClusterStats:
    """Mark every live non-canonical member a duplicate of `canonical_id`.

    Reads only. With `token` (execute mode) each duplicate is one POST to the
    dedup endpoint; without, it is counted as one the run would mark. A member
    already marked onto this canonical (a re-run) is passed over silently; one
    superseded by another claim, or otherwise not current, is skipped and
    counted in `duplicates_skipped_already_superseded`.
    """
    stats = ClusterStats(canonical_id=canonical_id)
    duplicates = [m for m in member_ids if m != canonical_id]

    for dup_id in duplicates:
        cur.execute(
            "SELECT 'deduped' = ANY(labels), supersedes::text, "
            "COALESCE(is_current, true) FROM claims WHERE id = %s::uuid",
            (dup_id,),
        )
        row = cur.fetchone()
        if row is None:
            continue  # claim was hard-deleted between the snapshot and now
        is_deduped, supersedes, is_current = row
        if is_deduped and not is_current:
            # Still retired by a pre-2026-10 mark of this script. Once un-marked
            # (current again, the label left on it) it is an ordinary member.
            continue
        if supersedes is not None and str(supersedes) == canonical_id:
            continue  # already marked onto this canonical (an earlier run)
        if supersedes is not None or not is_current:
            # Superseded by some other claim, or retired: the endpoint refuses
            # to overwrite that, so do not ask. Reported, not half-merged.
            stats.duplicates_skipped_already_superseded += 1
            continue
        stats.duplicate_count += 1
        if token is None:
            continue
        status, body = post_dedup(api_base, token, dup_id, canonical_id)
        if status == 200:
            stats.duplicates_marked += 1
        else:
            stats.duplicates_refused += 1
            what = f"HTTP {status}" if status else "no response"
            stats.refusals.append(f"{dup_id} -> {canonical_id}: {what} {body[:300]}")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT_PATH,
        help=f"Path to semantic-dedup.json snapshot (default: {DEFAULT_INPUT_PATH})",
    )
    parser.add_argument(
        "--database-url",
        default=maintenance_dsn(DEFAULT_DATABASE_URL),
        help="Postgres connection string for the READ-ONLY reads (env DATABASE_URL overrides default)",
    )
    parser.add_argument(
        "--api-base",
        default=os.environ.get("EPIGRAPH_API_BASE", DEFAULT_API_BASE),
        help=f"EpiGraph API base URL (env EPIGRAPH_API_BASE; default {DEFAULT_API_BASE})",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("EPIGRAPH_TOKEN"),
        help="Bearer token for the dedup endpoint (env EPIGRAPH_TOKEN); required with --execute",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Mark through the API. Without this flag nothing is sent.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after this many clusters (useful for staged rollouts).",
    )
    parser.add_argument(
        "--min-members",
        type=int,
        default=2,
        help="Skip clusters smaller than this (default: 2 = any duplicate group).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print one line per cluster.",
    )
    args = parser.parse_args()
    if args.execute and not args.token:
        parser.error("--execute needs a bearer token (--token or EPIGRAPH_TOKEN)")
    token = args.token if args.execute else None

    psycopg2.extras.register_uuid()
    groups = load_groups(args.input)
    print(
        f"loaded {len(groups)} groups from {args.input} "
        f"({'EXECUTE' if args.execute else 'DRY-RUN'})"
    )

    conn = psycopg2.connect(args.database_url)
    # Reads only: every write goes through the API.
    conn.set_session(readonly=True, autocommit=True)
    totals = TotalStats()

    processed = 0
    for group in groups:
        members = group.get("members") or []
        if len(members) < args.min_members:
            continue
        rep = group.get("rep") or members[0]
        # Validate UUIDs early; bad input shouldn't poison the run.
        try:
            [uuid.UUID(m) for m in members]
            uuid.UUID(rep)
        except ValueError as e:
            totals.failures.append(f"bad uuid in group rep={rep}: {e}")
            continue

        cur = conn.cursor()
        try:
            canonical = pick_canonical(cur, members, rep)
            if canonical is None:
                totals.clusters_skipped_already_deduped += 1
                continue
            stats = merge_cluster(cur, canonical, members, args.api_base, token)
            # Accumulate the refusal counter BEFORE the early-continue below.
            # A cluster whose only duplicate was skipped for having a prior
            # `supersedes` has duplicate_count == 0, and reporting it purely
            # as "already deduped" would hide it.
            totals.duplicates_skipped_already_superseded += (
                stats.duplicates_skipped_already_superseded
            )
            if stats.duplicate_count == 0:
                totals.clusters_skipped_already_deduped += 1
                continue
            totals.clusters_processed += 1
            totals.duplicates += stats.duplicate_count
            totals.duplicates_marked += stats.duplicates_marked
            totals.duplicates_refused += stats.duplicates_refused
            totals.failures.extend(stats.refusals)
            if args.verbose:
                print(
                    f"  [{stats.duplicate_count:>3} dups -> {canonical[:8]}] "
                    f"marked={stats.duplicates_marked} refused={stats.duplicates_refused}"
                )
        except Exception as e:
            totals.clusters_failed += 1
            totals.failures.append(f"cluster rep={rep}: {e}")
            if args.verbose:
                print(f"  [FAIL rep={rep[:8]}] {e}")
        finally:
            cur.close()

        processed += 1
        if args.limit is not None and processed >= args.limit:
            break

    conn.close()

    print()
    print(f"clusters_processed:              {totals.clusters_processed}")
    print(f"clusters_skipped_already_deduped: {totals.clusters_skipped_already_deduped}")
    print(f"clusters_failed:                 {totals.clusters_failed}")
    if args.execute:
        print(f"duplicates_marked:               {totals.duplicates_marked}")
        print(f"duplicates_refused:              {totals.duplicates_refused}")
    else:
        print(f"duplicates_would_mark:           {totals.duplicates}")
    print(
        "duplicates_skipped_already_superseded: "
        f"{totals.duplicates_skipped_already_superseded}"
    )
    if totals.failures:
        print(f"\n{len(totals.failures)} failures (first 10):")
        for f in totals.failures[:10]:
            print(f"  {f}")
    if not args.execute:
        print("\nDRY-RUN — pass --execute (with a token) to mark through the API.")
    return 1 if (totals.clusters_failed or totals.duplicates_refused) else 0


if __name__ == "__main__":
    sys.exit(main())
