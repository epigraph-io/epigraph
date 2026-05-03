#!/usr/bin/env python3
"""Fuzzy / semantic dedup pass over the claims table.

Consumes a precomputed semantic-dedup.json snapshot (cosine ≥ threshold over
claim embeddings) produced by the GUI's offline analysis. For each group, picks
a canonical claim, redirects its high-signal references (mass_functions, edges,
evidence, reasoning_traces), preserves AUTHORED-edge provenance from each
duplicate's agent, and soft-marks the duplicates so the GUI's collapse
behaviour and any downstream label-aware reader stay coherent.

This is the *S3 fuzzy* layer (cross-agent semantic equivalence). The S2
content-hash-keyed dedup that gates migration 107 is a separate tool.

Default mode is dry-run; pass --execute to commit. Each cluster runs in its
own transaction so a single hostile cluster does not abort the whole pass.

Usage:
    python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json
    python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute
    python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute --limit 100

Limitations (scope-deferred — see docs/architecture/noun-claims-and-verb-edges.md):
- Does not redirect FKs in: assessment_queue, assessment_results,
  behavioral_executions.step_claim_id, challenges, claim_clusters,
  claim_encryption, claim_frames, claim_neighborhood_membership,
  claim_signature_revocations, counterfactual_scenarios, countersignatures,
  ds_bayesian_divergence, embedding_shares, entity_mentions, evidence_diversity,
  experiments.hypothesis_id, learning_events, praxis_access_log.justification_claim_id,
  praxis_claims, praxis_compliance_requirements, sample_claims, triples,
  claims.supersedes. Soft-mark + label-aware reads cover these for now.
- Mass-function merge is lossy. Pre-2026-04-08 BBAs all carry
  perspective_id=NULL, so any same-agent BBA on the duplicate collides
  with the canonical's BBA on the unique
  (claim, frame, agent, perspective) and is dropped, not combined.
  The canonical's pre-existing BBA is the survivor; the duplicate's
  parallel record is gone. Acceptable when the duplicates are true
  semantic equivalents (same agent's belief, recorded twice). Run a
  CDST recombine pass after dedup if you want re-aggregated belief.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from dataclasses import dataclass, field

import psycopg2
import psycopg2.extras

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)
DEFAULT_INPUT_PATH = "/home/jeremy/epigraph-gui/public/semantic-dedup.json"


@dataclass
class ClusterStats:
    canonical_id: str
    duplicate_count: int = 0
    mfs_moved: int = 0
    mfs_skipped_collision: int = 0
    edges_redirected: int = 0
    edges_dropped_collision: int = 0
    evidence_redirected: int = 0
    traces_redirected: int = 0
    authored_edges_added: int = 0


@dataclass
class TotalStats:
    clusters_processed: int = 0
    clusters_skipped_already_deduped: int = 0
    clusters_failed: int = 0
    duplicates: int = 0
    mfs_moved: int = 0
    mfs_skipped_collision: int = 0
    edges_redirected: int = 0
    edges_dropped_collision: int = 0
    evidence_redirected: int = 0
    traces_redirected: int = 0
    authored_edges_added: int = 0
    failures: list[str] = field(default_factory=list)


def load_groups(path: str) -> list[dict]:
    with open(path) as fh:
        snapshot = json.load(fh)
    if "groups" not in snapshot:
        sys.exit(f"input {path} missing 'groups' field")
    return snapshot["groups"]


def pick_canonical(cur, member_ids: list[str], suggested_rep: str) -> str | None:
    """Pick the canonical claim id for a cluster.

    Prefers the rep id from the input snapshot when it still exists and is
    not already soft-deduped. Otherwise picks by (trace_count, mf_count,
    edge_count) descending. Returns None if every member is missing or
    already soft-deduped (idempotent re-run).
    """
    cur.execute(
        """
        SELECT c.id::text,
               COALESCE('deduped' = ANY(c.labels), false) AS is_deduped,
               (SELECT count(*) FROM reasoning_traces WHERE claim_id = c.id) AS trace_count,
               (SELECT count(*) FROM mass_functions  WHERE claim_id = c.id) AS mf_count,
               (SELECT count(*) FROM edges WHERE source_id = c.id OR target_id = c.id) AS edge_count
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
        }
        for r in cur.fetchall()
    ]
    live = [r for r in rows if not r["is_deduped"]]
    if len(live) <= 1:
        return None  # nothing to merge
    suggested = next((r for r in live if r["id"] == suggested_rep), None)
    if suggested is not None:
        return suggested["id"]
    live.sort(key=lambda r: (-r["trace_count"], -r["mf_count"], -r["edge_count"]))
    return live[0]["id"]


def merge_cluster(
    cur,
    canonical_id: str,
    member_ids: list[str],
) -> ClusterStats:
    stats = ClusterStats(canonical_id=canonical_id)
    duplicates = [m for m in member_ids if m != canonical_id]

    for dup_id in duplicates:
        # Skip if already soft-deduped — keeps the script idempotent.
        cur.execute(
            "SELECT 'deduped' = ANY(labels) FROM claims WHERE id = %s::uuid",
            (dup_id,),
        )
        row = cur.fetchone()
        if row is None:
            continue  # claim was hard-deleted between the snapshot and now
        if row[0]:
            continue  # already deduped
        stats.duplicate_count += 1

        # 1. Mass functions — UNIQUE (claim, frame, agent, perspective). Migrate
        #    rows that don't collide; drop collisions (canonical already has a BBA
        #    for that perspective and re-aggregation happens on next CDST pass).
        cur.execute(
            """
            UPDATE mass_functions
               SET claim_id = %s::uuid
             WHERE claim_id = %s::uuid
               AND NOT EXISTS (
                   SELECT 1 FROM mass_functions m2
                    WHERE m2.claim_id = %s::uuid
                      AND m2.frame_id = mass_functions.frame_id
                      AND m2.source_agent_id IS NOT DISTINCT FROM mass_functions.source_agent_id
                      AND m2.perspective_id  IS NOT DISTINCT FROM mass_functions.perspective_id
               )
            """,
            (canonical_id, dup_id, canonical_id),
        )
        stats.mfs_moved += cur.rowcount
        cur.execute(
            "DELETE FROM mass_functions WHERE claim_id = %s::uuid",
            (dup_id,),
        )
        stats.mfs_skipped_collision += cur.rowcount

        # 2. Edges where dup is the source — avoid (source, target, rel) UNIQUE
        #    collision and self-edges to the canonical.
        cur.execute(
            """
            UPDATE edges SET source_id = %s::uuid
             WHERE source_id = %s::uuid
               AND target_id != %s::uuid
               AND NOT EXISTS (
                   SELECT 1 FROM edges e2
                    WHERE e2.source_id = %s::uuid
                      AND e2.target_id = edges.target_id
                      AND e2.relationship = edges.relationship
               )
            """,
            (canonical_id, dup_id, canonical_id, canonical_id),
        )
        stats.edges_redirected += cur.rowcount

        # 3. Edges where dup is the target — same shape, mirrored.
        cur.execute(
            """
            UPDATE edges SET target_id = %s::uuid
             WHERE target_id = %s::uuid
               AND source_id != %s::uuid
               AND NOT EXISTS (
                   SELECT 1 FROM edges e2
                    WHERE e2.source_id = edges.source_id
                      AND e2.target_id = %s::uuid
                      AND e2.relationship = edges.relationship
               )
            """,
            (canonical_id, dup_id, canonical_id, canonical_id),
        )
        stats.edges_redirected += cur.rowcount

        # 4. Drop edges that couldn't redirect (would-be self-edge or triple
        #    collision). Without this they cascade-orphan when the dup's
        #    label-only soft-mark is later promoted to a hard delete.
        cur.execute(
            "DELETE FROM edges WHERE source_id = %s::uuid OR target_id = %s::uuid",
            (dup_id, dup_id),
        )
        stats.edges_dropped_collision += cur.rowcount

        # 5. Evidence and reasoning traces — straight repoint, no UNIQUE
        #    constraints to dodge.
        cur.execute(
            "UPDATE evidence SET claim_id = %s::uuid WHERE claim_id = %s::uuid",
            (canonical_id, dup_id),
        )
        stats.evidence_redirected += cur.rowcount
        cur.execute(
            "UPDATE reasoning_traces SET claim_id = %s::uuid WHERE claim_id = %s::uuid",
            (canonical_id, dup_id),
        )
        stats.traces_redirected += cur.rowcount

        # 6. Preserve cross-agent provenance: each dup's authoring agent gets
        #    an AUTHORED edge to the canonical (idempotent on the triple-UNIQUE).
        cur.execute(
            """
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
            SELECT c.agent_id, 'agent', %s::uuid, 'claim', 'AUTHORED',
                   jsonb_build_object('via', 'fuzzy_dedup_claims', 'merged_from', c.id::text)
              FROM claims c
             WHERE c.id = %s::uuid
            ON CONFLICT (source_id, target_id, relationship) DO NOTHING
            """,
            (canonical_id, dup_id),
        )
        stats.authored_edges_added += cur.rowcount

        # 7. Soft-mark the dup. Keeping the row preserves any FK reference
        #    we did not redirect; the label + deduped_into pointer lets readers
        #    follow to the canonical.
        cur.execute(
            """
            UPDATE claims
               SET labels = array_append(COALESCE(labels, ARRAY[]::text[]), 'deduped'),
                   properties = COALESCE(properties, '{}'::jsonb)
                              || jsonb_build_object(
                                  'deduped_into', %s,
                                  'deduped_by', 'fuzzy_dedup_claims',
                                  'deduped_at', now()::text
                              )
             WHERE id = %s::uuid
            """,
            (canonical_id, dup_id),
        )

    # 8. Sweep self-edges that may have arrived during redirect.
    cur.execute(
        "DELETE FROM edges WHERE source_id = %s::uuid AND target_id = %s::uuid",
        (canonical_id, canonical_id),
    )
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
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
        help="Postgres connection string (env DATABASE_URL overrides default)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Commit changes. Without this flag, every cluster's transaction is rolled back.",
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

    psycopg2.extras.register_uuid()
    groups = load_groups(args.input)
    print(
        f"loaded {len(groups)} groups from {args.input} "
        f"({'EXECUTE' if args.execute else 'DRY-RUN'})"
    )

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False
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
                conn.rollback()
                continue
            stats = merge_cluster(cur, canonical, members)
            if stats.duplicate_count == 0:
                totals.clusters_skipped_already_deduped += 1
                conn.rollback()
                continue
            if args.execute:
                conn.commit()
            else:
                conn.rollback()
            totals.clusters_processed += 1
            totals.duplicates += stats.duplicate_count
            totals.mfs_moved += stats.mfs_moved
            totals.mfs_skipped_collision += stats.mfs_skipped_collision
            totals.edges_redirected += stats.edges_redirected
            totals.edges_dropped_collision += stats.edges_dropped_collision
            totals.evidence_redirected += stats.evidence_redirected
            totals.traces_redirected += stats.traces_redirected
            totals.authored_edges_added += stats.authored_edges_added
            if args.verbose:
                print(
                    f"  [{stats.duplicate_count:>3} dups -> {canonical[:8]}] "
                    f"mfs={stats.mfs_moved}+{stats.mfs_skipped_collision}coll "
                    f"edges={stats.edges_redirected}redir+{stats.edges_dropped_collision}drop "
                    f"ev={stats.evidence_redirected} trace={stats.traces_redirected} "
                    f"authored={stats.authored_edges_added}"
                )
        except Exception as e:
            conn.rollback()
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
    print(f"duplicates_merged:               {totals.duplicates}")
    print(f"mass_functions_moved:            {totals.mfs_moved}")
    print(f"mass_functions_dropped_collision: {totals.mfs_skipped_collision}")
    print(f"edges_redirected:                {totals.edges_redirected}")
    print(f"edges_dropped_collision:         {totals.edges_dropped_collision}")
    print(f"evidence_redirected:             {totals.evidence_redirected}")
    print(f"reasoning_traces_redirected:     {totals.traces_redirected}")
    print(f"authored_edges_added:            {totals.authored_edges_added}")
    if totals.failures:
        print(f"\n{len(totals.failures)} failures (first 10):")
        for f in totals.failures[:10]:
            print(f"  {f}")
    if not args.execute:
        print("\nDRY-RUN — pass --execute to commit.")
    return 1 if totals.clusters_failed else 0


if __name__ == "__main__":
    sys.exit(main())
