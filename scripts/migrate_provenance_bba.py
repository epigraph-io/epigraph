#!/usr/bin/env python3
"""Materialize each claim's provenance confidence as a Dempster-Shafer BBA.

Plan: docs/superpowers/plans/2026-09-16-provenance-bba-migration.md
Spec context: backlogs 14b98adc (recall ranks on a column no DS path refreshes),
0183a294 (BetP bounds), 696d3a1c (one frame owns the cached scalars).

WHY
---
`epigraph_engine::bayesian::calculate_initial_truth` gives ingested claims a
source-class confidence capped at 0.85, and stores it ONLY in `claims.truth_value`.
It has no representation in the DS layer, so most of the corpus reads `no_bbas`.

A bare scalar conflates "85% likely true" with "credible source, incomplete
evidence". As a consonant (simple-support) BBA those separate cleanly:

    m({TRUE}) = truth_value            what the source asserts
    m(Theta)  = 1 - truth_value        "high but not 1.0" IS the ignorance mass

SAFETY POSTURE
--------------
* Dry-run by default. `--execute` is required to write anything.
* `--frame-id` and `--perspective-id` are REQUIRED and have no defaults. Two frames
  in this system both call themselves canonical, and picking wrong means re-running
  a ~476k-row migration. See the plan's G3.
* Refuses a perspective whose `source_reliability` IS NULL. 100+ auto-minted
  perspectives currently carry null, which makes lens re-weighting an identity
  function; migrating into one produces BBAs no lens can discriminate (plan G4).
* Never writes `claims.truth_value`. The migration is purely additive; the corpus
  reads identically until a separate recompute runs.
* Skips any claim that already has a BBA in the target frame. Real evidence
  outranks a synthesized prior.
* Every inserted row is tagged `combination_method = 'provenance_migration_v1'`,
  used by no other writer, so rollback is an exactly-scoped delete.
* Every insert is journalled to a manifest JSONL before the transaction commits,
  and `--rollback` replays that manifest.

WHY DIRECT SQL RATHER THAN submit_ds_evidence
---------------------------------------------
The MCP write path mints a fresh perspective per call. At corpus scale that would
add hundreds of thousands of junk perspective rows and make the G4 problem
permanent. This follows the precedent of scripts/migrate_mixed_bbas.py.

DOES NOT RUN recompute_beliefs
------------------------------
That is Phase 3 of the plan and is gated on backlog 696d3a1c being DEPLOYED. Before
that fix, `recompute_beliefs` writes the shared `claims.*` cache once per frame and
the alphabetically last frame wins — and `binary_truth` sorts first. This migration
gives many claims a SECOND frame, so running a recompute against an unfixed
deployment converts a latent revert into a corpus-wide one.

USAGE
-----
    # Phase 0 — census, writes nothing
    DATABASE_URL=postgres://... python3 scripts/migrate_provenance_bba.py \
        --frame-id <uuid> --perspective-id <uuid> --source-agent-id <uuid>

    # Phase 2 — one batch
    ... --execute --limit 1000 --manifest /path/run1.jsonl

    # Phase 4 — rollback
    ... --rollback --manifest /path/run1.jsonl --execute
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

MARKER = "provenance_migration_v1"

# Claims that are operational exhaust rather than semantic content. Mirrors the
# telemetry carve-out documented in CLAUDE.md's embedding policy.
TELEMETRY_PREDICATE = """
    NOT ('telemetry' = ANY(c.labels))
    AND (c.properties->>'event') IS NULL
"""


def eligible_sql(extra: str = "") -> str:
    """Claims eligible for a synthesized provenance BBA.

    Deliberately narrow:
      * is_current only — superseded claims must not gain new evidence.
      * truth_value NOT NULL — there is no provenance number to migrate otherwise.
      * no existing BBA in the TARGET frame — real evidence outranks a prior.
        Scoped to the target frame, not to all frames, so a claim assessed in some
        unrelated paper frame still gets its provenance recorded here.
    """
    return f"""
        SELECT c.id, c.truth_value, c.labels
        FROM claims c
        WHERE c.is_current
          AND c.truth_value IS NOT NULL
          AND {TELEMETRY_PREDICATE}
          AND NOT EXISTS (
              SELECT 1 FROM mass_functions mf
              WHERE mf.claim_id = c.id AND mf.frame_id = %(frame_id)s
          )
        ORDER BY c.id
        {extra}
    """


def census(cur, frame_id: str) -> None:
    """Phase 0. Read-only population sizing, printed before any write."""
    cur.execute(
        f"""
        WITH eligible AS ({eligible_sql()})
        SELECT
            COUNT(*)                                             AS eligible,
            COUNT(*) FILTER (WHERE truth_value = 0.85)           AS at_cap_085,
            COUNT(*) FILTER (WHERE truth_value = 0.5)            AS raw_050,
            COUNT(*) FILTER (WHERE truth_value > 0.85)           AS above_cap,
            COUNT(*) FILTER (WHERE truth_value < 0.05)           AS near_zero,
            MIN(truth_value)                                     AS min_tv,
            MAX(truth_value)                                     AS max_tv
        FROM eligible
        """,
        {"frame_id": frame_id},
    )
    row = cur.fetchone()

    cur.execute(
        """
        SELECT COUNT(*) AS already_in_frame
        FROM mass_functions WHERE frame_id = %(frame_id)s
        """,
        {"frame_id": frame_id},
    )
    already = cur.fetchone()["already_in_frame"]

    cur.execute(
        f"""
        SELECT COUNT(*) AS no_truth_value FROM claims c
        WHERE c.is_current AND c.truth_value IS NULL AND {TELEMETRY_PREDICATE}
        """
    )
    no_tv = cur.fetchone()["no_truth_value"]

    print("=== Phase 0 census (nothing written) ===")
    print(f"  eligible for migration      : {row['eligible']}")
    print(f"    at the 0.85 provenance cap: {row['at_cap_085']}")
    print(f"    at raw 0.5 (unscored)     : {row['raw_050']}")
    print(f"    truth_value > 0.85        : {row['above_cap']}   <- NOT from calculate_initial_truth")
    print(f"    truth_value < 0.05        : {row['near_zero']}   <- check these are genuinely refuted")
    print(f"    range                     : {row['min_tv']} .. {row['max_tv']}")
    print(f"  already have a BBA in frame : {already}  (skipped — real evidence wins)")
    print(f"  is_current, truth_value NULL: {no_tv}  (no provenance number to migrate)")
    print()
    if row["above_cap"]:
        print(
            f"  NOTE: {row['above_cap']} claims exceed the 0.85 cap, so their value did NOT\n"
            "        come from calculate_initial_truth. Confirm their origin before\n"
            "        treating them as provenance."
        )


def validate_targets(
    cur, frame_id: str, perspective_id: str, agent_id: str, evidence_type: str
) -> dict:
    """Fail loudly and early rather than writing into a misconfigured target."""
    cur.execute("SELECT id, name, hypotheses FROM frames WHERE id = %s", (frame_id,))
    frame = cur.fetchone()
    if frame is None:
        sys.exit(f"FATAL: frame {frame_id} does not exist. This script does not create frames.")
    if len(frame["hypotheses"]) != 2:
        sys.exit(
            f"FATAL: frame '{frame['name']}' has {len(frame['hypotheses'])} hypotheses "
            f"{frame['hypotheses']}. A provenance prior is binary — the source asserts the\n"
            "claim or it does not. Mapping it onto a 3-hypothesis frame requires inventing a\n"
            "position on the third that no source ever took. See plan G3."
        )

    # `source_reliability` is NOT a column. It lives in `properties` as a MAP of
    # evidence-type tag -> alpha, read by PerspectiveRow::source_reliability via
    # `properties->'source_reliability'`. The MCP list_perspectives response
    # surfaces it as a field, which is why it reads as a plain null there.
    cur.execute(
        """
        SELECT id, name,
               properties->'source_reliability' AS source_reliability,
               properties->'locality_reliability' AS locality_reliability
        FROM perspectives WHERE id = %s
        """,
        (perspective_id,),
    )
    persp = cur.fetchone()
    if persp is None:
        sys.exit(
            f"FATAL: perspective {perspective_id} does not exist. This script does not create\n"
            "perspectives — creating one per claim is exactly the defect described in plan G4."
        )
    sr = persp["source_reliability"]
    if not sr or not isinstance(sr, dict):
        sys.exit(
            f"FATAL: perspective '{persp['name']}' has no usable\n"
            f"properties->'source_reliability' map (got: {sr!r}).\n\n"
            "scoped_belief re-weights each BBA by that map's alpha for its evidence_type, so\n"
            "an absent or empty map makes the lens an identity function — these BBAs would be\n"
            "indistinguishable from any other source class, which defeats the entire point of\n"
            "migrating provenance in. Every perspective in production currently fails this\n"
            "check. Resolve a calibrated per-source-class perspective first (plan G4)."
        )
    if evidence_type not in sr:
        sys.exit(
            f"FATAL: perspective '{persp['name']}' has no alpha for evidence_type\n"
            f"'{evidence_type}'. Its map covers: {sorted(sr)}.\n"
            "Writing BBAs the lens cannot weight is worse than writing none."
        )

    cur.execute("SELECT id FROM agents WHERE id = %s", (agent_id,))
    if cur.fetchone() is None:
        sys.exit(f"FATAL: source agent {agent_id} does not exist.")

    return {"frame": frame, "perspective": persp}


def migrate(cur, args, manifest) -> int:
    extra = ""
    params = {"frame_id": args.frame_id}
    if args.limit is not None:
        extra += " LIMIT %(limit)s"
        params["limit"] = args.limit
    if args.offset:
        extra += " OFFSET %(offset)s"
        params["offset"] = args.offset

    cur.execute(eligible_sql(extra), params)
    rows = cur.fetchall()
    print(f"selected {len(rows)} claims (limit={args.limit} offset={args.offset})")

    written = 0
    for r in rows:
        tv = float(r["truth_value"])
        # Consonant simple-support BBA. m(Theta) carries the residual, so a source
        # is never certain: the 0.85 cap becomes an ignorance FLOOR of 0.15.
        masses = {"0": round(tv, 12), "0,1": round(1.0 - tv, 12)}

        if not args.execute:
            written += 1
            continue

        cur.execute(
            """
            INSERT INTO mass_functions
              (id, claim_id, frame_id, source_agent_id, perspective_id, masses,
               conflict_k, combination_method, source_strength, evidence_type,
               locality_tag)
            VALUES (gen_random_uuid(), %(claim)s, %(frame)s, %(agent)s, %(persp)s,
                    %(masses)s::jsonb, 0.0, %(marker)s, %(strength)s,
                    %(etype)s, 'provenance')
            ON CONFLICT DO NOTHING
            RETURNING id
            """,
            {
                "claim": r["id"],
                "frame": args.frame_id,
                "agent": args.source_agent_id,
                "persp": args.perspective_id,
                "masses": json.dumps(masses),
                "marker": MARKER,
                "strength": args.source_strength,
                "etype": args.evidence_type,
            },
        )
        got = cur.fetchone()
        if got is None:
            continue  # idempotent re-run: the unique constraint already holds a row

        # Journal BEFORE commit so a crash leaves the manifest a superset of what
        # landed — recoverable — rather than a subset, which would strand rows.
        manifest.write(
            json.dumps(
                {
                    "mass_function_id": str(got["id"]),
                    "claim_id": str(r["id"]),
                    "frame_id": args.frame_id,
                    "prior_truth_value": tv,
                    "masses": masses,
                    "marker": MARKER,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
            )
            + "\n"
        )
        manifest.flush()
        written += 1

    return written


def rollback(cur, args, manifest_path: str) -> int:
    """Delete exactly the rows this migration inserted, by manifest id."""
    ids = []
    with open(manifest_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                ids.append(json.loads(line)["mass_function_id"])
    print(f"manifest lists {len(ids)} inserted rows")

    if not args.execute:
        cur.execute(
            "SELECT COUNT(*) AS n FROM mass_functions "
            "WHERE id = ANY(%s::uuid[]) AND combination_method = %s",
            (ids, MARKER),
        )
        print(f"would delete {cur.fetchone()['n']} rows (dry-run)")
        return 0

    # The marker predicate is belt-and-braces: even a corrupted manifest cannot
    # delete a row this migration did not write.
    cur.execute(
        "DELETE FROM mass_functions "
        "WHERE id = ANY(%s::uuid[]) AND combination_method = %s",
        (ids, MARKER),
    )
    deleted = cur.rowcount
    print(f"deleted {deleted} rows")
    if deleted != len(ids):
        print(
            f"  NOTE: {len(ids) - deleted} manifest rows were already absent — expected if a\n"
            "  previous rollback ran, or if the insert was rolled back before commit."
        )
    print(
        "\n  Cached claims.{belief,plausibility,pignistic_prob,...} are NOT restored by\n"
        "  this rollback. If Phase 3 (recompute_beliefs) has run, the scalars reflect the\n"
        "  migrated BBAs and a recompute is one-way. That is why Phase 3 is sequenced last."
    )
    return deleted


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    p.add_argument("--frame-id", help="REQUIRED for migrate. Binary frame. No default — see plan G3.")
    p.add_argument("--perspective-id", help="REQUIRED for migrate. Must have non-null source_reliability.")
    p.add_argument("--source-agent-id", help="REQUIRED for migrate. Agent credited as the BBA source.")
    p.add_argument("--source-strength", type=float, default=0.7)
    p.add_argument("--evidence-type", default="textbook_assertion")
    p.add_argument("--limit", type=int)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--manifest", help="JSONL journal of inserts; required with --execute")
    p.add_argument("--rollback", action="store_true", help="Delete rows listed in --manifest")
    p.add_argument("--execute", action="store_true", help="Commit (default: dry-run)")
    args = p.parse_args()

    if not args.database_url:
        sys.exit("FATAL: set DATABASE_URL or pass --database-url")
    if args.execute and not args.manifest:
        sys.exit("FATAL: --execute requires --manifest. An unjournalled write is not reversible.")
    if not args.rollback and not (args.frame_id and args.perspective_id and args.source_agent_id):
        sys.exit(
            "FATAL: --frame-id, --perspective-id and --source-agent-id are all required.\n"
            "None has a default on purpose: two frames in this system both call themselves\n"
            "canonical, and choosing wrong means re-running a ~476k-row migration."
        )

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT current_database() AS db")
    print(f"database: {cur.fetchone()['db']}")
    print(f"mode    : {'EXECUTE' if args.execute else 'DRY-RUN (nothing will be written)'}")
    print()

    try:
        if args.rollback:
            if not args.manifest:
                sys.exit("FATAL: --rollback requires --manifest")
            rollback(cur, args, args.manifest)
        else:
            meta = validate_targets(
                cur, args.frame_id, args.perspective_id,
                args.source_agent_id, args.evidence_type,
            )
            print(f"frame      : {meta['frame']['name']} {meta['frame']['hypotheses']}")
            print(f"perspective: {meta['perspective']['name']} "
                  f"(alpha[{args.evidence_type}]="
                  f"{meta['perspective']['source_reliability'][args.evidence_type]})")
            print()
            census(cur, args.frame_id)
            if args.limit is None and args.execute:
                sys.exit(
                    "FATAL: refusing an unbounded --execute. Run in batches with --limit so the\n"
                    "census can be re-read between them (plan Phase 2)."
                )
            if args.limit is not None:
                manifest = open(args.manifest, "a", encoding="utf-8") if args.execute else None
                try:
                    n = migrate(cur, args, manifest)
                    print(f"\n{'wrote' if args.execute else 'would write'} {n} BBAs")
                finally:
                    if manifest:
                        manifest.close()

        if args.execute:
            conn.commit()
            print("committed")
        else:
            conn.rollback()
            print("\ndry-run complete — transaction rolled back, nothing written")
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
