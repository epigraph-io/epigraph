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

    m({asserted}) = truth_value        what the source asserts, in THIS frame
    m(Theta)      = 1 - truth_value    "high but not 1.0" IS the ignorance mass

The unit of work is a (claim, frame) PAIR, not a claim. The same provenance
confidence is a statement about the claim in each context it applies to, so a claim
assigned to three frames gets three BBAs — one per context, each carrying that
context's own hypothesis index and its own Theta.

SAFETY POSTURE
--------------
* Dry-run by default. `--execute` is required to write anything.
* `--frame-ids` and `--perspective-id` are REQUIRED and have no defaults. A claim
  legitimately holds different beliefs in different contexts — `claim_frames` is
  keyed PRIMARY KEY (claim_id, frame_id) — so the operator names the contexts
  explicitly rather than the script guessing one.
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
        --frame-ids <uuid> [<uuid> ...] --perspective-id <uuid> --source-agent-id <uuid>

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from maintenance_dsn import maintenance_dsn  # noqa: E402

MARKER = "provenance_migration_v1"

# Claims that are operational exhaust rather than semantic content. Mirrors the
# telemetry carve-out documented in CLAUDE.md's embedding policy.
TELEMETRY_PREDICATE = """
    NOT ('telemetry' = ANY(c.labels))
    AND (c.properties->>'event') IS NULL
"""


def eligible_sql(extra: str = "") -> str:
    """(claim, frame) PAIRS eligible for a synthesized provenance BBA.

    The unit is a PAIR, not a claim: `claim_frames` is keyed
    `PRIMARY KEY (claim_id, frame_id)` because a claim legitimately holds different
    beliefs in different contexts, and a provenance prior is a statement about the
    claim in each of them.

    `hypothesis_index` comes from the claim's OWN assignment where one exists —
    that is the index the framed `get_belief` path reads via
    `FrameRepository::get_claim_assignment`, so writing mass against any other index
    would produce a BBA the engine interprets as being about a different hypothesis.
    Where no assignment exists it falls back to --default-hypothesis-index.

    Deliberately narrow:
      * is_current only — superseded claims must not gain new evidence.
      * truth_value NOT NULL — there is no provenance number to migrate otherwise.
      * no existing BBA for THAT (claim, frame) — real evidence outranks a prior,
        per context. A claim assessed in one frame still gets provenance in another.
    """
    return f"""
        SELECT c.id AS claim_id,
               f.id AS frame_id,
               f.name AS frame_name,
               array_length(f.hypotheses, 1) AS n_hypotheses,
               c.truth_value,
               COALESCE(cf.hypothesis_index, %(default_idx)s) AS hypothesis_index,
               (cf.claim_id IS NULL) AS needs_assignment
        FROM claims c
        CROSS JOIN frames f
        LEFT JOIN claim_frames cf ON cf.claim_id = c.id AND cf.frame_id = f.id
        WHERE c.is_current
          AND c.truth_value IS NOT NULL
          AND f.id = ANY(%(frame_ids)s::uuid[])
          AND {TELEMETRY_PREDICATE}
          AND NOT EXISTS (
              SELECT 1 FROM mass_functions mf
              WHERE mf.claim_id = c.id AND mf.frame_id = f.id
          )
        ORDER BY c.id, f.id
        {extra}
    """


def census(cur, frame_ids: list, default_idx: int) -> None:
    """Phase 0. Read-only population sizing, per frame, printed before any write."""
    params = {"frame_ids": frame_ids, "default_idx": default_idx}
    cur.execute(
        f"""
        WITH eligible AS ({eligible_sql()})
        SELECT frame_name,
               COUNT(*)                                     AS pairs,
               COUNT(*) FILTER (WHERE needs_assignment)      AS would_assign,
               COUNT(*) FILTER (WHERE truth_value = 0.85)    AS at_cap_085,
               COUNT(*) FILTER (WHERE truth_value = 0.5)     AS raw_050,
               COUNT(*) FILTER (WHERE truth_value > 0.85)    AS above_cap,
               COUNT(DISTINCT hypothesis_index)              AS distinct_idx,
               MIN(hypothesis_index)                         AS min_idx,
               MAX(hypothesis_index)                         AS max_idx,
               MAX(n_hypotheses)                             AS n_hyp
        FROM eligible
        GROUP BY frame_name
        ORDER BY frame_name
        """,
        params,
    )
    rows = cur.fetchall()

    print("=== Phase 0 census (nothing written) ===")
    if not rows:
        print("  no eligible (claim, frame) pairs")
        return
    total = 0
    for r in rows:
        total += r["pairs"]
        print(f"  frame {r['frame_name']} ({r['n_hyp']} hypotheses)")
        print(f"    eligible pairs            : {r['pairs']}")
        print(f"    would create a claim_frames row: {r['would_assign']}")
        print(f"    at the 0.85 provenance cap: {r['at_cap_085']}")
        print(f"    at raw 0.5 (unscored)     : {r['raw_050']}")
        print(f"    truth_value > 0.85        : {r['above_cap']}   <- NOT from calculate_initial_truth")
        print(f"    hypothesis_index          : {r['min_idx']}..{r['max_idx']} "
              f"({r['distinct_idx']} distinct)")
        if r["max_idx"] is not None and r["n_hyp"] is not None and r["max_idx"] >= r["n_hyp"]:
            sys.exit(
                f"FATAL: frame '{r['frame_name']}' has {r['n_hyp']} hypotheses but an eligible\n"
                f"pair carries hypothesis_index {r['max_idx']}. Writing mass against an index the\n"
                "frame does not define would produce a BBA no reader can interpret."
            )
    print(f"  TOTAL eligible pairs        : {total}")

    cur.execute(
        """
        SELECT f.name, COUNT(mf.*) AS existing
        FROM frames f LEFT JOIN mass_functions mf ON mf.frame_id = f.id
        WHERE f.id = ANY(%(frame_ids)s::uuid[])
        GROUP BY f.name ORDER BY f.name
        """,
        {"frame_ids": frame_ids},
    )
    for r in cur.fetchall():
        print(f"  {r['name']}: {r['existing']} existing BBAs (those pairs are skipped)")
    print()


def validate_targets(cur, frame_ids: list, perspective_id: str, agent_id: str,
                     evidence_type: str, default_idx: int) -> dict:
    """Fail loudly and early rather than writing into a misconfigured target."""
    cur.execute(
        "SELECT id, name, hypotheses FROM frames WHERE id = ANY(%s::uuid[]) ORDER BY name",
        (frame_ids,),
    )
    frames = cur.fetchall()
    found = {str(f["id"]) for f in frames}
    missing = [fid for fid in frame_ids if fid not in found]
    if missing:
        sys.exit(
            f"FATAL: frame(s) do not exist: {missing}. This script does not create frames."
        )
    for f in frames:
        # NOT a binary-only check. A provenance prior is expressible in any frame:
        # m({asserted}) = tv and m(Theta) = 1 - tv, where Theta is the full
        # hypothesis set. What must hold is that the asserted index EXISTS.
        if default_idx >= len(f["hypotheses"]):
            sys.exit(
                f"FATAL: --default-hypothesis-index {default_idx} is out of range for frame\n"
                f"'{f['name']}', which defines {len(f['hypotheses'])} hypotheses "
                f"{f['hypotheses']}."
            )

    cur.execute(
        """
        SELECT id, name,
               properties->'source_reliability' AS source_reliability
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

    return {"frames": frames, "perspective": persp}


def theta_key(n_hypotheses: int) -> str:
    """Theta (the full hypothesis set) as a mass key: "0,1" binary, "0,1,2" ternary."""
    return ",".join(str(i) for i in range(n_hypotheses))


def migrate(cur, args, manifest) -> int:
    extra = ""
    params = {"frame_ids": args.frame_ids, "default_idx": args.default_hypothesis_index}
    if args.limit is not None:
        extra += " LIMIT %(limit)s"
        params["limit"] = args.limit
    if args.offset:
        extra += " OFFSET %(offset)s"
        params["offset"] = args.offset

    cur.execute(eligible_sql(extra), params)
    rows = cur.fetchall()
    print(f"selected {len(rows)} (claim, frame) pairs "
          f"(limit={args.limit} offset={args.offset})")

    written = 0
    for r in rows:
        tv = float(r["truth_value"])
        idx = int(r["hypothesis_index"])
        n_hyp = int(r["n_hypotheses"])
        if idx >= n_hyp:
            sys.exit(
                f"FATAL: claim {r['claim_id']} is assigned hypothesis_index {idx} in frame\n"
                f"'{r['frame_name']}', which defines only {n_hyp} hypotheses. Refusing to write\n"
                "mass against an index the frame does not define."
            )
        # m({asserted}) = tv, m(Theta) = 1 - tv. Generalizes to any arity: Theta is the
        # full hypothesis set, so the residual stays ignorance rather than being
        # spread across the other hypotheses as if the source had an opinion on them.
        masses = {str(idx): round(tv, 12), theta_key(n_hyp): round(1.0 - tv, 12)}

        if not args.execute:
            written += 1
            continue

        # Record the claim's position in this context if it has none. The framed
        # read resolves hypothesis_index via get_claim_assignment, so a BBA without
        # an assignment would be interpreted against index 0 regardless of intent.
        cur.execute(
            """
            INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
            VALUES (%(claim)s, %(frame)s, %(idx)s)
            ON CONFLICT (claim_id, frame_id) DO NOTHING
            """,
            {"claim": r["claim_id"], "frame": r["frame_id"], "idx": idx},
        )
        created_assignment = cur.rowcount == 1

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
                "claim": r["claim_id"],
                "frame": r["frame_id"],
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
                    "claim_id": str(r["claim_id"]),
                    "frame_id": str(r["frame_id"]),
                    "frame_name": r["frame_name"],
                    "hypothesis_index": idx,
                    "created_assignment": created_assignment,
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
    """Delete exactly what this migration inserted, by manifest id."""
    entries = []
    with open(manifest_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    ids = [e["mass_function_id"] for e in entries]
    # Only assignments THIS migration created. A pre-existing claim_frames row is
    # not ours to remove — another writer's belief may depend on it.
    assignments = [
        (e["claim_id"], e["frame_id"])
        for e in entries
        if e.get("created_assignment")
    ]
    print(f"manifest lists {len(ids)} inserted BBAs and "
          f"{len(assignments)} claim_frames rows this migration created")

    if not args.execute:
        cur.execute(
            "SELECT COUNT(*) AS n FROM mass_functions "
            "WHERE id = ANY(%s::uuid[]) AND combination_method = %s",
            (ids, MARKER),
        )
        print(f"would delete {cur.fetchone()['n']} BBAs "
              f"and {len(assignments)} assignments (dry-run)")
        return 0

    # The marker predicate is belt-and-braces: even a corrupted manifest cannot
    # delete a row this migration did not write.
    cur.execute(
        "DELETE FROM mass_functions "
        "WHERE id = ANY(%s::uuid[]) AND combination_method = %s",
        (ids, MARKER),
    )
    deleted = cur.rowcount
    print(f"deleted {deleted} BBAs")
    if deleted != len(ids):
        print(
            f"  NOTE: {len(ids) - deleted} manifest rows were already absent — expected if a\n"
            "  previous rollback ran, or if the insert was rolled back before commit."
        )

    dropped = 0
    for claim_id, frame_id in assignments:
        # Re-check emptiness: another writer may have added a BBA in this context
        # since the migration ran, in which case the assignment is now load-bearing.
        cur.execute(
            "DELETE FROM claim_frames cf WHERE cf.claim_id = %s AND cf.frame_id = %s "
            "AND NOT EXISTS (SELECT 1 FROM mass_functions mf "
            "                WHERE mf.claim_id = cf.claim_id AND mf.frame_id = cf.frame_id)",
            (claim_id, frame_id),
        )
        dropped += cur.rowcount
    print(f"dropped {dropped}/{len(assignments)} claim_frames rows "
          f"(kept any that another writer's BBA now depends on)")

    print(
        "\n  Cached claims.{belief,plausibility,pignistic_prob,...} are NOT restored by\n"
        "  this rollback. If Phase 3 (recompute_beliefs) has run, the scalars reflect the\n"
        "  migrated BBAs and a recompute is one-way. That is why Phase 3 is sequenced last."
    )
    return deleted


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    # Corpus-wide script: it must connect on the MAINTENANCE DSN, not an ordinary
    # application connection. Once RLS is active an application role makes every
    # statement match a subset — the SELECTs see less, the INSERTs touch nothing,
    # and the script exits 0. A silently partial provenance migration is worse than
    # a refused one. `maintenance_dsn` also refuses when MAINTENANCE_DATABASE_URL
    # and DATABASE_URL name different databases.
    p.add_argument("--database-url", default=None)
    p.add_argument(
        "--frame-ids",
        nargs="+",
        metavar="UUID",
        help="REQUIRED for migrate. One or more contexts. No default: a claim holds "
        "different beliefs in different frames, so the operator names them.",
    )
    p.add_argument(
        "--default-hypothesis-index",
        type=int,
        default=0,
        help="Index asserted when the claim has no claim_frames row for that frame. "
        "Where an assignment EXISTS its recorded index wins, because that is what "
        "the framed read resolves.",
    )
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
        args.database_url = maintenance_dsn()
    if not args.database_url:
        sys.exit(
            "FATAL: set MAINTENANCE_DATABASE_URL (preferred) or DATABASE_URL, "
            "or pass --database-url"
        )
    if args.execute and not args.manifest:
        sys.exit("FATAL: --execute requires --manifest. An unjournalled write is not reversible.")
    if not args.rollback and not (args.frame_ids and args.perspective_id and args.source_agent_id):
        sys.exit(
            "FATAL: --frame-ids, --perspective-id and --source-agent-id are all required.\n"
            "None has a default on purpose: a claim legitimately holds different beliefs in\n"
            "different contexts (claim_frames is PK (claim_id, frame_id)), so which contexts\n"
            "receive a provenance prior is an operator decision, not a script default."
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
                cur, args.frame_ids, args.perspective_id, args.source_agent_id,
                args.evidence_type, args.default_hypothesis_index,
            )
            for f in meta["frames"]:
                print(f"frame      : {f['name']} {f['hypotheses']}")
            print(f"perspective: {meta['perspective']['name']} "
                  f"(alpha[{args.evidence_type}]="
                  f"{meta['perspective']['source_reliability'][args.evidence_type]})")
            print()
            census(cur, args.frame_ids, args.default_hypothesis_index)
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
