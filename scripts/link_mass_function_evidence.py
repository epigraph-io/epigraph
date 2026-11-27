#!/usr/bin/env python3
"""Backfill `mass_functions.evidence_id` on historical BBAs, exact links only.

Phase 3 of issue #197 (migration 046 added the column). The forward write
path (`auto_wire_ds_update` in `crates/epigraph-mcp/src/tools/ds_auto.rs`)
sets it on every new evidence-derived BBA; this script handles the ~279 894
historical rows where the FK was missing at write time.

A wrong `evidence_id` is worse than a NULL one: locality and provenance
readers derive from it, and a recompute would fold a guessed link into
beliefs. So each pass links a row only when the link is certain, and leaves
everything else NULL. Nothing is guessed from timestamps or weights.

Pass 1 -- the evidence slot (exact)
===================================
Migration 267 moved every DS auto-wire evidence BBA onto `slot_kind =
'evidence'`, `slot_id` = the id of the evidence row it was written for. For
those rows the link is the slot itself: `evidence_id := slot_id`, when that
evidence row exists AND is on the BBA's own claim. A slot whose evidence row
is gone, or sits on another claim, is reported as `unmatched` and left NULL.

Pass 2 -- the single candidate
==============================
For a BBA that is not an evidence-slot row, look at the evidence rows on its
claim. If there is exactly ONE, link to it. Claims with several evidence rows
are `ambiguous` and claims with none are `no_candidate`; both stay NULL.
Evidence-slot rows are excluded here: their slot already names their
evidence row, so one that pass 1 could not match must not be linked to a
different row merely because its claim has one.

Why not value-match on `source_strength` x `evidence_type_weight`? That has a
composition trap: `edge_factor.rs::wire_evidential_edge_factor` stores
`source_strength = transmission_factor x locality_factor`, so an intra-source
BBA at the empirical tier stores `1.0 x 0.3 = 0.3`, colliding with the raw
conversational weight `0.3`; and a weight cannot tell apart two evidence rows
of the same type on one claim. No weight tie-break is applied.

Both passes skip retracted BBAs: migration 184's rewrite guard (re-created by
228) refuses any change to a retracted row's `evidence_id`, and one such row
in an UPDATE would abort the whole run. They are reported as `retracted`.

The two passes match disjoint rows (pass 1 only evidence-slot rows, pass 2
only the others), so the dry-run counts are exactly what `--execute` links,
barring concurrent writes. The reported buckets partition the unlinked rows.

Undo
====
`--execute` requires `--undo-file PATH` (a new file; an existing one is
refused). Before COMMIT it writes one JSON line per linked row,
`{"mass_function_id", "evidence_id", "pass"}`, and fsyncs it. `--undo PATH`
sets those rows back to NULL, only where `evidence_id` still equals the
recorded value and the row is not retracted; any other row is counted as
skipped. Like the link, the undo is a dry run unless `--execute` is given.

Idempotency: every UPDATE has `WHERE evidence_id IS NULL`, so a re-run links
nothing new (linked rows no longer match; skipped rows still fail their rule).

The last line of every run is `summary: {...}`, the counts as JSON.

Usage:
    # Dry-run (default) -- per-pass counts, no writes:
    python3 scripts/link_mass_function_evidence.py

    # Commit, recording what was linked:
    python3 scripts/link_mass_function_evidence.py --execute --undo-file link-1.jsonl

    # Revert that run (dry-run first, then --execute):
    python3 scripts/link_mass_function_evidence.py --undo link-1.jsonl
    python3 scripts/link_mass_function_evidence.py --undo link-1.jsonl --execute
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import psycopg2

from maintenance_dsn import maintenance_dsn


# Migration guard: both the FK column (046) and the slot columns (267).
REQUIRED_COLUMNS = ("evidence_id", "slot_kind", "slot_id")
COLUMNS_SQL = """
SELECT column_name
  FROM information_schema.columns
 WHERE table_schema = 'public'
   AND table_name = 'mass_functions'
   AND column_name = ANY(%s)
"""

# The rows either pass may touch: unlinked and not retracted.
ELIGIBLE = "mf.evidence_id IS NULL AND mf.retracted_at IS NULL"

# Pass 1: an evidence-slot row whose slot names an evidence row on its own
# claim. `e.claim_id = mf.claim_id` is what makes the link exact.
SLOT_MATCH = (
    "mf.slot_kind = 'evidence' AND EXISTS (SELECT 1 FROM evidence e "
    "WHERE e.id = mf.slot_id AND e.claim_id = mf.claim_id)"
)
LINK_SLOT_SQL = f"""
UPDATE mass_functions mf
   SET evidence_id = mf.slot_id
 WHERE {ELIGIBLE}
   AND {SLOT_MATCH}
RETURNING mf.id::text, mf.evidence_id::text
"""

# Pass 2: every other row, on a claim with exactly one evidence row. Postgres
# lacks `MIN(uuid)`; with HAVING COUNT(*) = 1, `(array_agg(id))[1]` is that
# sole row.
NOT_SLOT = "mf.slot_kind IS DISTINCT FROM 'evidence'"
LINK_SINGLE_SQL = f"""
WITH single_evidence_claims AS (
    SELECT claim_id, (array_agg(id))[1] AS evidence_id
      FROM evidence
     GROUP BY claim_id
    HAVING COUNT(*) = 1
)
UPDATE mass_functions mf
   SET evidence_id = sec.evidence_id
  FROM single_evidence_claims sec
 WHERE mf.claim_id = sec.claim_id
   AND {ELIGIBLE}
   AND {NOT_SLOT}
RETURNING mf.id::text, mf.evidence_id::text
"""

# Every unlinked row in exactly one bucket, built from the same predicates as
# the two UPDATEs so a dry run counts what --execute would link.
BUCKETS_SQL = f"""
WITH ec AS (
    SELECT claim_id, COUNT(*) AS n FROM evidence GROUP BY claim_id
)
SELECT
  COUNT(*) FILTER (WHERE mf.retracted_at IS NOT NULL)                            AS retracted,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {SLOT_MATCH})                            AS slot_linkable,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND mf.slot_kind = 'evidence'
                     AND NOT ({SLOT_MATCH}))                                     AS slot_unmatched,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {NOT_SLOT} AND COALESCE(ec.n, 0) = 1)    AS single_linkable,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {NOT_SLOT} AND COALESCE(ec.n, 0) > 1)    AS ambiguous,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {NOT_SLOT} AND COALESCE(ec.n, 0) = 0)    AS no_candidate,
  COUNT(*)                                                                        AS unlinked
  FROM mass_functions mf
  LEFT JOIN ec ON ec.claim_id = mf.claim_id
 WHERE mf.evidence_id IS NULL
"""

LINKED_TOTAL_SQL = "SELECT COUNT(*) FROM mass_functions WHERE evidence_id IS NOT NULL"

# Undo: only rows still carrying the recorded link, and not retracted since.
UNDO_FROM = """
  FROM unnest(%s::uuid[], %s::uuid[]) AS u(id, evidence_id)
 WHERE mf.id = u.id
   AND mf.evidence_id = u.evidence_id
   AND mf.retracted_at IS NULL
"""
UNDO_COUNT_SQL = (
    "SELECT COUNT(*) FROM mass_functions mf WHERE EXISTS (SELECT 1"
    + UNDO_FROM
    + ")"
)
UNDO_SQL = "UPDATE mass_functions mf SET evidence_id = NULL" + UNDO_FROM + "RETURNING mf.id"

BUCKET_KEYS = ("retracted", "slot_linkable", "slot_unmatched", "single_linkable",
               "ambiguous", "no_candidate")


def missing_columns(conn) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(COLUMNS_SQL, (list(REQUIRED_COLUMNS),))
        present = {r[0] for r in cur.fetchall()}
    return [c for c in REQUIRED_COLUMNS if c not in present]


def buckets(conn) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute(BUCKETS_SQL)
        names = [d[0] for d in cur.description]
        return {n: int(v) for n, v in zip(names, cur.fetchone())}


def linked_total(conn) -> int:
    with conn.cursor() as cur:
        cur.execute(LINKED_TOTAL_SQL)
        return int(cur.fetchone()[0])


def run_pass(conn, sql: str) -> list[tuple[str, str]]:
    """One link UPDATE in the caller's transaction; the (id, evidence_id) it set."""
    with conn.cursor() as cur:
        cur.execute(sql)
        return [(r[0], r[1]) for r in cur.fetchall()]


def write_undo_file(path: str, rows: list[tuple[str, str, str]]) -> None:
    """Create `path` (refusing an existing file) and make it durable."""
    with open(path, "x", encoding="utf-8") as fh:
        for mf_id, ev_id, pass_name in rows:
            fh.write(json.dumps(
                {"mass_function_id": mf_id, "evidence_id": ev_id, "pass": pass_name}
            ) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def read_undo_file(path: str) -> list[tuple[str, str]]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                out.append((str(row["mass_function_id"]), str(row["evidence_id"])))
            except (ValueError, KeyError, TypeError) as exc:
                raise SystemExit(f"ERROR: {path}:{n}: not an undo record ({exc})") from exc
    return out


def summary(**fields) -> None:
    print("summary: " + json.dumps(fields, sort_keys=True))


def print_buckets(b: dict[str, int], slot: int, single: int, verb: str) -> None:
    print("  pass 1 (evidence slot, exact):")
    print(f"    {verb:<12} = {slot:>10}")
    print(f"    unmatched    = {b['slot_unmatched']:>10} (slot's evidence row missing "
          f"or on another claim; left NULL)")
    print("  pass 2 (single candidate, non-slot rows):")
    print(f"    {verb:<12} = {single:>10}")
    print(f"    ambiguous    = {b['ambiguous']:>10} (claim has >= 2 evidence rows; left NULL)")
    print(f"    no_candidate = {b['no_candidate']:>10} (claim has no evidence row; left NULL)")
    print(f"  retracted      = {b['retracted']:>10} (evidence_id frozen; never linked)")
    print(f"  unlinked total = {b['unlinked']:>10}")


def pass_counts(b: dict[str, int], slot: int, single: int) -> dict:
    return {
        "pass1_slot": {"linked": slot, "unmatched": b["slot_unmatched"]},
        "pass2_single": {
            "linked": single,
            "ambiguous": b["ambiguous"],
            "no_candidate": b["no_candidate"],
        },
        "retracted": b["retracted"],
    }


def do_link(conn, execute: bool, undo_file: str | None) -> int:
    before = buckets(conn)
    partition = sum(before[k] for k in BUCKET_KEYS)
    if partition != before["unlinked"]:
        print(f"NOTE: the buckets sum to {partition}, not the unlinked total "
              f"{before['unlinked']}; investigate before executing.", file=sys.stderr)

    if not execute:
        print("DRY-RUN -- no writes.")
        print(f"  linked now     = {linked_total(conn):>10}")
        print_buckets(before, before["slot_linkable"], before["single_linkable"], "would link")
        print()
        print("Pass --execute --undo-file <new file> to commit.")
        conn.rollback()
        summary(mode="dry-run", **pass_counts(
            before, before["slot_linkable"], before["single_linkable"]))
        return 0

    print("Executing both passes in one transaction...")
    try:
        slot_rows = run_pass(conn, LINK_SLOT_SQL)
        single_rows = run_pass(conn, LINK_SINGLE_SQL)
        records = [(i, e, "slot") for i, e in slot_rows]
        records += [(i, e, "single") for i, e in single_rows]
        # Durable before COMMIT: a crash after the commit still leaves the
        # record --undo needs. A crash before it leaves a record of rows that
        # were never linked, which --undo skips (their evidence_id is NULL).
        write_undo_file(undo_file, records)
    except Exception as exc:
        conn.rollback()
        print(f"ERROR: rolled back, nothing linked: {exc}", file=sys.stderr)
        return 1
    conn.commit()

    after = buckets(conn)
    print(f"  undo file: {undo_file} ({len(records)} rows)")
    print_buckets(after, len(slot_rows), len(single_rows), "linked")
    print()
    print("A re-run links nothing new (every UPDATE has `evidence_id IS NULL`). "
          f"Revert with --undo {undo_file}.")
    summary(mode="execute", **pass_counts(after, len(slot_rows), len(single_rows)))
    return 0


def do_undo(conn, path: str, execute: bool) -> int:
    rows = read_undo_file(path)
    ids = [r[0] for r in rows]
    evs = [r[1] for r in rows]
    with conn.cursor() as cur:
        if execute:
            cur.execute(UNDO_SQL, (ids, evs))
            reverted = cur.rowcount
        else:
            cur.execute(UNDO_COUNT_SQL, (ids, evs))
            reverted = int(cur.fetchone()[0])
    if execute:
        conn.commit()
    else:
        conn.rollback()
    skipped = len(rows) - reverted
    print("UNDO" if execute else "UNDO DRY-RUN -- no writes.")
    print(f"  {'reverted' if execute else 'would revert':<12} = {reverted:>10} "
          "(evidence_id set back to NULL)")
    print(f"  skipped      = {skipped:>10} (link changed since, row retracted or gone)")
    if not execute:
        print("Pass --execute to commit the undo.")
    summary(mode="undo" if execute else "undo-dry-run", records=len(rows),
            reverted=reverted, skipped=skipped)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--database-url", default=None)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Commit (the link, or with --undo the revert). Default is dry-run.",
    )
    parser.add_argument(
        "--undo-file",
        default=None,
        help="With --execute: a NEW file recording every linked row, written "
             "before COMMIT. Required with --execute.",
    )
    parser.add_argument(
        "--undo",
        metavar="UNDO_FILE",
        default=None,
        help="Revert the links an earlier --execute recorded in UNDO_FILE.",
    )
    args = parser.parse_args()
    if args.undo and args.undo_file:
        parser.error("--undo and --undo-file are separate modes")
    if args.execute and not args.undo and not args.undo_file:
        parser.error("--execute needs --undo-file <new file> (the record --undo reverts)")
    if args.undo_file and os.path.exists(args.undo_file):
        parser.error(f"--undo-file {args.undo_file} exists; name a new file")
    if args.undo and not os.path.isfile(args.undo):
        parser.error(f"--undo {args.undo}: no such file")
    # No built-in default (backlog 62bdae04): with no flag and no
    # environment, maintenance_dsn() refuses instead of reaching a live database.
    args.database_url = args.database_url or maintenance_dsn()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False
    try:
        missing = missing_columns(conn)
        if missing:
            print(
                f"ERROR: mass_functions lacks {', '.join(missing)}: migrations 046 "
                "(evidence_id) and 267 (slot_kind, slot_id) must be applied first.",
                file=sys.stderr,
            )
            return 2
        if args.undo:
            return do_undo(conn, args.undo, args.execute)
        return do_link(conn, args.execute, args.undo_file)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
