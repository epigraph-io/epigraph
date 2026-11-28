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
Pass 2 links only a row shaped like the evidence BBA the forward writers
link: `combination_method = 'auto_wire'`, a source agent, no perspective and
no slot (`auto_wire_ds_for_claim` and the batch writer `wire_single_batch_entry`
in `ds_auto.rs`; the batch writer predates the FK and wrote NULL). Every other
unslotted row is reported as `not_evidence_derived`, with a breakdown by
`combination_method`, and left NULL: a truth_value seed, an `edge_factor` row
written before 267, a propagated or attributed row, a manual DS submission
(`ds.rs`, `belief.rs`: no evidence row in scope), a perspective's row, and a
combined row (`source_agent_id IS NULL`, a fold of several inputs). For all of
those `evidence_id` is NULL by contract (`mass_function.rs`, `store`).

An evidence-shaped row is then linked to its claim's evidence row E only when
the link is one-to-one:
  * the claim has exactly ONE evidence row E (several: `ambiguous`; none:
    `no_candidate`);
  * the row is the claim's only unlinked evidence-shaped row, and no other
    BBA on the claim already names E (`evidence_id = E`, or an evidence slot
    on E, which pass 1 links to E). Otherwise `shared_candidate`.
The engine keys a BBA's source item on `evidence_id` (`atom_items.rs`,
`source_dependence.rs::item_key`: rows citing one evidence row are one
source), so a second row linked to E would merge two sources into one. The
case this rules out: a claim created without an evidence row that later got
its one evidence row E through the slotted update path. Its creation row is
not from E; the slot row is.

Slotted rows are excluded from pass 2 and reported as `other_slot` when pass 1
does not apply to them:
  * an evidence-slot row already names its evidence row, so one that pass 1
    could not match must not be linked to a different row merely because its
    claim has one;
  * an edge-slot row (an edge factor) or an assessment-slot row is not
    evidence-derived.

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
only unslotted rows), and pass 2's one-to-one check already counts an evidence
slot pass 1 will link, so the dry-run counts are exactly what `--execute`
links, barring concurrent writes. The reported buckets partition the unlinked
rows.

Beliefs are not recomputed here. A linked row's visibility rule changes with
`evidence_id` (a cached combination checks the evidence row's visibility
through it), so recompute the beliefs of the claims behind the undo file after
`--execute`, and again after `--undo --execute`.

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

# Pass 2. EVIDENCE_SHAPED is the forward evidence writers' row (auto_wire, a
# source agent, no perspective, no slot); every other unslotted row is not
# evidence-derived. `{a}` is the table alias. Null-safe throughout (IS NOT
# DISTINCT FROM), so `NOT (...)` is never NULL and the buckets partition.
EVIDENCE_SHAPED = (
    "{a}.slot_kind IS NULL AND {a}.perspective_id IS NULL "
    "AND {a}.source_agent_id IS NOT NULL "
    "AND {a}.combination_method IS NOT DISTINCT FROM 'auto_wire'"
)
UNSLOTTED = "mf.slot_kind IS NULL"
SHAPED = EVIDENCE_SHAPED.format(a="mf")
# One-to-one: no OTHER row on the claim names E (linked to it, or an evidence
# slot on it, which pass 1 links), and no other unlinked live evidence-shaped
# row competes for it. `{e}` is the expression for E.
ONE_TO_ONE = (
    "NOT EXISTS (SELECT 1 FROM mass_functions o "
    "WHERE o.claim_id = mf.claim_id AND o.id <> mf.id AND ("
    "o.evidence_id = {e} "
    "OR (o.slot_kind = 'evidence' AND o.slot_id = {e}) "
    "OR (o.evidence_id IS NULL AND o.retracted_at IS NULL AND "
    + EVIDENCE_SHAPED.format(a="o")
    + ")))"
)
# Postgres lacks `MIN(uuid)`; with HAVING COUNT(*) = 1, `(array_agg(id))[1]`
# is that sole row.
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
   AND {SHAPED}
   AND {ONE_TO_ONE.format(e="sec.evidence_id")}
RETURNING mf.id::text, mf.evidence_id::text
"""

# Every unlinked row in exactly one bucket, built from the same predicates as
# the two UPDATEs so a dry run counts what --execute would link.
BUCKETS_SQL = f"""
WITH ec AS (
    SELECT claim_id, COUNT(*) AS n, (array_agg(id))[1] AS sole_id
      FROM evidence GROUP BY claim_id
)
SELECT
  COUNT(*) FILTER (WHERE mf.retracted_at IS NOT NULL)                            AS retracted,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {SLOT_MATCH})                            AS slot_linkable,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND mf.slot_kind = 'evidence'
                     AND NOT ({SLOT_MATCH}))                                     AS slot_unmatched,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND mf.slot_kind <> 'evidence')             AS other_slot,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {UNSLOTTED} AND NOT ({SHAPED}))          AS not_evidence_derived,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {SHAPED} AND COALESCE(ec.n, 0) = 1
                     AND {ONE_TO_ONE.format(e="ec.sole_id")})                    AS single_linkable,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {SHAPED} AND COALESCE(ec.n, 0) = 1
                     AND NOT ({ONE_TO_ONE.format(e="ec.sole_id")}))              AS shared_candidate,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {SHAPED} AND COALESCE(ec.n, 0) > 1)      AS ambiguous,
  COUNT(*) FILTER (WHERE {ELIGIBLE} AND {SHAPED} AND COALESCE(ec.n, 0) = 0)      AS no_candidate,
  COUNT(*)                                                                        AS unlinked
  FROM mass_functions mf
  LEFT JOIN ec ON ec.claim_id = mf.claim_id
 WHERE mf.evidence_id IS NULL
"""

# The `not_evidence_derived` bucket by label: what the single-candidate rule
# would have linked before it was restricted to evidence-shaped rows.
NOT_DERIVED_BY_METHOD_SQL = f"""
SELECT COALESCE(mf.combination_method, '(null)') AS method, COUNT(*)
  FROM mass_functions mf
 WHERE {ELIGIBLE} AND {UNSLOTTED} AND NOT ({SHAPED})
 GROUP BY 1
 ORDER BY 2 DESC, 1
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

BUCKET_KEYS = ("retracted", "slot_linkable", "slot_unmatched", "other_slot",
               "not_evidence_derived", "single_linkable", "shared_candidate",
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


def not_derived_by_method(conn) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute(NOT_DERIVED_BY_METHOD_SQL)
        return {m: int(n) for m, n in cur.fetchall()}


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


def print_buckets(b: dict[str, int], slot: int, single: int, verb: str,
                  by_method: dict[str, int]) -> None:
    print("  pass 1 (evidence slot, exact):")
    print(f"    {verb:<12} = {slot:>10}")
    print(f"    unmatched    = {b['slot_unmatched']:>10} (slot's evidence row missing "
          f"or on another claim; left NULL)")
    print(f"  other_slot     = {b['other_slot']:>10} (edge or assessment slot; not "
          f"evidence-derived, never linked)")
    print(f"  not_evidence_derived = {b['not_evidence_derived']:>10} (unslotted, not an "
          f"auto_wire row of one agent; never linked)")
    for method, n in by_method.items():
        print(f"    {method:<26} {n:>10}")
    print("  pass 2 (single candidate, unslotted evidence-shaped rows):")
    print(f"    {verb:<12} = {single:>10}")
    print(f"    shared       = {b['shared_candidate']:>10} (the one evidence row is already "
          f"named by another BBA, or several rows compete for it; left NULL)")
    print(f"    ambiguous    = {b['ambiguous']:>10} (claim has >= 2 evidence rows; left NULL)")
    print(f"    no_candidate = {b['no_candidate']:>10} (claim has no evidence row; left NULL)")
    print(f"  retracted      = {b['retracted']:>10} (evidence_id frozen; never linked)")
    print(f"  unlinked total = {b['unlinked']:>10}")


def pass_counts(b: dict[str, int], slot: int, single: int, by_method: dict[str, int]) -> dict:
    return {
        "pass1_slot": {"linked": slot, "unmatched": b["slot_unmatched"]},
        "pass2_single": {
            "linked": single,
            "shared_candidate": b["shared_candidate"],
            "ambiguous": b["ambiguous"],
            "no_candidate": b["no_candidate"],
        },
        "not_evidence_derived": b["not_evidence_derived"],
        "not_evidence_derived_by_method": by_method,
        "other_slot": b["other_slot"],
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
        by_method = not_derived_by_method(conn)
        print_buckets(before, before["slot_linkable"], before["single_linkable"], "would link",
                      by_method)
        print()
        print("Pass --execute --undo-file <new file> to commit.")
        conn.rollback()
        summary(mode="dry-run", **pass_counts(
            before, before["slot_linkable"], before["single_linkable"], by_method))
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
    by_method = not_derived_by_method(conn)
    conn.rollback()
    print(f"  undo file: {undo_file} ({len(records)} rows)")
    print_buckets(after, len(slot_rows), len(single_rows), "linked", by_method)
    print()
    print("A re-run links nothing new (every UPDATE has `evidence_id IS NULL`). "
          f"Revert with --undo {undo_file}.")
    print("Recompute the beliefs of the linked rows' claims (see the header).")
    summary(mode="execute", **pass_counts(after, len(slot_rows), len(single_rows), by_method))
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
