#!/usr/bin/env python3
"""Compose intra-source locality factor onto historical `mass_functions.source_strength`.

Companion to `backfill_source_strength.py` (commit 5202ded, 2026-05-03), which
populated `source_strength` from per-BBA `evidence_type` weights. This script
multiplies that per-BBA reliability by the calibrated
`intra_evidence_locality_factor` (from `calibration.toml`, default 0.3) for
BBAs whose claim has at least one intra-source evidence row.

Composition (does NOT replace):
    source_strength_new = source_strength_old * intra_evidence_locality_factor

So a logical/intra BBA at 0.85 lands at 0.85 * 0.3 = 0.255 (close to the
single-value 0.25 the original #185 script REPLACED with), but an
empirical/intra BBA at 1.0 lands at 0.30 — preserving the evidence-type
ordering. Cross-source BBAs are left untouched.

Per-frame override: `frames.properties->>'intra_evidence_locality_factor'`,
if set, takes precedence over the calibration.toml global default for BBAs
on that frame (migration 044). Mirrors the resolution order in
`edge_factor.rs`, so the backfill applies the same locality model new edge
writes use. Operators set per-frame overrides via
FrameRepository::set_property or directly:
    UPDATE frames SET properties = properties ||
      jsonb_build_object('intra_evidence_locality_factor', 0.5)
     WHERE name = 'research_validity';

Schema bridge:
  mass_functions.claim_id -> evidence.claim_id
  evidence.properties->>'doi' = (paper that asserts mass_functions.claim_id)

Heuristic: the script discounts every BBA on a claim that has ≥1 intra-source
evidence row (by doi match). It cannot tell which BBAs derived from which
evidence row, so claims with MIXED intra+cross evidence over-discount the
cross-derived BBAs. The long-term fix is per-BBA provenance (e.g.
`mass_functions.evidence_id` FK); this script is the pragmatic step until
that lands.

Usage:
    # Dry run — preview, no writes:
    python3 scripts/backfill_intra_source_evidence_discount.py

    # Commit — UPDATE the BBAs AND write affected claim_ids to a file:
    python3 scripts/backfill_intra_source_evidence_discount.py --execute

    # Refresh the cached BetP on the affected claims (the
    # `claims.{belief, plausibility, pignistic_prob, ...}` scalars):
    DATABASE_URL=... epigraph-recompute-belief \\
        --input /tmp/locality-backfill-affected-claims.txt

By default `--scope 0.85` targets the largest tier (≈74 711 BBAs in prod
as of 2026-05-27). Pass `--scope 1.0`, `--scope 0.75`, `--scope 0.5`,
`--scope 0.3`, or `--scope all` to widen.

Idempotency: the predicate only matches BBAs whose `source_strength`
sits at an UNCOMPOSED tier value. The set of post-composition values
({0.255, 0.225, 0.30, 0.18, 0.09} for the standard tiers at intra=0.3)
is disjoint from the set of pre-composition tier values
({0.85, 0.75, 1.0, 0.6, 0.3}) for any intra factor strictly less than 1.0,
so a second run sees no candidates. The forward write path (post-#185)
ALSO emits composed values directly, so newly-written BBAs are also
naturally excluded from re-discounting.

Why is the recompute a separate step?

The UPDATE landed on ``mass_functions.source_strength`` is one transaction
— atomic, fast, easy to reason about. The cached BetP on each affected
claim, on the other hand, requires fetching all BBAs on every (claim,
frame) pair, applying the new discount, combining via Dempster's rule,
and writing back. That's per-claim and per-frame, takes ~2 minutes for
~16k claims, and is naturally idempotent (re-running just re-derives
the same combined values). Coupling these two operations behind a
single ``--execute`` flag bound them to the same transaction's
success/failure semantics and locked the operator into one strategy
(synchronous HTTP per-claim). An earlier version of this script tried
that and hit two bugs at once: wrong URL, AND the only available HTTP
route is a global obstruction-resolver that doesn't recompute the bulk
of an affected population. PR #195 introduced ``epigraph-recompute-belief``
as the canonical per-claim, per-frame recompute path; this script's job
is now just to emit the claim list for it to consume.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for older interpreters
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]

import psycopg2


DEFAULT_DATABASE_URL = "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph"
DEFAULT_CALIBRATION = Path(__file__).resolve().parent.parent / "calibration.toml"

# Scope flag maps to a tier filter on `mf.source_strength`. `all` means
# "every BBA at a known uncomposed tier value". The pre-composition tier
# set is {0.85, 0.75, 1.0, 0.6, 0.3, 0.5, 0.9, 0.95, 0.98, 0.99, 0.97, 0.93,
# 0.92, 0.96, 0.8} — the 15 largest source_strength buckets in prod today.
# Composed values (input * 0.3) won't appear in this set for any intra
# factor strictly less than 1.0, which gives us natural idempotency
# without a schema-level marker.
KNOWN_TIERS = (
    1.0, 0.99, 0.98, 0.97, 0.96, 0.95, 0.93, 0.92, 0.9, 0.85, 0.8, 0.75, 0.6, 0.5, 0.3,
)
SCOPE_TIERS: dict[str, tuple[float, ...] | None] = {
    "1.0": (1.0,),
    "0.85": (0.85,),
    "0.75": (0.75,),
    "0.6": (0.6,),
    "0.5": (0.5,),
    "0.3": (0.3,),
    "all": KNOWN_TIERS,
}


def load_intra_factor(calibration_path: Path) -> float:
    with calibration_path.open("rb") as fh:
        cfg = tomllib.load(fh)
    locality = cfg["evidence_locality"]
    # Accept either the new key or, transitionally, the old one. The script
    # itself only uses the new key going forward.
    if "intra_evidence_locality_factor" in locality:
        return float(locality["intra_evidence_locality_factor"])
    raise KeyError(
        "evidence_locality.intra_evidence_locality_factor missing from "
        f"{calibration_path}. Did the calibration shape change?"
    )


def in_clause(values: tuple[float, ...]) -> str:
    """Render a SQL `IN (...)` list from a tuple of floats."""
    return "(" + ", ".join(f"{v}" for v in values) + ")"


# Numeric-literal regex for parsing per-frame property values. Mirrors the
# Rust `f64::parse` behaviour the engine uses, so the SQL and the engine
# agree on which property values are "valid" overrides.
_FACTOR_REGEX = r"^-?[0-9]+(\\.[0-9]+)?$"


def effective_factor_sql(global_default_placeholder: str = "%s") -> str:
    """SQL expression that resolves the per-frame factor for `mf`.

    Returns a SQL fragment that evaluates to:
      * (frames.properties->>'intra_evidence_locality_factor')::float8
        when the override is present AND parses as a number,
      * the global default placeholder otherwise.

    The caller is responsible for binding the global default as a
    parameter at the placeholder.
    """
    return (
        "CASE "
        f"WHEN f.properties ? 'intra_evidence_locality_factor' "
        f"AND (f.properties->>'intra_evidence_locality_factor') ~ '{_FACTOR_REGEX}' "
        f"THEN (f.properties->>'intra_evidence_locality_factor')::float8 "
        f"ELSE {global_default_placeholder} "
        "END"
    )


def candidate_query(scope_tiers: tuple[float, ...]) -> str:
    """SELECT for in-scope BBAs. `scope_tiers` filters `mf.source_strength`.

    Match criterion: BBA's claim has at least one evidence row whose
    `properties->>'doi'` equals the doi of the paper that asserts the
    claim. The set of post-composition tier values is disjoint from
    `scope_tiers` for any intra factor < 1.0, giving natural idempotency
    (with the additional caveat that a per-frame override at the global
    default value won't move BBAs at that tier — operators setting
    overrides at non-default values get clean re-runs as well).

    The JOIN to `frames` lets us pull the per-frame
    `intra_evidence_locality_factor` override when set; the
    `effective_factor` column carries the resolved value (per-frame or
    global default) so the caller can group preview output by it.
    """
    tier_filter = f"mf.source_strength IN {in_clause(scope_tiers)}"
    factor_expr = effective_factor_sql()
    return f"""
        SELECT mf.id, mf.claim_id, mf.source_strength,
               {factor_expr} AS effective_factor
          FROM mass_functions mf
          JOIN frames f ON f.id = mf.frame_id
         WHERE {tier_filter}
           AND EXISTS (
               SELECT 1
                 FROM evidence e
                 JOIN edges ed
                   ON ed.target_id = e.claim_id
                  AND ed.relationship = 'asserts'
                  AND ed.source_type = 'paper'
                 JOIN papers p
                   ON p.id = ed.source_id
                  AND p.doi = e.properties->>'doi'
                WHERE e.claim_id = mf.claim_id
                  AND e.properties ? 'doi'
           );
    """


def count_out_of_scope_candidates(
    conn, scope_tiers: tuple[float, ...]
) -> tuple[int, int, list[tuple[float, int]]]:
    """Count intra-source candidates at tiers OUTSIDE the current scope.

    Catches the "0 in current scope but lots elsewhere" trap — if an
    operator runs `--scope 0.85` after a prior run discounted that
    tier, the in-scope count is honestly 0 but tiers like 0.75 or 0.5
    may still hold thousands of unprocessed intra-source BBAs.

    Returns ``(total_rows, distinct_claims, [(tier, rows), ...])`` for the
    complementary tier set. Returns empty / zero when current scope is
    already `all`.
    """
    out_of_scope = tuple(t for t in KNOWN_TIERS if t not in scope_tiers)
    if not out_of_scope:
        return 0, 0, []
    sql = f"""
        SELECT mf.source_strength, mf.claim_id
          FROM mass_functions mf
         WHERE mf.source_strength IN {in_clause(out_of_scope)}
           AND EXISTS (
               SELECT 1
                 FROM evidence e
                 JOIN edges ed
                   ON ed.target_id = e.claim_id
                  AND ed.relationship = 'asserts'
                  AND ed.source_type = 'paper'
                 JOIN papers p
                   ON p.id = ed.source_id
                  AND p.doi = e.properties->>'doi'
                WHERE e.claim_id = mf.claim_id
                  AND e.properties ? 'doi'
           );
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    by_tier: dict[float, int] = {}
    claims: set = set()
    for ss, cid in rows:
        by_tier[float(ss)] = by_tier.get(float(ss), 0) + 1
        claims.add(cid)
    breakdown = sorted(by_tier.items(), key=lambda kv: kv[1], reverse=True)
    return len(rows), len(claims), breakdown


def report_out_of_scope(scope_tiers: tuple[float, ...], conn) -> None:
    """Print a footer showing intra-source candidates at OTHER tiers, if any.

    Always runs (except when scope is already `all`) — the goal is to
    prevent a "0 in scope = nothing to do" misread of the dry-run.
    """
    if set(scope_tiers) >= set(KNOWN_TIERS):
        return
    n_rows, n_claims, breakdown = count_out_of_scope_candidates(conn, scope_tiers)
    if n_rows == 0:
        return
    print()
    print(
        f"FYI: {n_rows} additional intra-source candidates across "
        f"{n_claims} claims sit at OTHER tiers (not in --scope {scope_tiers}):"
    )
    print(f"  {'tier':>9} {'rows':>10}")
    for tier, rows in breakdown:
        print(f"  {tier:>9.4f} {rows:>10}")
    print(
        "Run with --scope all (or specific tiers) to include them; current scope "
        "is honest but partial."
    )


def preview_distribution(
    conn, scope_tiers: tuple[float, ...], intra_factor: float
) -> tuple[int, int]:
    """Show what would be written, grouped by (source_strength, effective_factor).

    The effective_factor varies when frames carry a per-frame
    `intra_evidence_locality_factor` override. Reporting both columns
    surfaces those overrides explicitly instead of hiding them inside a
    single "post" number that conflates frame-level differences.
    """
    sql = candidate_query(scope_tiers)
    with conn.cursor() as cur:
        cur.execute(sql, (intra_factor,))
        rows = cur.fetchall()
    n_rows = len(rows)
    n_claims = len({r[1] for r in rows})

    print(f"matched {n_rows} BBAs across {n_claims} target claims in --scope")

    if n_rows > 0:
        # Group by (source_strength, effective_factor) so per-frame
        # overrides show up as distinct buckets.
        by_bucket: dict[tuple[float, float], int] = {}
        for _, _, ss, factor in rows:
            key = (float(ss), float(factor))
            by_bucket[key] = by_bucket.get(key, 0) + 1

        print(f"{'pre':>9} {'factor':>9} {'post':>9} {'rows':>10}")
        print("-" * 42)
        for (tier, factor) in sorted(by_bucket.keys(), reverse=True):
            post = tier * factor
            marker = " *" if abs(factor - intra_factor) > 1e-9 else ""
            print(
                f"{tier:>9.4f} {factor:>9.4f} {post:>9.4f} "
                f"{by_bucket[(tier, factor)]:>10}{marker}"
            )
        print("-" * 42)
        print(f"  (global default factor: {intra_factor}; '*' = per-frame override)")

    # Always show what's left outside the current scope — both when the
    # in-scope count is 0 (catch the "looks idempotent, isn't done" trap)
    # and when it's non-zero (catch "this scope is partial, here's the
    # rest").
    report_out_of_scope(scope_tiers, conn)
    return n_rows, n_claims


def execute_backfill(
    conn, scope_tiers: tuple[float, ...], intra_factor: float
) -> tuple[int, list]:
    """Multiply source_strength by the resolved per-frame factor for in-scope BBAs.

    Effective factor per row = per-frame override if set, else `intra_factor`
    (the global default from calibration.toml). Mirrors the resolution
    order in `edge_factor::wire_evidential_edge_factor`.

    Returns (n_rows_updated, sorted_unique_affected_claim_ids).
    """
    tier_filter = f"mf.source_strength IN {in_clause(scope_tiers)}"
    factor_expr = effective_factor_sql()
    sql = f"""
        UPDATE mass_functions mf
           SET source_strength = source_strength * ({factor_expr})
          FROM frames f
         WHERE f.id = mf.frame_id
           AND {tier_filter}
           AND EXISTS (
               SELECT 1
                 FROM evidence e
                 JOIN edges ed
                   ON ed.target_id = e.claim_id
                  AND ed.relationship = 'asserts'
                  AND ed.source_type = 'paper'
                 JOIN papers p
                   ON p.id = ed.source_id
                  AND p.doi = e.properties->>'doi'
                WHERE e.claim_id = mf.claim_id
                  AND e.properties ? 'doi'
           )
         RETURNING mf.claim_id;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (intra_factor,))
        claim_ids = [row[0] for row in cur.fetchall()]
    n_rows = len(claim_ids)
    conn.commit()
    return n_rows, sorted(set(claim_ids))


def write_affected_claims(path: Path, claim_ids: list) -> None:
    """Persist the affected claim_ids to a file, one UUID per line.

    Consumed by `epigraph-recompute-belief --input <path>` to refresh
    the cached `claims.{belief, plausibility, pignistic_prob, ...}`
    that this script's UPDATE invalidates.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        f.write("# affected claim_ids from backfill_intra_source_evidence_discount.py\n")
        f.write(f"# {len(claim_ids)} unique claims\n")
        for cid in claim_ids:
            f.write(f"{cid}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
    )
    parser.add_argument(
        "--calibration",
        type=Path,
        default=DEFAULT_CALIBRATION,
    )
    parser.add_argument(
        "--scope",
        choices=sorted(SCOPE_TIERS.keys()),
        default="0.85",
        help="Tier of source_strength to target. Default 0.85 (largest tier in prod).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Write the multiplication and persist affected claim_ids. Otherwise dry-run.",
    )
    parser.add_argument(
        "--affected-claims-out",
        type=Path,
        default=Path("/tmp/locality-backfill-affected-claims.txt"),
        help=(
            "Where to write the list of affected claim_ids on --execute. "
            "Feed this file to `epigraph-recompute-belief --input <path>` "
            "to refresh the cached BetP on the affected claims."
        ),
    )
    args = parser.parse_args()

    intra_factor = load_intra_factor(args.calibration)
    scope_tiers = SCOPE_TIERS[args.scope]
    assert scope_tiers is not None
    print(f"intra_evidence_locality_factor = {intra_factor}")
    print(f"scope = {args.scope} (tier filter: source_strength IN {in_clause(scope_tiers)})")
    print()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    n_rows, _n_claims = preview_distribution(conn, scope_tiers, intra_factor)

    if n_rows == 0:
        print()
        print("nothing to do in --scope (see FYI above for other tiers, if any)")
        conn.close()
        return 0

    if not args.execute:
        print()
        print("DRY-RUN — pass --execute to commit.")
        conn.close()
        return 0

    print()
    print(f"executing UPDATE (source_strength * {intra_factor})...")
    written, claim_ids = execute_backfill(conn, scope_tiers, intra_factor)
    print(f"  updated {written} BBAs across {len(claim_ids)} claims")
    conn.close()

    write_affected_claims(args.affected_claims_out, claim_ids)
    print()
    print(f"affected claim_ids → {args.affected_claims_out}")
    print()
    print("Next: refresh the cached BetP on the affected claims —")
    print(
        f"    DATABASE_URL=... epigraph-recompute-belief --input {args.affected_claims_out}"
    )
    print(
        "Until you run that, `claims.{belief, plausibility, pignistic_prob}` for "
        "these claims will reflect the PRE-discount BBA values; the BBA layer "
        "is already consistent."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
