#!/usr/bin/env python3
"""Backfill `mass_functions.source_strength` for legacy NULL rows.

The 295k pre-2026-04-08 mass-function rows have NULL `source_strength`,
which the discount path treats as 1.0 (no discount) — undiscounted Dempster
combination then runs away to BetP≈1.0 with even mid-confidence sources.
This is bug #6 (sheaf stuck), explained at length in PR #75 and PR #76.

This is **piece 3 of 3**: backfill the legacy NULLs by inferring each row's
source_strength from its claim's evidence rows.

Policy:
  - For each NULL row with ≥1 attached evidence row: take the highest
    evidence-type weight (best-evidence wins) using the calibration map
    + DB-vocab aliases shipped in PR #75.
  - For each NULL row with no attached evidence (~82% of NULLs):
    use the conversational / agent-only tier (0.3).

The mapping is loaded from `calibration.toml` at the repo root (single
source of truth shared with the Rust engine).

Usage:
    python3 scripts/backfill_source_strength.py            # dry run
    python3 scripts/backfill_source_strength.py --execute  # commit

After --execute, run reconcile_sheaf (or wait for the next nightly
graph-integrity task) to re-aggregate beliefs. Most legacy hubs should
move down from BetP≈1.0 to a value matching their support distribution.
"""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

import psycopg2

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)
DEFAULT_CALIBRATION = Path(__file__).resolve().parent.parent / "calibration.toml"
AGENT_ONLY_TIER_KEY = "conversational"  # claims with no evidence rows
UNKNOWN_TYPE_DEFAULT = 0.5


# DB-vocab fallback: applied if calibration.toml predates PR #75 and lacks
# the [evidence_type_aliases] section. Once #75 lands, the TOML alias values
# take precedence (these defaults still match by construction).
DB_VOCAB_FALLBACK: dict[str, str] = {
    "observation": "empirical",
    "computation": "statistical",
    "document": "logical",
    "reference": "logical",
    "testimony": "testimonial",
}


def load_weight_map(calibration_path: Path) -> dict[str, float]:
    """Resolve canonical + alias evidence-type names to weights, lowercased."""
    with calibration_path.open("rb") as fh:
        cfg = tomllib.load(fh)
    canonical = {k.lower(): float(v) for k, v in cfg["evidence_type_weights"].items()}
    aliases = dict(cfg.get("evidence_type_aliases", {}))
    # Apply hardcoded DB-vocab fallback for any alias key the TOML doesn't cover.
    for alias, target in DB_VOCAB_FALLBACK.items():
        aliases.setdefault(alias, target)

    merged: dict[str, float] = dict(canonical)
    for alias, target in aliases.items():
        target_key = target.lower()
        if target_key in canonical:
            merged[alias.lower()] = canonical[target_key]
    return merged


def build_case_expression(weight_map: dict[str, float]) -> str:
    """SQL CASE expression mapping evidence_type → weight."""
    arms = "\n        ".join(
        f"WHEN lower(evidence_type) = '{k}' THEN {v:.4f}"
        for k, v in sorted(weight_map.items())
    )
    return f"""CASE
        {arms}
        ELSE {UNKNOWN_TYPE_DEFAULT}
    END"""


def preview_distribution(cur, weight_map: dict[str, float], agent_only_weight: float) -> None:
    """Print the distribution of resolved source_strength values without writing."""
    case_expr = build_case_expression(weight_map)
    cur.execute(
        f"""
        WITH null_rows AS (
            SELECT m.id AS mf_id, m.claim_id
              FROM mass_functions m
             WHERE m.source_strength IS NULL
        ),
        per_claim AS (
            SELECT n.mf_id,
                   MAX({case_expr}) AS best_weight
              FROM null_rows n
              JOIN evidence e ON e.claim_id = n.claim_id
          GROUP BY n.mf_id
        )
        SELECT 'with-evidence (max-weight derivation)' AS bucket,
               COALESCE(best_weight, %s) AS resolved_strength,
               COUNT(*) AS n_rows
          FROM per_claim
      GROUP BY 2
        UNION ALL
        SELECT 'agent-only (no evidence rows on claim)' AS bucket,
               %s AS resolved_strength,
               COUNT(*) AS n_rows
          FROM null_rows n
         WHERE NOT EXISTS (SELECT 1 FROM evidence e WHERE e.claim_id = n.claim_id)
      GROUP BY 2
      ORDER BY 1, 2 DESC
        """,
        (agent_only_weight, agent_only_weight),
    )
    print(f"{'bucket':<45} {'strength':>9} {'rows':>10}")
    print("-" * 67)
    total = 0
    for bucket, strength, n in cur.fetchall():
        print(f"{bucket:<45} {strength:>9.4f} {n:>10}")
        total += n
    print("-" * 67)
    print(f"{'total':<45} {'':>9} {total:>10}")


def execute_backfill(
    conn, weight_map: dict[str, float], agent_only_weight: float
) -> tuple[int, int]:
    """Write the resolved source_strength values. Returns (with_ev, agent_only)."""
    case_expr = build_case_expression(weight_map)
    with conn.cursor() as cur:
        cur.execute(
            f"""
            WITH null_rows AS (
                SELECT m.id AS mf_id, m.claim_id
                  FROM mass_functions m
                 WHERE m.source_strength IS NULL
            ),
            per_claim AS (
                SELECT n.mf_id,
                       MAX({case_expr}) AS best_weight
                  FROM null_rows n
                  JOIN evidence e ON e.claim_id = n.claim_id
              GROUP BY n.mf_id
            )
            UPDATE mass_functions m
               SET source_strength = pc.best_weight
              FROM per_claim pc
             WHERE m.id = pc.mf_id
            RETURNING m.id
            """
        )
        with_ev = cur.rowcount

        cur.execute(
            "UPDATE mass_functions SET source_strength = %s WHERE source_strength IS NULL",
            (agent_only_weight,),
        )
        agent_only = cur.rowcount
    conn.commit()
    return with_ev, agent_only


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
        help=f"Path to calibration.toml (default: {DEFAULT_CALIBRATION})",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually write. Without this flag, the script only previews.",
    )
    args = parser.parse_args()

    weight_map = load_weight_map(args.calibration)
    agent_only_weight = weight_map.get(AGENT_ONLY_TIER_KEY, 0.3)
    print(
        f"loaded {len(weight_map)} evidence-type weights from {args.calibration}"
    )
    print(f"agent-only tier ({AGENT_ONLY_TIER_KEY}) = {agent_only_weight}")
    print()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM mass_functions WHERE source_strength IS NULL"
        )
        n_null = cur.fetchone()[0]
    print(f"NULL source_strength rows: {n_null}")
    if n_null == 0:
        print("nothing to do.")
        return 0
    print()

    with conn.cursor() as cur:
        preview_distribution(cur, weight_map, agent_only_weight)

    if not args.execute:
        print()
        print("DRY-RUN — pass --execute to commit.")
        conn.close()
        return 0

    print()
    print("executing backfill...")
    with_ev, agent_only = execute_backfill(conn, weight_map, agent_only_weight)
    conn.close()
    print(f"  evidence-derived updates:  {with_ev}")
    print(f"  agent-only tier updates:   {agent_only}")
    print(f"  total updated:             {with_ev + agent_only}")
    print()
    print("Next: trigger reconcile_sheaf (or wait for nightly graph-integrity)")
    print("to re-aggregate beliefs. Hub BetPs should drop from ~1.0 toward")
    print("their actual support distribution.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
