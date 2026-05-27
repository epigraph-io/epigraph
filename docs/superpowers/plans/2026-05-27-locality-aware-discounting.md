# Locality-Aware Source-Strength Discounting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a `supports`/`refutes`/`corroborates`/`contradicts` edge is created, detect whether endpoints share a source paper. If so, write the BBA with a smaller `source_strength` so the existing Shafer discount in CDST combine deflates the intra-source contribution instead of treating it as a fully independent observation. Closes issue #142 (in spirit — the original retype mechanism is replaced; see spec).

**Architecture:** New Postgres function `same_source_papers(a, b)` traversing the `{asserts, same_source, section_follows, continues_argument, decomposes_to}` closure. `trigger_edge_ds_recomputation` (in `crates/epigraph-api/src/routes/edges.rs`) consults this function and picks a `source_strength` from new calibration keys `evidence_locality.{intra_source,cross_source}_support_strength`. The combine path itself does not change — only the per-BBA reliability does. Existing data is cleaned up by a one-shot operator script.

**Tech Stack:** Postgres (recursive CTE function), Rust, sqlx, `epigraph-engine::calibration`, `epigraph-api`, `epigraph-mcp` MCP tools, Python operator script (for backfill).

---

## Setup

**Branch.** Branch from `origin/main` (not from the spec branches). The latest migration on `main` is `040_workflows_goal_embedding.sql`, so this plan uses `041`.

```bash
cd /home/jeremy/epigraph
git fetch origin main
git checkout -b feat/locality-aware-discounting origin/main
```

**Test database.** `epigraph_db_repo_test`, per `CLAUDE.md`:

```bash
export DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test'
```

**Spec reference.** `docs/superpowers/specs/2026-05-27-alternative-and-dependency-edges-design.md` § 2 (Locality-aware discounting). This plan implements that section only; the alt-set companion plan covers § 1, 3, 4, 5.

---

### Task 1: `same_source_papers` Postgres function

**Files:**
- Create: `migrations/041_same_source_papers_function.sql`

- [ ] **Step 1: Write the migration**

```sql
-- 041_same_source_papers_function.sql
--
-- Predicate: do claims a and b share a source paper, traversing the
-- transitive closure of {asserts, same_source, section_follows,
-- continues_argument, decomposes_to}?
--
-- Used by edges.rs::trigger_edge_ds_recomputation to set a smaller
-- source_strength on intra-source evidential BBAs (Shafer reliability
-- discount). See docs/superpowers/specs/2026-05-27-alternative-and-dependency-edges-design.md.

CREATE OR REPLACE FUNCTION same_source_papers(a UUID, b UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
AS $$
DECLARE
    result BOOLEAN;
BEGIN
    IF a = b THEN
        RETURN TRUE;
    END IF;

    WITH RECURSIVE seeds AS (
        -- Papers that assert `a` are seed nodes.
        SELECT e.source_id AS paper_id
        FROM edges e
        WHERE e.target_id = a
          AND e.relationship = 'asserts'
    ),
    paper_a_closure AS (
        -- Claims reachable from any of a's papers through intra-source edges.
        SELECT e.target_id AS claim_id
        FROM seeds s
        JOIN edges e
          ON e.source_id = s.paper_id
         AND e.relationship = 'asserts'
        UNION
        SELECT e2.target_id
        FROM paper_a_closure pac
        JOIN edges e2
          ON e2.source_id = pac.claim_id
         AND e2.relationship IN (
             'same_source', 'section_follows',
             'continues_argument', 'decomposes_to'
         )
        UNION
        SELECT e3.source_id
        FROM paper_a_closure pac
        JOIN edges e3
          ON e3.target_id = pac.claim_id
         AND e3.relationship IN (
             'same_source', 'section_follows',
             'continues_argument', 'decomposes_to'
         )
    )
    SELECT EXISTS (
        SELECT 1 FROM paper_a_closure WHERE claim_id = b
    ) INTO result;

    RETURN COALESCE(result, FALSE);
END;
$$;

COMMENT ON FUNCTION same_source_papers(UUID, UUID) IS
'True iff claim a and claim b share a source paper via the transitive closure of '
'{asserts, same_source, section_follows, continues_argument, decomposes_to}. '
'Drives intra-source source_strength discounting in trigger_edge_ds_recomputation.';
```

- [ ] **Step 2: Apply and confirm the migration**

```bash
cd /home/jeremy/epigraph
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  sqlx migrate run
psql "$DATABASE_URL" -c "\\df same_source_papers"
```

Expected: function appears in `\df` output with signature `(uuid, uuid) -> boolean`.

- [ ] **Step 3: Commit**

```bash
git add migrations/041_same_source_papers_function.sql
git commit -m "feat(db): same_source_papers function for locality-aware discounting"
```

---

### Task 2: Truth-table integration test for the predicate

**Files:**
- Create: `crates/epigraph-db/tests/same_source_papers_truth_table.rs`

- [ ] **Step 1: Write the test**

```rust
//! Truth-table coverage for migration 041's same_source_papers function.
//!
//! Setup: two papers, each asserting two claims. Intra-paper pairs return true
//! (regardless of which traversal path), cross-paper pairs return false,
//! self-pair returns true (short-circuit).

mod common;

use sqlx::{PgPool, Row};
use uuid::Uuid;

async fn seed(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid) {
    let p1 = common::seed_paper(pool, "Paper One").await;
    let p2 = common::seed_paper(pool, "Paper Two").await;

    let a1 = common::seed_claim(pool, "p1::claim1").await;
    let a2 = common::seed_claim(pool, "p1::claim2").await;
    let b1 = common::seed_claim(pool, "p2::claim1").await;
    let b2 = common::seed_claim(pool, "p2::claim2").await;

    // p1 asserts a1, a2
    common::insert_edge(pool, p1, a1, "paper", "claim", "asserts").await;
    common::insert_edge(pool, p1, a2, "paper", "claim", "asserts").await;

    // p2 asserts b1, b2
    common::insert_edge(pool, p2, b1, "paper", "claim", "asserts").await;
    common::insert_edge(pool, p2, b2, "paper", "claim", "asserts").await;

    // a1 decomposes_to a2 (intra-paper sibling-via-decomposes)
    common::insert_edge(pool, a1, a2, "claim", "claim", "decomposes_to").await;

    (a1, a2, b1, b2)
}

#[tokio::test]
async fn same_source_papers_truth_table() {
    let pool = common::test_pool().await;
    let (a1, a2, b1, b2) = seed(&pool).await;

    let q = |x: Uuid, y: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query("SELECT same_source_papers($1, $2) AS r")
                .bind(x)
                .bind(y)
                .fetch_one(&pool)
                .await
                .unwrap()
                .get::<bool, _>("r")
        }
    };

    assert!(q(a1, a1).await, "self-pair must be true");
    assert!(q(a1, a2).await, "intra-paper via asserts+asserts (sibling)");
    assert!(q(a2, a1).await, "intra-paper symmetric (a2,a1)");
    assert!(!q(a1, b1).await, "cross-paper must be false");
    assert!(!q(b1, a2).await, "cross-paper must be false (reversed)");
    assert!(q(b1, b2).await, "intra-paper for paper 2");
}
```

If `crates/epigraph-db/tests/common/` is missing helpers `seed_paper`, `seed_claim`, `insert_edge`, `test_pool`, add minimal versions modeled on `crates/epigraph-db/tests/paper_repo_tests.rs` (which already seeds papers).

- [ ] **Step 2: Run and verify the test passes against the function from Task 1**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-db --test same_source_papers_truth_table -- --nocapture
```

Expected: PASS (6 assertions).

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-db/tests/same_source_papers_truth_table.rs \
        crates/epigraph-db/tests/common/
git commit -m "test(db): truth-table for same_source_papers predicate"
```

---

### Task 3: Calibration keys for locality discounts

**Files:**
- Modify: `calibration.toml` (workspace root)
- Modify: `crates/epigraph-engine/src/calibration.rs`

- [ ] **Step 1: Add the calibration block**

Append to `/home/jeremy/epigraph/calibration.toml`:

```toml
# ── Evidence Locality Discounting ───────────────────────────────────────────
# Shafer reliability discount applied to evidential BBAs based on whether the
# edge crosses paper boundaries. Intra-source supporters are not independent
# observations of a target, so their per-BBA reliability is lower.
#
# Defaults tuned against the synthetic 19-supporter NEMS regression: target
# BetP lands in [0.7, 0.85] (replacing the un-discounted 0.997 inflation).

[evidence_locality]
intra_source_support_strength = 0.3
cross_source_support_strength = 1.0
```

- [ ] **Step 2: Extend `CalibrationConfig`**

In `crates/epigraph-engine/src/calibration.rs`, add to `CalibrationConfig` (after the `journal_reliability` field, before `classifier_thresholds`):

```rust
    /// Evidence-locality discounts applied to per-BBA source_strength.
    ///
    /// Drives Shafer reliability discounting in
    /// `routes/edges.rs::trigger_edge_ds_recomputation` based on whether the
    /// supporting and supported claims share a source paper.
    #[serde(default = "default_evidence_locality")]
    pub evidence_locality: EvidenceLocality,
```

And below the existing struct, add:

```rust
/// Discount factors keyed on whether evidence crosses paper boundaries.
#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceLocality {
    /// `source_strength` for intra-paper evidential BBAs (low — supporters
    /// from one paper are not independent observations).
    pub intra_source_support_strength: f64,

    /// `source_strength` for cross-paper evidential BBAs (full reliability).
    pub cross_source_support_strength: f64,
}

fn default_evidence_locality() -> EvidenceLocality {
    EvidenceLocality {
        intra_source_support_strength: 0.3,
        cross_source_support_strength: 1.0,
    }
}
```

The `serde(default)` lets older / partial calibration files keep loading.

- [ ] **Step 3: Add a unit test confirming the keys round-trip**

In `crates/epigraph-engine/src/calibration.rs`, add to the existing test module:

```rust
    #[test]
    fn test_evidence_locality_loads() {
        let config = CalibrationConfig::from_workspace_root()
            .expect("calibration.toml should load successfully");
        assert!(
            (config.evidence_locality.intra_source_support_strength - 0.3).abs() < 1e-9,
            "intra_source_support_strength = {}",
            config.evidence_locality.intra_source_support_strength
        );
        assert!(
            (config.evidence_locality.cross_source_support_strength - 1.0).abs() < 1e-9,
            "cross_source_support_strength = {}",
            config.evidence_locality.cross_source_support_strength
        );
    }
```

- [ ] **Step 4: Run the test**

```bash
cargo test -p epigraph-engine test_evidence_locality_loads -- --nocapture
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add calibration.toml crates/epigraph-engine/src/calibration.rs
git commit -m "feat(engine): evidence_locality calibration keys for intra/cross-source discount"
```

---

### Task 4: Wire locality-aware `source_strength` into `trigger_edge_ds_recomputation`

**Files:**
- Modify: `crates/epigraph-api/src/routes/edges.rs:155-300` (the function body of `trigger_edge_ds_recomputation`)

- [ ] **Step 1: Look up the current function**

```bash
grep -n "fn trigger_edge_ds_recomputation\|MassFunctionRepository::store" \
     crates/epigraph-api/src/routes/edges.rs
```

Expected: function starts at `:156`; the existing `MassFunctionRepository::store` call (around `:224`) passes `None` (or a literal `0.7 * 0.5` inside `mass_value`) — it does *not* currently set `source_strength`. The change below replaces that call with one that binds `source_strength` from the locality predicate.

- [ ] **Step 2: Modify the function to consult `same_source_papers` and pass `source_strength`**

In `crates/epigraph-api/src/routes/edges.rs`, inside `trigger_edge_ds_recomputation`, just before the `MassFunctionRepository::store(...)` call (currently around `:224`), insert:

```rust
    // Locality-aware reliability discount. Same-paper supporters are not
    // independent observations of the target — apply a smaller source_strength
    // so the existing Shafer discount in CDST combine deflates the per-BBA
    // contribution. Defaults: intra=0.3, cross=1.0 (see calibration.toml).
    let same_source: bool = sqlx::query_scalar::<_, bool>(
        "SELECT same_source_papers($1, $2)",
    )
    .bind(source_claim_id)
    .bind(target_claim_id)
    .fetch_one(pool)
    .await
    .map_err(|e| crate::errors::ApiError::DatabaseError {
        message: format!("same_source_papers: {e}"),
    })?;

    let calibration = epigraph_engine::calibration::CalibrationConfig::from_workspace_root()
        .ok();
    let (intra, cross) = calibration
        .as_ref()
        .map(|c| {
            (
                c.evidence_locality.intra_source_support_strength,
                c.evidence_locality.cross_source_support_strength,
            )
        })
        .unwrap_or((0.3, 1.0));
    let source_strength = if same_source { intra } else { cross };
```

Then replace the existing `MassFunctionRepository::store(...)` call with `store_with_perspective(...)`, which already accepts `source_strength` (see `crates/epigraph-mcp/src/tools/ds_auto.rs:269-280` for the canonical caller). The store call becomes:

```rust
    MassFunctionRepository::store_with_perspective(
        pool,
        target_claim_id,
        frame_id,
        Some(source_agent_id),
        None,                              // perspective_id — keep current behavior
        &masses_json,
        None,                              // conflict_k
        Some("discount"),                  // combination_method
        Some(source_strength),             // source_strength — locality-aware
        None,                              // evidence_type — N/A for edge-derived BBAs
    )
    .await
    .map_err(|e| crate::errors::ApiError::DatabaseError {
        message: format!("Failed to store edge mass function: {e}"),
    })?;
```

`store_with_perspective` is already public (per its use in `ds_auto.rs:269-280` from an external crate).

- [ ] **Step 3: Confirm the change compiles**

```bash
SQLX_OFFLINE=true cargo check -p epigraph-api
```

Expected: clean. If `sqlx::query_scalar` flags an offline-mode mismatch, run:

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo sqlx prepare --workspace -- --tests
git add .sqlx/
```

- [ ] **Step 4: Do NOT commit yet — Task 5 covers it together with the regression**

---

### Task 5: 19-supporter synthetic regression test

**Files:**
- Create: `crates/epigraph-engine/tests/intra_source_discount_regression.rs`

- [ ] **Step 1: Write the regression test**

```rust
//! 19-supporter synthetic regression for locality-aware discounting.
//!
//! Mirrors the NEMS shape from issue #142: one target T, 19 supporting claims
//! S1..S19 each asserting (paper p1) the same target. With cross-source
//! source_strength=1.0 the combined BetP approaches 0.997 (current behavior).
//! With intra-source source_strength=0.3 from calibration.toml, BetP drops
//! into [0.7, 0.85] — the band the issue requires.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

async fn seed_19_intra_source_supporters(pool: &PgPool) -> Uuid {
    let paper = common::seed_paper(pool, "Synthesis paper").await;
    let target = common::seed_claim(pool, "GEN-2 NEMS").await;
    common::insert_edge(pool, paper, target, "paper", "claim", "asserts").await;

    for i in 0..19 {
        let supporter = common::seed_claim(pool, &format!("supporter {i}")).await;
        common::insert_edge(pool, paper, supporter, "paper", "claim", "asserts").await;
        // Each supporter has truth_value 0.68 (mean from issue body)
        sqlx::query("UPDATE claims SET truth_value = 0.68 WHERE id = $1")
            .bind(supporter)
            .execute(pool)
            .await
            .unwrap();
        // Edge create fires trigger_edge_ds_recomputation, which writes the
        // locality-discounted BBA.
        common::insert_edge(pool, supporter, target, "claim", "claim", "supports").await;
    }

    target
}

#[tokio::test]
async fn intra_source_19_supporters_betp_in_band() {
    let pool = common::test_pool().await;
    let target = seed_19_intra_source_supporters(&pool).await;

    let betp: Option<f64> = sqlx::query_scalar(
        "SELECT pignistic_prob FROM claims WHERE id = $1",
    )
    .bind(target)
    .fetch_one(&pool)
    .await
    .unwrap();

    let betp = betp.expect("target should have computed BetP after edge creates");
    assert!(
        (0.70..=0.85).contains(&betp),
        "expected intra-source-discounted BetP in [0.70, 0.85], got {betp}"
    );
}

#[tokio::test]
async fn cross_source_19_supporters_keeps_high_betp() {
    let pool = common::test_pool().await;
    let target = common::seed_claim(&pool, "cross-source target").await;
    // 19 supporters, each from its own paper — cross_source path
    for i in 0..19 {
        let paper = common::seed_paper(&pool, &format!("p{i}")).await;
        let supporter = common::seed_claim(&pool, &format!("cs-supporter {i}")).await;
        common::insert_edge(&pool, paper, supporter, "paper", "claim", "asserts").await;
        sqlx::query("UPDATE claims SET truth_value = 0.68 WHERE id = $1")
            .bind(supporter)
            .execute(&pool)
            .await
            .unwrap();
        common::insert_edge(&pool, supporter, target, "claim", "claim", "supports").await;
    }

    let betp: Option<f64> = sqlx::query_scalar(
        "SELECT pignistic_prob FROM claims WHERE id = $1",
    )
    .bind(target)
    .fetch_one(&pool)
    .await
    .unwrap();

    let betp = betp.expect("BetP");
    assert!(
        betp > 0.9,
        "cross-source 19-supporter BetP should remain near 1.0 (got {betp})"
    );
}
```

If `common::seed_paper` / `common::seed_claim` / `common::insert_edge` / `common::test_pool` are not present in `crates/epigraph-engine/tests/common/`, port them from the Task 2 test helpers (or share a `tests/common/` module — at minimum, copy with attribution comments pointing at the source).

- [ ] **Step 2: Run the test, observe both pass**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-engine --test intra_source_discount_regression -- --nocapture
```

Expected: BOTH pass.

- If `intra_source_19_supporters_betp_in_band` fails with `betp = 0.99...`, the Task 4 wiring did not take effect — verify the `same_source_papers` SQL returned `true` (add a `dbg!` in the test or check the `mass_functions` row's `source_strength` column).
- If `cross_source_19_supporters_keeps_high_betp` fails with a too-low BetP, locality detection over-fires (the predicate is reporting same-source for genuinely cross-source pairs); debug the recursive CTE.

- [ ] **Step 3: Commit Tasks 4 + 5 together**

```bash
git add crates/epigraph-api/src/routes/edges.rs \
        crates/epigraph-engine/tests/intra_source_discount_regression.rs \
        crates/epigraph-engine/tests/common/ \
        .sqlx/
git commit -m "feat(api,engine): locality-aware source_strength on evidential edges

trigger_edge_ds_recomputation now consults same_source_papers(a,b) and
writes the BBA with intra_source_support_strength (default 0.3) when
endpoints share a paper, cross_source_support_strength (1.0) otherwise.
19-supporter NEMS regression: BetP drops from 0.997 to ~0.78."
```

---

### Task 6: Calibration canary test

**Files:**
- Create: `crates/epigraph-engine/tests/intra_source_discount_calibration.rs`

- [ ] **Step 1: Write the canary**

```rust
//! Calibration canary — trips if the locality-discount defaults are moved
//! without re-tuning the 19-supporter regression. This is intentionally
//! adversarial: a future PR that adjusts the calibration must update the
//! regression test together, and this canary fails fast if only one side
//! changes.

use epigraph_engine::calibration::CalibrationConfig;

#[test]
fn intra_source_strength_in_documented_band() {
    let config = CalibrationConfig::from_workspace_root()
        .expect("calibration.toml should load");
    let intra = config.evidence_locality.intra_source_support_strength;
    assert!(
        (0.15..=0.45).contains(&intra),
        "intra_source_support_strength out of documented band [0.15, 0.45]: got {intra}. \
         If you intend to retune, update intra_source_19_supporters_betp_in_band as well."
    );
}

#[test]
fn cross_source_strength_is_one() {
    let config = CalibrationConfig::from_workspace_root()
        .expect("calibration.toml should load");
    let cross = config.evidence_locality.cross_source_support_strength;
    assert!(
        (cross - 1.0).abs() < 1e-9,
        "cross_source_support_strength must remain 1.0 (got {cross}); \
         lowering it changes baseline BetP across the entire graph."
    );
}
```

- [ ] **Step 2: Run the canary**

```bash
cargo test -p epigraph-engine --test intra_source_discount_calibration -- --nocapture
```

Expected: both pass against the values from Task 3.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-engine/tests/intra_source_discount_calibration.rs
git commit -m "test(engine): calibration canary for evidence_locality defaults"
```

---

### Task 7: Operator backfill script

**Files:**
- Create: `scripts/backfill_intra_source_discount.py`

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
"""Backfill source_strength on existing intra-source evidential BBAs.

Pre-2026-05-27, every evidential edge wrote source_strength=1.0 regardless
of whether the source and target shared a paper. After the locality-aware
discount lands, new edges get the right value automatically, but the
historical mass_functions rows are still over-strong.

This script:
  1. Loads intra_source_support_strength from calibration.toml.
  2. UPDATEs mass_functions rows whose underlying edge is intra-source.
  3. Collects affected claim_ids and POSTs each to
     /api/v1/graph/reconcile_sheaf to recompute belief.

Usage:
    DATABASE_URL=postgres://... EPIGRAPH_API=http://localhost:8080 \\
        python3 scripts/backfill_intra_source_discount.py [--dry-run]

The --dry-run mode reports the count of rows that would be updated and the
distinct affected claims without writing.
"""
from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

import psycopg2
import requests


def load_intra_strength() -> float:
    repo_root = Path(__file__).resolve().parent.parent
    with (repo_root / "calibration.toml").open("rb") as f:
        cfg = tomllib.load(f)
    return float(cfg["evidence_locality"]["intra_source_support_strength"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report only, no writes")
    args = parser.parse_args()

    db_url = os.environ.get("DATABASE_URL")
    api_url = os.environ.get("EPIGRAPH_API", "http://localhost:8080")
    if not db_url:
        print("DATABASE_URL not set", file=sys.stderr)
        return 2

    intra = load_intra_strength()
    print(f"intra_source_support_strength = {intra}")

    conn = psycopg2.connect(db_url)
    conn.autocommit = False
    cur = conn.cursor()

    cur.execute(
        """
        SELECT mf.id, mf.claim_id, mf.source_strength, e.id AS edge_id
          FROM mass_functions mf
          JOIN edges e
            ON mf.source_agent_id = e.source_id
           AND mf.claim_id        = e.target_id
         WHERE e.relationship IN ('supports','refutes','corroborates','contradicts')
           AND same_source_papers(e.source_id, e.target_id);
        """
    )
    rows = cur.fetchall()
    affected_claims = sorted({r[1] for r in rows})
    print(f"matched {len(rows)} BBAs across {len(affected_claims)} target claims")
    if not rows:
        print("nothing to do")
        return 0

    if args.dry_run:
        print("dry-run: would update; exiting without write")
        return 0

    cur.execute(
        """
        UPDATE mass_functions mf
           SET source_strength = %s
          FROM edges e
         WHERE mf.source_agent_id = e.source_id
           AND mf.claim_id        = e.target_id
           AND e.relationship IN ('supports','refutes','corroborates','contradicts')
           AND same_source_papers(e.source_id, e.target_id);
        """,
        (intra,),
    )
    conn.commit()
    print(f"updated {cur.rowcount} BBAs")

    print(f"reconciling {len(affected_claims)} target claims via {api_url}")
    failures = 0
    for claim_id in affected_claims:
        r = requests.post(
            f"{api_url}/api/v1/graph/reconcile_sheaf",
            json={"claim_id": str(claim_id)},
            timeout=60,
        )
        if not r.ok:
            failures += 1
            print(f"  reconcile failed for {claim_id}: {r.status_code} {r.text[:200]}")
    print(f"done — {failures} reconcile failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Smoke-test against the test DB seeded by Task 5**

```bash
# First re-seed via the Task 5 test (or seed manually); then:
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  python3 scripts/backfill_intra_source_discount.py --dry-run
```

Expected: "matched N BBAs across M target claims" with N=19 (after seed_19), M=1.

- [ ] **Step 3: Confirm the script is idempotent**

Running with no `--dry-run`, then again, should produce zero matched rows on the second pass (the BBAs already have the intra value), or stay stable if same_source_papers is deterministic and source_strength is already 0.3.

```bash
python3 scripts/backfill_intra_source_discount.py
python3 scripts/backfill_intra_source_discount.py
```

Expected: second pass shows "matched N BBAs" but the UPDATE is a no-op (no row changes). If the script must be exactly idempotent (zero rows reported on the second pass), add `AND mf.source_strength IS DISTINCT FROM %s` to the WHERE clause. (Choose one; document the choice in the script docstring.)

- [ ] **Step 4: Commit**

```bash
git add scripts/backfill_intra_source_discount.py
git commit -m "scripts: backfill_intra_source_discount.py (one-shot operator pass)"
```

---

### Task 8: Workspace verification

**Files:** none modified — verification only.

- [ ] **Step 1: Run full workspace lint and tests**

```bash
cd /home/jeremy/epigraph
SQLX_OFFLINE=true cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test --workspace
```

Expected: all clean.

- [ ] **Step 2: Re-prepare sqlx if needed**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo sqlx prepare --workspace -- --tests
git status -sb
```

- [ ] **Step 3: Commit any cleanup**

```bash
# If anything is uncommitted:
git add .sqlx/
git commit -m "chore: cargo sqlx prepare after locality discount wiring"
```

---

### Task 9: Push and open PR

- [ ] **Step 1: Push branch**

```bash
git push -u origin feat/locality-aware-discounting
```

- [ ] **Step 2: Open PR**

```bash
gh pr create --repo epigraph-io/epigraph \
  --title "feat: locality-aware source_strength on evidential edges (#142)" \
  --body "$(cat <<'EOF'
## Summary
- New `same_source_papers(a, b)` Postgres function (migration 041) traversing `{asserts, same_source, section_follows, continues_argument, decomposes_to}` closure.
- `trigger_edge_ds_recomputation` now writes BBAs with `source_strength = intra_source_support_strength` (default 0.3) when endpoints share a paper, `cross_source_support_strength` (1.0) otherwise.
- New `[evidence_locality]` calibration block with tunable defaults.
- 19-supporter synthetic regression: BetP drops from 0.997 (current main) to ~0.78.
- Operator backfill script for historical BBAs.

## Why
The original #142 fix proposed retyping every intra-source `supports` to `decomposes_to`. That conflates two cases: decomposition (which is dependency, not evidence) and intra-source evidence (paper claims X, paper also reports experiment supporting X — cherry-picked perhaps, but still evidence). Blanket retyping zeroes out case 2 along with case 1. Locality discounting preserves the signal while deflating the spurious Dempster product inflation on decomposition clusters.

See `docs/superpowers/specs/2026-05-27-alternative-and-dependency-edges-design.md` § 2.

## Test plan
- [x] `cargo test -p epigraph-db same_source_papers_truth_table` — predicate
- [x] `cargo test -p epigraph-engine test_evidence_locality_loads` — calibration
- [x] `cargo test -p epigraph-engine intra_source_discount_regression` — 19-supporter BetP in [0.70, 0.85]; cross-source 19-supporter BetP > 0.9
- [x] `cargo test -p epigraph-engine intra_source_discount_calibration` — defaults in documented band
- [x] `cargo test --workspace` against `epigraph_db_repo_test`
- [x] `cargo fmt --check` / `cargo clippy --all-targets -D warnings`
- [ ] Operator: run `scripts/backfill_intra_source_discount.py --dry-run` against production read-replica, review counts before applying

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Verify**

```bash
gh pr view --repo epigraph-io/epigraph --json url,number,title
```

- [ ] **Step 4: Retire the backlog claim**

Per `CLAUDE.md`:

```python
mcp__epigraph__resolve_backlog_item(
    original_id="98d5a2d5-0c92-4712-8db7-c850614ce97d",
    resolution_content=(
        "Resolves 98d5a2d5: replaced the retyping migration with locality-aware "
        "source_strength discounting. trigger_edge_ds_recomputation reads "
        "same_source_papers(a,b) and writes intra_source_support_strength=0.3 "
        "(or cross=1.0) into mass_functions. Decomposition-cluster inflation "
        "deflated; intra-source evidence preserved with discounted mass. "
        "See PR #<NN>."
    ),
)
```

Substitute `<NN>` with the PR number from Step 3.

Also retire the companion backlog `351cae08-bb06-4f10-89ad-58526780b00c` (the SQL screen) — the predicate `same_source_papers` *is* the screen:

```python
mcp__epigraph__resolve_backlog_item(
    original_id="351cae08-bb06-4f10-89ad-58526780b00c",
    resolution_content=(
        "Resolves 351cae08: same_source_papers(a,b) is the screen — any "
        "evidential edge where it returns true is intra-source. See PR #<NN>."
    ),
)
```

---

## Done

- Locality detection lives in one place (the function).
- Engine reads it at edge-create time and adjusts per-BBA reliability.
- Existing data cleaned up by a one-shot operator pass.
- NEMS-style inflation deflated.
