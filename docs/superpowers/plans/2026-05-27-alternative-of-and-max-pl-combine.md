# `alternative_of` Edge + Max-Pl Combine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit `alternative_of` edge type for mutually-exclusive supporters of a shared target. Teach CDST BP to combine alt-set members via max-Bel / max-Pl ("least restrictive alternative") before Dempster-combining with non-alt supporters. Expose an MCP candidate-finder tool that surfaces likely alt pairs as operator suggestions (no auto-creation). Closes #140 and #141.

**Architecture:** Three layers. **Schema:** new migration adds a partial unique index canonicalizing endpoint order, plus an `alternative_set` view exposing the equivalence class under transitive closure. **Engine:** `combine_alternative_set(bbas, target)` lives in `epigraph-ds`; CDST groups a target's incoming supporters by alt-set membership, reduces each group with the new combine, then Dempster-combines the per-group BBAs as today. **Suggestion tool:** an MCP tool returning candidate (claim_a, claim_b, score, reason) pairs from existing graph state.

**Tech Stack:** Postgres (recursive CTE view, partial unique index), Rust, sqlx, `epigraph-ds`, `epigraph-engine` CDST BP, `epigraph-mcp`, `epigraph-api`.

---

## Setup

**Branch.** Branch from `origin/main`:

```bash
cd /home/jeremy/epigraph
git fetch origin main
git checkout -b feat/alternative-of-and-max-pl origin/main
```

This plan is independent of the locality-aware-discounting plan; they touch disjoint surfaces and can land in either order.

**Test database.** `epigraph_db_repo_test`.

**Migration slot.** `main` ends at `040_workflows_goal_embedding.sql`. This plan uses `042` to leave room for the locality plan's `041`. If both plans land out of order, the executor adjusts the slot via `chore: renumber` per the pattern established in PRs #177/#178.

**Spec reference.** `docs/superpowers/specs/2026-05-27-alternative-and-dependency-edges-design.md` § 1, 3, 4, 5.

---

### Task 1: Add `alternative_of` to the relationship allow-list

**Files:**
- Modify: `crates/epigraph-api/src/routes/edges.rs:65-119` (`VALID_RELATIONSHIPS` array)
- Modify: `crates/epigraph-api/src/routes/edges.rs:2554-2572` (`is_valid_relationship` test)

- [ ] **Step 1: Add the constant**

In `crates/epigraph-api/src/routes/edges.rs`, insert into `VALID_RELATIONSHIPS` (alphabetical-ish, next to `"asserts"`, `"same_source"` etc.):

```rust
    "alternative_of",        // claim ↔ claim (symmetric — mutually-exclusive supporters of a shared target)
```

- [ ] **Step 2: Extend the test**

In `crates/epigraph-api/src/routes/edges.rs`, in the existing `is_valid_relationship` test:

```rust
        assert!(is_valid_relationship("alternative_of"));
```

- [ ] **Step 3: Run the test**

```bash
cd /home/jeremy/epigraph
cargo test -p epigraph-api routes::edges_validation -- --nocapture
# or whatever the existing test module path is — falls back to:
cargo test -p epigraph-api is_valid_relationship -- --nocapture
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-api/src/routes/edges.rs
git commit -m "feat(api): admit alternative_of relationship in VALID_RELATIONSHIPS"
```

---

### Task 2: Migration — symmetric unique index + `alternative_set` view

**Files:**
- Create: `migrations/042_alternative_of_edge_type.sql`

- [ ] **Step 1: Write the migration**

```sql
-- 042_alternative_of_edge_type.sql
--
-- Symmetric uniqueness for alternative_of edges (the application-level
-- allow-list in routes/edges.rs admits the relationship; here we enforce
-- the symmetry contract at the schema level).
--
-- Plus a view materializing the transitive-closure equivalence class. CDST
-- BP reads this view to group supporters of a target into alternative
-- sets before max-Pl combining (see crates/epigraph-engine/src/cdst_bp.rs).

CREATE UNIQUE INDEX IF NOT EXISTS edges_alternative_of_symmetric_uniq
  ON edges (LEAST(source_id, target_id), GREATEST(source_id, target_id))
  WHERE relationship = 'alternative_of';

CREATE OR REPLACE VIEW alternative_set AS
WITH RECURSIVE pairs AS (
  SELECT source_id AS a, target_id AS b
    FROM edges WHERE relationship = 'alternative_of'
  UNION
  SELECT target_id, source_id
    FROM edges WHERE relationship = 'alternative_of'
), closure AS (
  SELECT a, b FROM pairs
  UNION
  SELECT c.a, p.b FROM closure c JOIN pairs p ON c.b = p.a
)
SELECT a AS claim_id,
       array_agg(DISTINCT b ORDER BY b) AS alt_members
  FROM closure
 GROUP BY a;

COMMENT ON VIEW alternative_set IS
'Equivalence class under the symmetric closure of alternative_of. Each row '
'maps a claim_id to the sorted list of claims it is mutually-exclusive with '
'(itself excluded). Drives max-Pl combine in CDST BP.';
```

- [ ] **Step 2: Apply and confirm**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  sqlx migrate run
psql "$DATABASE_URL" -c "\\d+ alternative_set"
psql "$DATABASE_URL" -c "\\d edges" | grep edges_alternative_of_symmetric_uniq
```

Expected: view exists with `claim_id, alt_members` columns; index appears in the table-indexes list.

- [ ] **Step 3: Commit**

```bash
git add migrations/042_alternative_of_edge_type.sql
git commit -m "feat(db): symmetric uniqueness + alternative_set view for alternative_of"
```

---

### Task 3: Symmetric dedup + view tests

**Files:**
- Create: `crates/epigraph-api/tests/alternative_of_symmetric_dedup.rs`
- Create: `crates/epigraph-api/tests/alternative_set_view_closure.rs`

- [ ] **Step 1: Write the dedup test**

```rust
//! Inserting alternative_of(A,B) and alternative_of(B,A) must produce
//! exactly one edge row (the second insertion is a dedup hit on the
//! symmetric uniqueness index from migration 042).

mod common;

use uuid::Uuid;

#[tokio::test]
async fn alternative_of_dedupes_under_endpoint_swap() {
    let pool = common::test_pool().await;
    let a = common::seed_claim(&pool, "A").await;
    let b = common::seed_claim(&pool, "B").await;

    let id1 = common::insert_edge(&pool, a, b, "claim", "claim", "alternative_of").await;
    // Reversed direction — should be rejected by the unique index, not
    // silently double-recorded.
    let res = sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         VALUES ($1, $2, 'claim', 'claim', 'alternative_of')",
    )
    .bind(b)
    .bind(a)
    .execute(&pool)
    .await;
    assert!(
        res.is_err(),
        "reversed alternative_of insert must hit unique index, got: {res:?}"
    );

    let cnt: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'alternative_of' \
         AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cnt.0, 1, "exactly one row, got {}", cnt.0);
    let _ = id1; // suppresses unused warning
}
```

- [ ] **Step 2: Write the view closure test**

```rust
//! 3-cycle (A↔B, B↔C) under alternative_of must collapse into one
//! equivalence class — every member's alt_members lists the other two.

mod common;

#[tokio::test]
async fn alternative_set_view_transitive_closure() {
    let pool = common::test_pool().await;
    let a = common::seed_claim(&pool, "A").await;
    let b = common::seed_claim(&pool, "B").await;
    let c = common::seed_claim(&pool, "C").await;

    common::insert_edge(&pool, a, b, "claim", "claim", "alternative_of").await;
    common::insert_edge(&pool, b, c, "claim", "claim", "alternative_of").await;

    let row_a: (Vec<uuid::Uuid>,) = sqlx::query_as(
        "SELECT alt_members FROM alternative_set WHERE claim_id = $1",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row_a.0.contains(&b), "A's alt_members must include B");
    assert!(row_a.0.contains(&c), "A's alt_members must include C (transitive)");

    let row_c: (Vec<uuid::Uuid>,) = sqlx::query_as(
        "SELECT alt_members FROM alternative_set WHERE claim_id = $1",
    )
    .bind(c)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row_c.0.contains(&a), "C's alt_members must include A (transitive)");
    assert!(row_c.0.contains(&b), "C's alt_members must include B");
}
```

If `crates/epigraph-api/tests/common/` lacks `seed_claim` / `insert_edge` / `test_pool`, port from existing tests (e.g., `crates/epigraph-api/tests/graph_neighborhoods_test.rs` has comparable fixtures).

- [ ] **Step 3: Run both tests**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-api \
    --test alternative_of_symmetric_dedup \
    --test alternative_set_view_closure \
  -- --nocapture
```

Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-api/tests/alternative_of_symmetric_dedup.rs \
        crates/epigraph-api/tests/alternative_set_view_closure.rs \
        crates/epigraph-api/tests/common/
git commit -m "test(api): alternative_of symmetric dedup + view transitive closure"
```

---

### Task 4: `combine_alternative_set` in `epigraph-ds`

**Files:**
- Modify: `crates/epigraph-ds/src/combination.rs` (append function + tests)
- Modify: `crates/epigraph-ds/src/lib.rs` (re-export if needed)

- [ ] **Step 1: Write the unit tests first (TDD)**

Append to `crates/epigraph-ds/src/combination.rs` test module (or create the test block if it does not exist):

```rust
#[cfg(test)]
mod combine_alternative_set_tests {
    use super::combine_alternative_set;
    use crate::{measures::{belief, plausibility}, FocalElement, FrameOfDiscernment, MassFunction};
    use std::collections::BTreeSet;

    fn binary() -> FrameOfDiscernment {
        FrameOfDiscernment::new("alt-set-test", vec!["supported".into(), "unsupported".into()])
            .unwrap()
    }

    fn target() -> FocalElement {
        FocalElement::positive(BTreeSet::from([0])) // {supported}
    }

    #[test]
    fn singleton_returns_input_unchanged() {
        let frame = binary();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();
        let combined = combine_alternative_set(std::slice::from_ref(&m), &target()).unwrap();
        assert!((belief(&combined, &target()) - 0.6).abs() < 1e-9);
        assert!((plausibility(&combined, &target()) - 1.0).abs() < 1e-9); // simple gives m(Θ) = 0.4
    }

    #[test]
    fn two_member_set_picks_max_bel_and_max_pl() {
        let frame = binary();
        // Member A: BBA pushing strongly toward {supported}: Bel=0.7, Pl=1.0 (ignorance 0.3 on Θ)
        let a = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        // Member B: BBA pushing weakly toward {supported}: Bel=0.3, Pl=1.0
        let b = MassFunction::simple(frame, BTreeSet::from([0]), 0.3).unwrap();
        let combined = combine_alternative_set(&[a, b], &target()).unwrap();
        let bel = belief(&combined, &target());
        let pl = plausibility(&combined, &target());
        assert!(
            (bel - 0.7).abs() < 1e-9,
            "max_Bel should equal max(0.7, 0.3) = 0.7, got {bel}"
        );
        assert!(
            (pl - 1.0).abs() < 1e-9,
            "max_Pl should equal max(1.0, 1.0) = 1.0, got {pl}"
        );
    }

    #[test]
    fn mixed_alt_vs_independent_differs_from_dempster() {
        use crate::combination::combine_multiple;
        let frame = binary();
        // Alt members A1, A2 — same shape as previous test
        let a1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let a2 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.3).unwrap();
        // Independent A3
        let a3 = MassFunction::simple(frame, BTreeSet::from([0]), 0.5).unwrap();

        let alt_combined = combine_alternative_set(&[a1.clone(), a2.clone()], &target()).unwrap();
        let (mixed, _) = combine_multiple(&[alt_combined, a3.clone()], 0.1).unwrap();
        let (pure_dempster, _) = combine_multiple(&[a1, a2, a3], 0.1).unwrap();

        let mixed_bel = belief(&mixed, &target());
        let pure_bel = belief(&pure_dempster, &target());
        assert!(
            (mixed_bel - pure_bel).abs() > 1e-3,
            "max-Pl ⊕ Dempster must differ from pure-Dempster: mixed={mixed_bel}, pure={pure_bel}"
        );
        // Sanity: max-Pl path should not over-combine, so mixed_bel < pure_bel
        assert!(
            mixed_bel < pure_bel,
            "max-Pl reduction should yield lower combined Bel than pure Dempster"
        );
    }
}
```

- [ ] **Step 2: Run them — expect failure with "function not defined"**

```bash
cd /home/jeremy/epigraph
cargo test -p epigraph-ds combine_alternative_set_tests -- --nocapture
```

Expected: `error[E0425]: cannot find function combine_alternative_set`.

- [ ] **Step 3: Implement the function**

Append to `crates/epigraph-ds/src/combination.rs` (above the `#[cfg(test)]` blocks):

```rust
/// Reduce a set of mutually-exclusive supporter BBAs to a single representative
/// BBA via max-Bel / max-Pl on the projected belief interval toward `target`.
///
/// Used by CDST BP for alternative-set members: independence has failed (these
/// claims compete to support the same target), so the product rule
/// (`combine_multiple`) over-combines. Max-Pl is the "least restrictive
/// alternative" rule from regulatory/legal reasoning: the combined belief is
/// bounded by the most permissive single alternative.
///
/// Members are passed *post-discount* — the caller applies any per-BBA
/// `source_strength` reliability discount via [`discount`] before invoking
/// this function.
///
/// Returns the singleton input unchanged.
///
/// # Errors
/// Returns [`DsError::IncompatibleFrames`] if BBAs span different frames.
pub fn combine_alternative_set(
    bbas: &[MassFunction],
    target: &FocalElement,
) -> Result<MassFunction, DsError> {
    if bbas.is_empty() {
        return Err(DsError::EmptyInput);
    }
    if bbas.len() == 1 {
        return Ok(bbas[0].clone());
    }
    let frame = bbas[0].frame().clone();
    for m in &bbas[1..] {
        if m.frame() != &frame {
            return Err(DsError::IncompatibleFrames);
        }
    }

    let max_bel = bbas
        .iter()
        .map(|m| crate::measures::belief(m, target))
        .fold(0.0_f64, f64::max);
    let max_pl = bbas
        .iter()
        .map(|m| crate::measures::plausibility(m, target))
        .fold(0.0_f64, f64::max);
    let max_bel = max_bel.clamp(0.0, 1.0);
    let max_pl = max_pl.clamp(max_bel, 1.0); // Pl >= Bel by definition

    // Construct: m({target}) = max_bel, m(Θ) = max_pl - max_bel,
    //            m(complement(target)) = 1 - max_pl
    use std::collections::BTreeMap;
    let mut masses: BTreeMap<FocalElement, f64> = BTreeMap::new();
    if max_bel > 0.0 {
        masses.insert(target.clone(), max_bel);
    }
    let ignorance = max_pl - max_bel;
    if ignorance > 1e-12 {
        // Θ = full frame
        let theta: std::collections::BTreeSet<usize> = (0..frame.cardinality()).collect();
        masses.insert(FocalElement::positive(theta), ignorance);
    }
    let neg_mass = 1.0 - max_pl;
    if neg_mass > 1e-12 {
        // complement of target within the frame
        let comp: std::collections::BTreeSet<usize> = (0..frame.cardinality())
            .filter(|i| !target.subset.contains(i))
            .collect();
        if !comp.is_empty() {
            masses.insert(FocalElement::positive(comp), neg_mass);
        }
    }

    MassFunction::from_masses(frame, masses).map_err(|_| DsError::MassNormalizationFailed)
}
```

If any of `DsError::EmptyInput`, `DsError::IncompatibleFrames`, `DsError::MassNormalizationFailed`, or `MassFunction::from_masses` do not exist with those exact names, look up the actual names with:

```bash
grep -n "pub enum DsError\|pub fn from_masses\|pub fn frame\|pub fn cardinality" \
     crates/epigraph-ds/src/{errors,mass,frame}.rs
```

and substitute the actual symbols. (The shape of the construction does not change — only the names.)

- [ ] **Step 4: Run the tests, expect PASS**

```bash
cargo test -p epigraph-ds combine_alternative_set_tests -- --nocapture
```

Expected: 3 passed.

- [ ] **Step 5: Re-export from the crate**

In `crates/epigraph-ds/src/lib.rs`, ensure `combination::combine_alternative_set` is reachable from the crate's top-level — if other combine functions are re-exported there, add this one too.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-ds/src/combination.rs crates/epigraph-ds/src/lib.rs
git commit -m "feat(ds): combine_alternative_set (max-Bel/max-Pl reduction)"
```

---

### Task 5: CDST BP integration — group supporters by alt-set before combining

**Files:**
- Modify: `crates/epigraph-engine/src/cdst_bp.rs`
- (Possibly) Modify: `crates/epigraph-api/src/routes/computation.rs` where the BP factors are loaded — only if the alt-set membership has to be threaded through the factor representation.

- [ ] **Step 1: Find the supporter-grouping site**

```bash
grep -n "fn run_cdst_bp\|combine_multiple\|combine_evidences\|fn compute_cdst_factor_message" \
     crates/epigraph-engine/src/cdst_bp.rs
```

The combine of incoming supporter BBAs happens inside `run_cdst_bp` (or `compute_cdst_factor_message`). The change is: before the existing `combine_multiple` over supporters of target T, partition the supporter BBAs into alt-set groups using the `alternative_set` view, reduce each multi-member group with `combine_alternative_set(group, target)`, then `combine_multiple` over the per-group BBAs.

- [ ] **Step 2: Plumb alt-set membership into the engine call site**

The engine is pure (no DB access). The route handler that calls into `run_cdst_bp` (`crates/epigraph-api/src/routes/computation.rs`) must load the alt-set view *once* per request and pass it down. Define a new type in `crates/epigraph-engine/src/cdst_bp.rs`:

```rust
/// Per-claim alternative-set membership loaded from the `alternative_set` view.
///
/// Map keys are claim IDs; values are the sorted equivalence-class members
/// (excluding the key itself). Engine consumers route a target T's incoming
/// supporters through `combine_alternative_set` when two or more supporters
/// share a class.
pub type AltSetMembership = std::collections::HashMap<uuid::Uuid, Vec<uuid::Uuid>>;
```

Extend `run_cdst_bp`'s signature (or `CdstBpConfig`) to accept `&AltSetMembership` — preferring the config struct so external callers don't break:

```rust
pub struct CdstBpConfig {
    // ... existing fields ...
    pub alt_set_membership: AltSetMembership,
}
```

with a `Default` that returns an empty map (engine behavior unchanged on empty config — no alt-set grouping, identical to today).

- [ ] **Step 3: Apply the grouping in the combine path**

In `run_cdst_bp` (or wherever incoming supporter BBAs are combined for a target T), replace the current straight-line `combine_multiple(&supporter_bbas, ...)` with:

```rust
use std::collections::HashMap;
use epigraph_ds::FocalElement;

// Canonical-class id per claim: the minimum claim_id in the equivalence class
// (used as the group key). Singletons map to themselves.
let canonical_class = |claim_id: &uuid::Uuid| -> uuid::Uuid {
    match config.alt_set_membership.get(claim_id) {
        Some(members) => *std::iter::once(claim_id).chain(members.iter()).min().unwrap(),
        None => *claim_id,
    }
};

// Group (supporter_claim_id, bba) pairs by canonical class.
let mut groups: HashMap<uuid::Uuid, Vec<MassFunction>> = HashMap::new();
for (supporter_id, bba) in &supporter_bbas_with_ids {
    groups.entry(canonical_class(supporter_id)).or_default().push(bba.clone());
}

// Reduce alt-set groups; singletons pass through.
let target_focal = FocalElement::positive(std::collections::BTreeSet::from([H_SUPPORTED]));
let per_group_bbas: Vec<MassFunction> = groups
    .into_values()
    .map(|grp| {
        if grp.len() == 1 {
            grp.into_iter().next().unwrap()
        } else {
            epigraph_ds::combination::combine_alternative_set(&grp, &target_focal)
                .unwrap_or_else(|_| vacuous())
        }
    })
    .collect();

let (combined, _) = epigraph_ds::combination::combine_multiple(&per_group_bbas, 0.1)?;
```

If `run_cdst_bp` currently loses the per-supporter `claim_id` before combine (i.e., it collects raw BBAs without tracking which claim each came from), extend the upstream collection to keep `(supporter_id, bba)` pairs. This may require touching the factor-message machinery; preserve the call site's existing variable names and add an `_ids: &[uuid::Uuid]` parameter alongside the existing BBA slice rather than introducing a new tuple type.

- [ ] **Step 4: Load and pass the alt-set view from the route**

In `crates/epigraph-api/src/routes/computation.rs`, where the CDST branch builds `cdst_config` (around `:597`), load the membership map before the engine call:

```rust
let alt_set_rows: Vec<(Uuid, Vec<Uuid>)> = sqlx::query_as(
    "SELECT claim_id, alt_members FROM alternative_set",
)
.fetch_all(&state.db_pool)
.await
.unwrap_or_default();

let mut alt_set_membership: epigraph_engine::cdst_bp::AltSetMembership = HashMap::new();
for (claim_id, members) in alt_set_rows {
    alt_set_membership.insert(claim_id, members);
}

let cdst_config = epigraph_engine::cdst_bp::CdstBpConfig {
    max_iterations: config.max_iterations,
    convergence_threshold: config.convergence_threshold,
    damping: config.damping,
    alt_set_membership,
    ..epigraph_engine::cdst_bp::CdstBpConfig::default()
};
```

`unwrap_or_default()` is intentional: the alt-set view returns zero rows on a fresh graph, and BP should not fail if the view is empty.

- [ ] **Step 5: Compile, fix any signature drift**

```bash
SQLX_OFFLINE=true cargo check --workspace
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo sqlx prepare --workspace -- --tests
```

- [ ] **Step 6: Do NOT commit yet — Task 6 covers the regression test that proves the integration works**

---

### Task 6: CDST integration regression test

**Files:**
- Create: `crates/epigraph-engine/tests/alt_set_cdst_integration.rs`

- [ ] **Step 1: Write the test**

```rust
//! Alt set {A1, A2} + independent A3 all supporting T.
//! Combined T BetP must equal `dempster(maxPl({A1,A2}), A3)`, not
//! `dempster(A1, A2, A3)`. This proves the alt-set grouping is being
//! applied rather than silently dropping back to Dempster.

mod common;

use uuid::Uuid;

#[tokio::test]
async fn alt_set_combine_differs_from_pure_dempster() {
    let pool = common::test_pool().await;
    let t  = common::seed_claim(&pool, "Target").await;
    let a1 = common::seed_claim_with_truth(&pool, "A1", 0.7).await;
    let a2 = common::seed_claim_with_truth(&pool, "A2", 0.3).await;
    let a3 = common::seed_claim_with_truth(&pool, "A3", 0.5).await;

    // a1, a2, a3 each support T
    common::insert_edge(&pool, a1, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a2, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a3, t, "claim", "claim", "supports").await;

    // Record BetP without alt_set wired (control: insert nothing into alternative_of)
    let betp_no_alt: f64 = sqlx::query_scalar(
        "SELECT pignistic_prob FROM claims WHERE id = $1"
    ).bind(t).fetch_one(&pool).await.unwrap().unwrap();

    // Now mark A1, A2 as alternative_of
    common::insert_edge(&pool, a1, a2, "claim", "claim", "alternative_of").await;

    // Trigger BP recompute (POST /api/v1/graph/recompute_beliefs apply=true)
    common::run_cdst_recompute(&pool).await;

    let betp_with_alt: f64 = sqlx::query_scalar(
        "SELECT pignistic_prob FROM claims WHERE id = $1"
    ).bind(t).fetch_one(&pool).await.unwrap().unwrap();

    assert!(
        (betp_with_alt - betp_no_alt).abs() > 1e-3,
        "alt_set grouping must shift BetP — without={betp_no_alt}, with={betp_with_alt}"
    );
    assert!(
        betp_with_alt < betp_no_alt,
        "alt_set max-Pl reduction should lower combined BetP relative to pure Dempster"
    );
}
```

`common::seed_claim_with_truth` writes the truth_value at insert. `common::run_cdst_recompute` POSTs to the API recompute endpoint (or directly invokes `run_cdst_bp`); use whichever is cleaner against the existing engine test fixtures.

- [ ] **Step 2: Run the test, expect PASS against the Task 5 integration**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-engine --test alt_set_cdst_integration -- --nocapture
```

Expected: PASS. Both assertions hold (the alt-set BetP is lower than the no-alt-set BetP).

- [ ] **Step 3: Commit Tasks 5 + 6 together**

```bash
git add crates/epigraph-engine/src/cdst_bp.rs \
        crates/epigraph-engine/tests/alt_set_cdst_integration.rs \
        crates/epigraph-engine/tests/common/ \
        crates/epigraph-api/src/routes/computation.rs \
        .sqlx/
git commit -m "feat(engine): CDST groups supporters by alt-set before Dempster combine"
```

---

### Task 7: Candidate-finder MCP tool

**Files:**
- Create: `crates/epigraph-mcp/src/tools/alternative_sets.rs`
- Modify: `crates/epigraph-mcp/src/server.rs` (register the tool)
- Modify: `crates/epigraph-mcp/src/scope_map.rs` (add entry under `claims:read`)
- Create: `crates/epigraph-mcp/tests/suggest_alternative_sets.rs`

- [ ] **Step 1: Write the tool implementation**

Create `crates/epigraph-mcp/src/tools/alternative_sets.rs`:

```rust
//! mcp__epigraph__suggest_alternative_sets — surface candidate alternative_of
//! pairs by finding contradicts edges between supporters of a shared target.
//!
//! Pure suggestion: the operator promotes by submitting an explicit
//! `alternative_of` edge. Auto-promotion would risk false positives (two
//! claims that contradict each other on a different axis may both be valid
//! independent supporters of T).

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::EpiGraphMcpFull;
use crate::utils::{internal_error, parse_uuid, success_json};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SuggestAlternativeSetsParams {
    /// Restrict suggestions to candidate pairs that both support this target.
    /// Omit to scan the whole graph.
    pub target_claim_id: Option<String>,

    /// Minimum `min(BetP_a, BetP_b)` to surface a candidate. Default 0.5.
    #[serde(default = "default_min_strength")]
    pub min_pair_strength: f64,
}

fn default_min_strength() -> f64 {
    0.5
}

#[derive(Debug, Serialize)]
pub struct SuggestedAlternativePair {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub target_claim: Uuid,
    pub score: f64,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct SuggestAlternativeSetsResponse {
    pub candidates: Vec<SuggestedAlternativePair>,
}

pub async fn suggest_alternative_sets(
    server: &EpiGraphMcpFull,
    params: SuggestAlternativeSetsParams,
) -> Result<CallToolResult, McpError> {
    let target_filter = match params.target_claim_id.as_deref() {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };
    let min_strength = params.min_pair_strength.clamp(0.0, 1.0);

    let candidates = scan_candidates(&server.pool, target_filter, min_strength)
        .await
        .map_err(internal_error)?;

    success_json(&SuggestAlternativeSetsResponse { candidates })
}

async fn scan_candidates(
    pool: &PgPool,
    target_filter: Option<Uuid>,
    min_strength: f64,
) -> Result<Vec<SuggestedAlternativePair>, sqlx::Error> {
    // Pair (A, B) such that:
    //   - both A and B `supports` the same target T
    //   - there exists a `contradicts` edge between A and B (either direction)
    //   - no explicit alternative_of edge between A and B already exists
    //   - min(pignistic_prob_A, pignistic_prob_B) >= min_strength
    let rows: Vec<(Uuid, Uuid, Uuid, f64)> = sqlx::query_as(
        r#"
        SELECT
            LEAST(s1.source_id, s2.source_id)  AS claim_a,
            GREATEST(s1.source_id, s2.source_id) AS claim_b,
            s1.target_id                        AS target_claim,
            LEAST(
                COALESCE(ca.pignistic_prob, 0.0),
                COALESCE(cb.pignistic_prob, 0.0)
            ) AS score
        FROM edges s1
        JOIN edges s2
          ON s2.target_id = s1.target_id
         AND s2.relationship = 'supports'
         AND s2.source_id <> s1.source_id
        JOIN edges contr
          ON ((contr.source_id = s1.source_id AND contr.target_id = s2.source_id)
           OR (contr.source_id = s2.source_id AND contr.target_id = s1.source_id))
         AND contr.relationship = 'contradicts'
        JOIN claims ca ON ca.id = s1.source_id
        JOIN claims cb ON cb.id = s2.source_id
        LEFT JOIN edges existing
          ON existing.relationship = 'alternative_of'
         AND ((existing.source_id = s1.source_id AND existing.target_id = s2.source_id)
           OR (existing.source_id = s2.source_id AND existing.target_id = s1.source_id))
        WHERE s1.relationship = 'supports'
          AND s1.source_id < s2.source_id  -- de-dupe the symmetric self-join
          AND ($1::uuid IS NULL OR s1.target_id = $1)
          AND existing.id IS NULL
          AND LEAST(
                COALESCE(ca.pignistic_prob, 0.0),
                COALESCE(cb.pignistic_prob, 0.0)
              ) >= $2
        ORDER BY score DESC
        LIMIT 200
        "#,
    )
    .bind(target_filter)
    .bind(min_strength)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(a, b, t, score)| SuggestedAlternativePair {
            claim_a: a,
            claim_b: b,
            target_claim: t,
            score,
            reason: format!("contradicts edge between supporters of {t}"),
        })
        .collect())
}
```

(If `crate::types::EpiGraphMcpFull` / `crate::utils::*` / `success_json` use different names in your tree, mirror the imports from a sibling tool — e.g., `crates/epigraph-mcp/src/tools/claims.rs`.)

- [ ] **Step 2: Register the tool in `server.rs`**

In `crates/epigraph-mcp/src/server.rs`, register `suggest_alternative_sets` following the existing pattern (`update_with_evidence` at `:233` is a good reference). The body wires `params` into `tools::alternative_sets::suggest_alternative_sets(self, params).await`.

- [ ] **Step 3: Add the scope-map entry**

In `crates/epigraph-mcp/src/scope_map.rs`, add (under `claims:read`, alphabetically near the existing entries at `:25-39`):

```rust
    ("suggest_alternative_sets", "claims:read"),
```

- [ ] **Step 4: Write the integration test**

```rust
//! Three supporters of T; two of them are linked by contradicts. Tool
//! returns exactly that one pair, scored. The third supporter does not
//! appear in any candidate.

mod common;

use uuid::Uuid;

#[tokio::test]
async fn suggest_returns_only_contradicts_pair() {
    let server = common::TestServer::start().await;
    let t  = common::seed_claim(&server.pool, "Target").await;
    let a1 = common::seed_claim_with_truth(&server.pool, "A1", 0.7).await;
    let a2 = common::seed_claim_with_truth(&server.pool, "A2", 0.6).await;
    let a3 = common::seed_claim_with_truth(&server.pool, "A3", 0.5).await;

    common::insert_edge(&server.pool, a1, t, "claim", "claim", "supports").await;
    common::insert_edge(&server.pool, a2, t, "claim", "claim", "supports").await;
    common::insert_edge(&server.pool, a3, t, "claim", "claim", "supports").await;
    common::insert_edge(&server.pool, a1, a2, "claim", "claim", "contradicts").await;
    // BP recompute so pignistic_prob is populated
    common::run_cdst_recompute(&server.pool).await;

    let resp = server
        .suggest_alternative_sets(
            epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
                target_claim_id: Some(t.to_string()),
                min_pair_strength: 0.0,
            },
        )
        .await
        .expect("tool call ok");

    let payload = common::unwrap_call_result(&resp);
    let candidates = payload["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1, "expected 1 candidate, got {:?}", candidates);

    let cand = &candidates[0];
    let ids: std::collections::BTreeSet<Uuid> = [
        Uuid::parse_str(cand["claim_a"].as_str().unwrap()).unwrap(),
        Uuid::parse_str(cand["claim_b"].as_str().unwrap()).unwrap(),
    ]
    .into_iter()
    .collect();
    assert_eq!(ids, std::collections::BTreeSet::from([a1, a2]));
    assert!(!ids.contains(&a3), "A3 must not appear (no contradicts edge)");
}

#[tokio::test]
async fn suggest_skips_pairs_with_existing_alternative_of() {
    let server = common::TestServer::start().await;
    let t  = common::seed_claim(&server.pool, "Target").await;
    let a1 = common::seed_claim_with_truth(&server.pool, "A1", 0.7).await;
    let a2 = common::seed_claim_with_truth(&server.pool, "A2", 0.6).await;
    common::insert_edge(&server.pool, a1, t, "claim", "claim", "supports").await;
    common::insert_edge(&server.pool, a2, t, "claim", "claim", "supports").await;
    common::insert_edge(&server.pool, a1, a2, "claim", "claim", "contradicts").await;
    common::insert_edge(&server.pool, a1, a2, "claim", "claim", "alternative_of").await;

    let resp = server
        .suggest_alternative_sets(
            epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
                target_claim_id: Some(t.to_string()),
                min_pair_strength: 0.0,
            },
        )
        .await
        .expect("tool call ok");

    let payload = common::unwrap_call_result(&resp);
    let candidates = payload["candidates"].as_array().unwrap();
    assert!(
        candidates.is_empty(),
        "alternative_of pair must not be re-suggested, got {candidates:?}"
    );
}
```

- [ ] **Step 5: Run the tool tests**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-mcp --test suggest_alternative_sets -- --nocapture
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-mcp/src/tools/alternative_sets.rs \
        crates/epigraph-mcp/src/server.rs \
        crates/epigraph-mcp/src/scope_map.rs \
        crates/epigraph-mcp/tests/suggest_alternative_sets.rs \
        crates/epigraph-mcp/tests/common/
git commit -m "feat(mcp): suggest_alternative_sets candidate-finder tool"
```

---

### Task 8: Workspace verification

**Files:** none modified — verification only.

- [ ] **Step 1: Full workspace lint + tests**

```bash
SQLX_OFFLINE=true cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test --workspace
```

Expected: clean across all four.

- [ ] **Step 2: Commit any cleanup**

```bash
git status -sb
# If anything needs committing:
git add .sqlx/
git commit -m "chore: cargo sqlx prepare after alternative_of + max-pl work"
```

---

### Task 9: Push and open PR

- [ ] **Step 1: Push**

```bash
git push -u origin feat/alternative-of-and-max-pl
```

- [ ] **Step 2: Open PR**

```bash
gh pr create --repo epigraph-io/epigraph \
  --title "feat: alternative_of edge + max-Pl combine + suggest_alternative_sets (#140, #141)" \
  --body "$(cat <<'EOF'
## Summary
- New `alternative_of` relationship admitted by `is_valid_relationship` and the application allow-list.
- Migration 042: symmetric partial unique index on the canonicalized endpoint pair + `alternative_set` view exposing the transitive-closure equivalence class.
- `epigraph_ds::combination::combine_alternative_set(bbas, target)` — max-Bel/max-Pl reduction.
- CDST BP groups a target's incoming supporters by alt-set canonical class, reduces each multi-member group with the new combine, then Dempster-combines the per-group BBAs.
- `mcp__epigraph__suggest_alternative_sets` returns candidate (claim_a, claim_b, target, score, reason) pairs from supporter contradictions; pure suggestion — no auto-creation.

## Why
The Dempster product rule over-combines mutually-exclusive supporters of a shared target (the legal/regulatory "least restrictive alternative" semantics). Without an alt-set primitive the engine treats two competing hypotheses as if their evidence stacked. Max-Pl reduction is the correct rule when independence has failed.

See `docs/superpowers/specs/2026-05-27-alternative-and-dependency-edges-design.md` § 1, 3, 4, 5.

## Test plan
- [x] `cargo test -p epigraph-api alternative_of_symmetric_dedup` — reversed-direction insert rejected
- [x] `cargo test -p epigraph-api alternative_set_view_closure` — 3-cycle transitive closure
- [x] `cargo test -p epigraph-ds combine_alternative_set_tests` — singleton, two-member, mixed
- [x] `cargo test -p epigraph-engine alt_set_cdst_integration` — alt-set BetP differs from pure Dempster
- [x] `cargo test -p epigraph-mcp suggest_alternative_sets` — only contradicts pairs surfaced; existing alternative_of skipped
- [x] `cargo test --workspace`
- [x] `cargo fmt --check` / `cargo clippy --all-targets -D warnings`

Closes #140, #141.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Verify PR**

```bash
gh pr view --repo epigraph-io/epigraph --json url,number,title
```

- [ ] **Step 4: Retire backlog claims**

Per `CLAUDE.md`:

```python
mcp__epigraph__resolve_backlog_item(
    original_id="46410d7c-5c17-4f81-9284-98fd879f5dac",  # alternative_of edge type
    resolution_content=(
        "Resolves 46410d7c: alternative_of admitted by VALID_RELATIONSHIPS, "
        "symmetric uniqueness enforced by partial unique index, equivalence "
        "class exposed via alternative_set view. Ingestion guidance for "
        "emitting alternative_of and the candidate-finder MCP tool ship in "
        "the same PR. See PR #<NN>."
    ),
)

mcp__epigraph__resolve_backlog_item(
    original_id="4812b044-a491-4e59-8214-7aeec8374f10",  # max-Pl combine
    resolution_content=(
        "Resolves 4812b044: combine_alternative_set in epigraph-ds applies "
        "max-Bel/max-Pl on the projected belief interval toward the target. "
        "CDST BP groups supporters by alt-set canonical class before "
        "Dempster combine. Mixed alt+independent regression test in "
        "alt_set_cdst_integration confirms divergence from pure Dempster. "
        "See PR #<NN>."
    ),
)
```

---

## Done

- `alternative_of` is a first-class edge type.
- The engine consumes it correctly.
- Operators can find candidate alt pairs without committing to them.
- Mutually-exclusive supporters no longer over-combine.
