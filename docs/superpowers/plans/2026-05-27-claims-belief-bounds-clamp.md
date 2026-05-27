# `claims_*_bounds` Write-Contract Clamp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Centralize the `[0.0, 1.0]` clamp for the five belief-measure columns (`belief`, `plausibility`, `pignistic_prob`, `mass_on_empty`, `mass_on_missing`) into one helper, then route every `UPDATE claims SET ...` write site through it. Closes issue #139.

**Architecture:** New helper `clamp_claim_belief_measures` in `crates/epigraph-ds/src/measures.rs`. Three confirmed write sites are migrated onto it: `MassFunctionRepository::update_claim_belief` (already clamps inline — drops the inline clamps in favor of the helper), `routes/computation.rs:621` (CDST BP apply — currently unclamped), `routes/computation.rs:655` (scalar BP fallback — currently unclamped, single-field). Per-site drift tests assert in-bounds persistence. An end-to-end test reproduces #139's repro and asserts no constraint violation.

**Tech Stack:** Rust, sqlx, Postgres (`epigraph_db_repo_test`), `epigraph-ds` crate, `epigraph-db` repo layer, `epigraph-mcp` MCP tools, `epigraph-api` HTTP routes.

---

## Setup

**Test database.** Every test in this plan runs against `epigraph_db_repo_test`, per `CLAUDE.md`:

```bash
export DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test'
```

**Branch.** Already on `spec/claims-belief-bounds-clamp` (the spec lives here). Continue on this branch.

**Background.** PR #149 / commit `a5b908e` (2026-05-16, *after* #139 was filed on 2026-05-14) added inline clamps to `epigraph_ds::measures::{belief, plausibility}` and to `MassFunctionRepository::update_claim_belief`. The `auto_wire_ds_update → update_claim_belief` path the issue body traces is therefore likely already protected. The remaining unclamped sites are in `crates/epigraph-api/src/routes/computation.rs`. The reproduction test in Task 1 establishes which path actually fails today.

---

### Task 1: Reproduce via `update_with_evidence` (the path the issue traces)

**Files:**
- Create: `crates/epigraph-mcp/tests/update_with_evidence_plausibility_one.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! Regression for issue #139.
//!
//! Seeds a claim at (plausibility=1.0, belief=0.4) and calls
//! update_with_evidence with supporting evidence. The issue body asserts
//! Postgres returns claims_plausibility_bounds. Post-PR #149 the
//! auto_wire_ds_update path clamps, so this test may pass on main;
//! if so, Task 3 captures the still-unclamped surface.

use epigraph_mcp::tests::common::{TestServer, seed_claim_with_belief};

#[tokio::test]
async fn update_with_evidence_does_not_violate_plausibility_bounds_at_one() {
    let server = TestServer::start().await;
    let claim_id = seed_claim_with_belief(
        &server.pool,
        /* belief */ 0.4,
        /* plausibility */ 1.0,
        /* pignistic_prob */ Some(0.4),
    )
    .await;

    let result = server
        .update_with_evidence(epigraph_mcp::types::UpdateWithEvidenceParams {
            claim_id: claim_id.to_string(),
            evidence_type: "experimental_data".into(),
            evidence_data: "Supporting observation that narrows belief but \
                            does not require lowering plausibility.".into(),
            source_url: None,
            supports: true,
            strength: 0.8,
        })
        .await;

    assert!(
        result.is_ok(),
        "update_with_evidence on Pl=1.0 claim returned err: {result:?}"
    );
}
```

If `seed_claim_with_belief` does not exist in `tests/common`, create it (Step 2). If `TestServer` does not exist, model on existing test fixtures (e.g., `crates/epigraph-mcp/tests/source_strength_tests.rs`).

- [ ] **Step 2: Add the seed helper if missing**

```rust
// crates/epigraph-mcp/tests/common/mod.rs (add to the existing mod)
pub async fn seed_claim_with_belief(
    pool: &sqlx::PgPool,
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    let agent_id = ensure_test_agent(pool).await;
    let content_hash: [u8; 32] = rand::random();
    sqlx::query(
        r#"
        INSERT INTO claims
            (id, content, content_hash, agent_id, truth_value,
             belief, plausibility, pignistic_prob, is_current)
        VALUES ($1, $2, $3, $4, 0.5, $5, $6, $7, true)
        "#,
    )
    .bind(id)
    .bind("test claim — pre-evidence Pl=1.0")
    .bind(content_hash.to_vec())
    .bind(agent_id)
    .bind(belief)
    .bind(plausibility)
    .bind(pignistic_prob)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
```

Re-use `ensure_test_agent` if it already exists; otherwise inline a minimal `INSERT INTO agents` for a test signer.

- [ ] **Step 3: Run the test and record the outcome**

```bash
cd /home/jeremy/epigraph
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-mcp \
  --test update_with_evidence_plausibility_one -- --nocapture
```

Expected: one of two outcomes.
- **(a)** Test fails with `claims_plausibility_bounds` violation. Record the stack — that is the still-unclamped path.
- **(b)** Test passes. Path is already protected by PR #149's inline clamps. The BP apply path in Task 3 is still unclamped and that is where the next reproduction is built.

Write the outcome into a one-paragraph note at the top of the test file as a `//!` comment so future reviewers know which case fired.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/tests/update_with_evidence_plausibility_one.rs \
        crates/epigraph-mcp/tests/common/mod.rs
git commit -m "test(mcp): regression repro for #139 (update_with_evidence at Pl=1.0)"
```

---

### Task 2: Add the centralized helper with unit tests

**Files:**
- Modify: `crates/epigraph-ds/src/measures.rs`
- Modify: `crates/epigraph-ds/src/lib.rs` (re-export if needed)

- [ ] **Step 1: Write helper unit tests first**

Append to `crates/epigraph-ds/src/measures.rs`:

```rust
#[cfg(test)]
mod clamp_tests {
    use super::clamp_claim_belief_measures;

    #[test]
    fn clamps_one_ulp_drift_to_one() {
        // 0.05 * 20 = 1.0000000000000002 in f64 — the exact drift case
        // measured in the order_independence_smoke test.
        let drifted = 0.05_f64 * 20.0;
        assert!(drifted > 1.0, "test setup: expected drift > 1.0");
        let (bel, pl, betp, me, mm) =
            clamp_claim_belief_measures(drifted, drifted, Some(drifted), drifted, drifted);
        assert_eq!(bel, 1.0);
        assert_eq!(pl, 1.0);
        assert_eq!(betp, Some(1.0));
        assert_eq!(me, 1.0);
        assert_eq!(mm, 1.0);
    }

    #[test]
    fn clamps_overshoot_and_undershoot() {
        let (bel, pl, betp, me, mm) =
            clamp_claim_belief_measures(1.5, -0.1, Some(2.0), -0.5, 1.7);
        assert_eq!(bel, 1.0);
        assert_eq!(pl, 0.0);
        assert_eq!(betp, Some(1.0));
        assert_eq!(me, 0.0);
        assert_eq!(mm, 1.0);
    }

    #[test]
    fn passes_through_in_range_values() {
        let (bel, pl, betp, me, mm) =
            clamp_claim_belief_measures(0.4, 0.9, Some(0.5), 0.1, 0.05);
        assert_eq!(bel, 0.4);
        assert_eq!(pl, 0.9);
        assert_eq!(betp, Some(0.5));
        assert_eq!(me, 0.1);
        assert_eq!(mm, 0.05);
    }

    #[test]
    fn preserves_none_pignistic() {
        let (_, _, betp, _, _) =
            clamp_claim_belief_measures(0.4, 0.9, None, 0.1, 0.05);
        assert_eq!(betp, None);
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail with "function not defined"**

```bash
cd /home/jeremy/epigraph
cargo test -p epigraph-ds clamp_tests -- --nocapture
```

Expected: `error[E0425]: cannot find function clamp_claim_belief_measures`.

- [ ] **Step 3: Implement the helper**

Add to `crates/epigraph-ds/src/measures.rs` (above the `#[cfg(test)]` block):

```rust
/// Clamp the five belief-measure fields written to `claims` to `[0.0, 1.0]`.
///
/// Three of the five — `belief`, `plausibility`, `mass_on_empty` — are enforced
/// at the DB level by `claims_belief_bounds`, `claims_plausibility_bounds`, and
/// `claims_mass_empty_bounds` respectively (see
/// `migrations/001_initial_schema.sql:627-631`). `pignistic_prob` and
/// `mass_on_missing` have no CHECK constraint today but are clamped defensively
/// so a future `ALTER TABLE ... ADD CONSTRAINT ...` lands without surfacing a
/// new bug.
///
/// All callers that issue
/// `UPDATE claims SET belief|plausibility|pignistic_prob|mass_on_empty|mass_on_missing ...`
/// MUST route their values through this helper.
#[must_use]
pub fn clamp_claim_belief_measures(
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
    mass_on_empty: f64,
    mass_on_missing: f64,
) -> (f64, f64, Option<f64>, f64, f64) {
    (
        belief.clamp(0.0, 1.0),
        plausibility.clamp(0.0, 1.0),
        pignistic_prob.map(|p| p.clamp(0.0, 1.0)),
        mass_on_empty.clamp(0.0, 1.0),
        mass_on_missing.clamp(0.0, 1.0),
    )
}
```

- [ ] **Step 4: Run the tests and verify they pass**

```bash
cargo test -p epigraph-ds clamp_tests -- --nocapture
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-ds/src/measures.rs
git commit -m "feat(ds): centralized clamp_claim_belief_measures helper"
```

---

### Task 3: Reproduce via the CDST BP apply path (the still-unclamped surface)

**Files:**
- Create: `crates/epigraph-api/tests/bp_apply_plausibility_bounds.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! Regression for issue #139 covering the BP apply path.
//!
//! routes/computation.rs:621 writes raw bel/pl from result.updated_intervals
//! without clamping. A combine sequence whose raw plausibility drifts above
//! 1.0 by one ULP trips claims_plausibility_bounds on apply.

use epigraph_api::tests::common::TestApi;
use serde_json::json;

#[tokio::test]
async fn cdst_bp_apply_clamps_drifted_plausibility() {
    let api = TestApi::start().await;
    let claim = api.seed_claim_with_belief(0.4, 1.0, Some(0.4)).await;

    // Seed enough BBAs (each w/ source_strength forcing the combined Pl above 1.0
    // by ULP drift) to trip the apply path. The 0.05 * 20 trick from
    // order_independence_smoke is reused.
    api.seed_drifting_bbas(claim, 20, 0.05).await;

    let resp = api
        .post(
            "/api/v1/graph/recompute_beliefs",
            json!({ "apply": true, "engine": "cdst" }),
        )
        .await;

    assert!(
        resp.status().is_success(),
        "recompute_beliefs apply returned {}: {}",
        resp.status(),
        resp.text().await
    );
}
```

If `TestApi::seed_drifting_bbas` is not present in test common helpers, add it: inserts 20 single-focal-element BBAs each carrying mass 0.05 against the binary frame for `claim_id`. Model on the seed helper in `crates/epigraph-ds/tests/order_independence_smoke.rs`.

- [ ] **Step 2: Run the test, observe failure**

```bash
cargo test -p epigraph-api --test bp_apply_plausibility_bounds -- --nocapture
```

Expected: HTTP 500 or err string containing `claims_plausibility_bounds`. If the test passes without the fix, the drift seed is not aggressive enough — increase the number of focal elements or the per-BBA mass until reproduction is achieved, and note in the test docstring.

- [ ] **Step 3: Do NOT commit yet — task 4 makes it pass**

The test is intentionally red; commit happens after Task 4.

---

### Task 4: Migrate `routes/computation.rs` BP apply paths to the helper

**Files:**
- Modify: `crates/epigraph-api/src/routes/computation.rs:611-660`

- [ ] **Step 1: Replace the CDST BP apply UPDATE with a helper call**

Current (`computation.rs:611-630`):

```rust
        // Apply updates: write pignistic_prob, belief, plausibility to claims
        let mut apply_failures = 0_usize;
        if apply {
            for (claim_id, betp) in &result.updated_betps {
                let iv = result
                    .updated_intervals
                    .iter()
                    .find(|(id, _)| id == claim_id)
                    .map(|(_, iv)| iv);
                let (bel, pl) = iv.map(|i| (i.bel, i.pl)).unwrap_or((0.0, 1.0));
                if sqlx::query(
                    "UPDATE claims SET pignistic_prob = $1, belief = $2, plausibility = $3, updated_at = NOW() WHERE id = $4",
                )
                .bind(betp).bind(bel).bind(pl).bind(claim_id)
                .execute(&state.db_pool)
                .await
                .is_err() {
                    apply_failures += 1;
                }
            }
        }
```

Replace with:

```rust
        // Apply updates: write pignistic_prob, belief, plausibility to claims.
        // claims_{belief,plausibility}_bounds CHECK constraint is satisfied via
        // epigraph_ds::measures::clamp_claim_belief_measures — see
        // docs/superpowers/specs/2026-05-27-claims-belief-bounds-clamp-design.md.
        let mut apply_failures = 0_usize;
        if apply {
            for (claim_id, betp) in &result.updated_betps {
                let iv = result
                    .updated_intervals
                    .iter()
                    .find(|(id, _)| id == claim_id)
                    .map(|(_, iv)| iv);
                let (raw_bel, raw_pl) = iv.map(|i| (i.bel, i.pl)).unwrap_or((0.0, 1.0));
                let (bel, pl, betp_clamped, _me, _mm) =
                    epigraph_ds::measures::clamp_claim_belief_measures(
                        raw_bel,
                        raw_pl,
                        Some(*betp),
                        0.0,
                        0.0,
                    );
                let betp_clamped = betp_clamped.unwrap_or(*betp);
                if sqlx::query(
                    "UPDATE claims SET pignistic_prob = $1, belief = $2, plausibility = $3, updated_at = NOW() WHERE id = $4",
                )
                .bind(betp_clamped).bind(bel).bind(pl).bind(claim_id)
                .execute(&state.db_pool)
                .await
                .is_err() {
                    apply_failures += 1;
                }
            }
        }
```

- [ ] **Step 2: Replace the scalar BP fallback UPDATE**

Current (`computation.rs:653-660`):

```rust
        for (claim_id, new_betp) in &result.updated_beliefs {
            let _ = sqlx::query("UPDATE claims SET pignistic_prob = $1 WHERE id = $2")
                .bind(new_betp)
                .bind(claim_id)
                .execute(&state.db_pool)
                .await;
        }
```

Replace with:

```rust
        for (claim_id, new_betp) in &result.updated_beliefs {
            let (_, _, betp_clamped, _, _) =
                epigraph_ds::measures::clamp_claim_belief_measures(
                    0.0,
                    0.0,
                    Some(*new_betp),
                    0.0,
                    0.0,
                );
            let betp_clamped = betp_clamped.unwrap_or(*new_betp);
            let _ = sqlx::query("UPDATE claims SET pignistic_prob = $1 WHERE id = $2")
                .bind(betp_clamped)
                .bind(claim_id)
                .execute(&state.db_pool)
                .await;
        }
```

- [ ] **Step 3: Run the Task 3 test, verify it now passes**

```bash
cargo test -p epigraph-api --test bp_apply_plausibility_bounds -- --nocapture
```

Expected: PASS.

- [ ] **Step 4: Commit Tasks 3 and 4 together**

```bash
git add crates/epigraph-api/tests/bp_apply_plausibility_bounds.rs \
        crates/epigraph-api/src/routes/computation.rs
# include any test-common helper additions in the same commit
git commit -m "fix(api): clamp BP apply writes to claims_*_bounds via helper

routes/computation.rs:621 wrote raw bel/pl from updated_intervals without
clamping, tripping claims_plausibility_bounds when combine drift pushed
Pl one ULP above 1.0. Now routes through
epigraph_ds::measures::clamp_claim_belief_measures, same contract as
MassFunctionRepository::update_claim_belief. Scalar BP fallback at
:655 migrated for consistency."
```

---

### Task 5: Migrate `MassFunctionRepository::update_claim_belief` to the helper

**Files:**
- Modify: `crates/epigraph-db/src/repos/mass_function.rs:275-307`

- [ ] **Step 1: Replace inline clamps with helper call**

Current (`mass_function.rs:275-307`):

```rust
        claim_id: Uuid,
        belief: f64,
        plausibility: f64,
        mass_on_empty: f64,
        pignistic_prob: Option<f64>,
        mass_on_missing: f64,
    ) -> Result<(), DbError> {
        let belief = belief.clamp(0.0, 1.0);
        let plausibility = plausibility.clamp(0.0, 1.0);
        let mass_on_empty = mass_on_empty.clamp(0.0, 1.0);
        let mass_on_missing = mass_on_missing.clamp(0.0, 1.0);
        let pignistic_prob = pignistic_prob.map(|p| p.clamp(0.0, 1.0));
```

Replace with:

```rust
        claim_id: Uuid,
        belief: f64,
        plausibility: f64,
        mass_on_empty: f64,
        pignistic_prob: Option<f64>,
        mass_on_missing: f64,
    ) -> Result<(), DbError> {
        // claims_{belief,plausibility,mass_empty}_bounds — see helper docs.
        let (belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing) =
            epigraph_ds::measures::clamp_claim_belief_measures(
                belief,
                plausibility,
                pignistic_prob,
                mass_on_empty,
                mass_on_missing,
            );
```

(Confirm `epigraph_ds` is already a dependency of `epigraph-db` via `cargo metadata -p epigraph-db | grep epigraph-ds`. If not, add to `crates/epigraph-db/Cargo.toml`.)

- [ ] **Step 2: Run the existing order_independence_smoke regression**

```bash
cargo test -p epigraph-ds order_independence_smoke -- --nocapture
```

Expected: PASS — confirms semantic behavior of the helper matches the prior inline clamps.

- [ ] **Step 3: Run the repo's own tests**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-db mass_function -- --nocapture
```

Expected: all existing tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-db/src/repos/mass_function.rs \
        crates/epigraph-db/Cargo.toml
git commit -m "refactor(db): mass_function update_claim_belief uses central clamp helper"
```

---

### Task 6: Per-site drift regression tests

**Files:**
- Modify: `crates/epigraph-db/tests/` (or create `mass_function_update_belief_drift.rs`)
- Modify: existing `bp_apply_plausibility_bounds.rs` from Task 3 (already covers the BP-apply site)

- [ ] **Step 1: Add the repo-level drift test**

Create `crates/epigraph-db/tests/mass_function_update_belief_drift.rs`:

```rust
//! Drift regression for MassFunctionRepository::update_claim_belief — proves
//! that one-ULP overshoot persists as 1.0 exactly, not 1.0000000000000002 and
//! not 0.97 (i.e., the clamp is applied where the inline code used to apply
//! it pre-helper).

use epigraph_db::repos::{ClaimRepository, MassFunctionRepository};

mod common;

#[tokio::test]
async fn update_claim_belief_clamps_one_ulp_drift() {
    let pool = common::test_pool().await;
    let (claim_id, _agent) = common::seed_minimal_claim(&pool).await;
    let frame_id = common::ensure_binary_frame(&pool).await;

    let drifted = 0.05_f64 * 20.0; // > 1.0 by one ULP
    assert!(drifted > 1.0);

    MassFunctionRepository::update_claim_belief(
        &pool,
        claim_id,
        /* belief */ drifted,
        /* plausibility */ drifted,
        /* mass_on_empty */ drifted,
        /* pignistic_prob */ Some(drifted),
        /* mass_on_missing */ drifted,
    )
    .await
    .expect("update_claim_belief tolerates drifted input");

    let row: (f64, f64, Option<f64>) = sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0, 1.0, "belief persisted unclamped");
    assert_eq!(row.1, 1.0, "plausibility persisted unclamped");
    assert_eq!(row.2, Some(1.0), "pignistic_prob persisted unclamped");
}
```

If `common::seed_minimal_claim` / `common::ensure_binary_frame` do not exist in `crates/epigraph-db/tests/common`, add minimal versions modeled on existing repo test fixtures.

- [ ] **Step 2: Run all three regression tests together**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' cargo test \
  -p epigraph-db mass_function_update_belief_drift \
  -p epigraph-api bp_apply_plausibility_bounds \
  -p epigraph-mcp update_with_evidence_plausibility_one \
  -- --nocapture
```

Expected: all 3 pass.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-db/tests/mass_function_update_belief_drift.rs \
        crates/epigraph-db/tests/common/
git commit -m "test(db): drift regression for MassFunctionRepository::update_claim_belief"
```

---

### Task 7: Final sweep — verify no other write sites slipped through

**Files:** none modified — verification only.

- [ ] **Step 1: Re-grep the workspace**

```bash
cd /home/jeremy/epigraph
# Using the Grep tool / ripgrep equivalent:
rg -n 'UPDATE claims SET[^"]*(belief|plausibility|pignistic_prob|mass_on_empty|mass_on_missing)' \
   crates/ migrations/
```

Expected output (no others):
- `crates/epigraph-api/src/routes/computation.rs:62?` — both BP apply sites (using helper)
- `crates/epigraph-db/src/repos/mass_function.rs:29?` — `update_claim_belief` (using helper)
- migration files (schema only, not application code)

If any additional UPDATE site appears (e.g., a new ingest path, a future migration script), migrate it via the helper now and add a drift test for it.

- [ ] **Step 2: Workspace build / lint / test**

```bash
SQLX_OFFLINE=true cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test --workspace
```

Expected: clean across all four.

- [ ] **Step 3: Re-prepare sqlx if any `query!` macros changed**

If `cargo check` reports `query!` macro mismatches:

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo sqlx prepare --workspace -- --tests
git add .sqlx
```

(No `query!` macros are expected to change since we only touch dynamic `sqlx::query(...)` strings, but verify.)

- [ ] **Step 4: Commit any sqlx or formatting fallout**

```bash
git status -sb
# If anything is staged from steps 2–3:
git commit -m "chore: cargo fmt + sqlx prepare after clamp-helper migration"
```

---

### Task 8: Push branch and open PR

- [ ] **Step 1: Push**

```bash
git push -u origin spec/claims-belief-bounds-clamp
```

- [ ] **Step 2: Open PR**

```bash
gh pr create --repo epigraph-io/epigraph \
  --title "fix: clamp claim belief/plausibility writes through central helper (#139)" \
  --body "$(cat <<'EOF'
## Summary
- New `epigraph_ds::measures::clamp_claim_belief_measures` helper; every `UPDATE claims SET ... (belief|plausibility|pignistic_prob|mass_on_empty|mass_on_missing)` site routes through it.
- `routes/computation.rs:621` (CDST BP apply) and `:655` (scalar BP fallback) previously wrote raw values; now clamped.
- `MassFunctionRepository::update_claim_belief` keeps the same clamp semantics, sourced from the helper instead of inline.
- Three regression tests prove drifted input persists at exactly 1.0 (not 1.0 + 1ULP).

## Why
Issue #139 traced `update_with_evidence` to a `claims_plausibility_bounds` violation. PR #149 fixed the inline `auto_wire_ds_update` path, but the BP apply path was never audited. Centralizing the contract prevents this class of bug from re-appearing at the next new write site.

## Test plan
- [x] `cargo test -p epigraph-ds clamp_tests` — 4 unit tests
- [x] `cargo test -p epigraph-mcp update_with_evidence_plausibility_one`
- [x] `cargo test -p epigraph-api bp_apply_plausibility_bounds`
- [x] `cargo test -p epigraph-db mass_function_update_belief_drift`
- [x] `cargo test --workspace` against epigraph_db_repo_test
- [x] `cargo fmt --check` / `cargo clippy --all-targets -D warnings`

Closes #139.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Verify PR exists**

```bash
gh pr view --repo epigraph-io/epigraph --json url,number,title
```

- [ ] **Step 4: Retire backlog claim**

Per `CLAUDE.md`, retire the backlog item via `mcp__epigraph__resolve_backlog_item`:

```python
mcp__epigraph__resolve_backlog_item(
    original_id="8c921f32-e99a-4045-981a-031f14d784ba",
    resolution_content=(
        "Resolves 8c921f32: clamp_claim_belief_measures helper now gates "
        "every UPDATE claims SET belief|plausibility|pignistic_prob|mass_on_empty|"
        "mass_on_missing site. CDST BP apply path (routes/computation.rs:621) "
        "was the live unclamped surface; sweeping all sites via the helper "
        "prevents the next instance. See PR #<NN>."
    ),
)
```

Substitute `<NN>` with the PR number from Step 3.

---

## Done

- Helper exists, every write site routes through it.
- Three regression tests pin the contract.
- #139 closed by PR merge.
- Backlog claim `8c921f32` retired via `resolve_backlog_item`.
