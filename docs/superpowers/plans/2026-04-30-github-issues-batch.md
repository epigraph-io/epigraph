# GitHub Issues Batch Implementation Plan (#19, #28–#33)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land all 7 open issues on `epigraph-io/epigraph` in a single coordinated effort, ordered to fix silent data loss first, unblock EpiClaw migration second, harden security third, and finish quality-of-life last.

**Architecture:** Six independent phases inside one feature branch. Phase 1 fixes ingest correctness in `epigraph-mcp` + `epigraph-db`. Phases 2–4 add API endpoints in `epigraph-api`. Phase 5 plumbs Ed25519 verification through `submit.rs`. Phase 6 adds an opt-in `relationships` query param to graph routes. Each phase has its own commit and can be cherry-picked or reverted independently.

**Tech Stack:** Rust 1.75+, Axum, sqlx, PostgreSQL 16, ed25519-dalek, blake3.

---

## Pre-flight

This plan was written from spec, not from a brainstorming session. There is no pre-built worktree.

- [ ] **Step 0.1: Create a fresh worktree off origin/main**

```bash
cd /home/jeremy/epigraph
git fetch origin main
git worktree add -b feat/github-issues-batch ../epigraph-wt-issues-batch origin/main
cd ../epigraph-wt-issues-batch
```

Expected: working tree at HEAD `171fdd6f` (or newer if main moved). Verify:

```bash
git log --oneline -1
# 171fdd6f docs: port design specs from epigraph-internal (#27)
```

- [ ] **Step 0.2: Confirm the toolchain works end-to-end**

```bash
cargo build -p epigraph-api -p epigraph-mcp -p epigraph-db --no-default-features --features db
```

Expected: clean build. If sqlx complains about offline-mode metadata, run `cargo sqlx prepare --workspace` against a live dev DB first.

- [ ] **Step 0.3: Confirm the dev DB is reachable**

```bash
psql "$DATABASE_URL" -c '\dt claims' | head -3
```

Expected: one row, `public | claims | table | <owner>`. If the connection fails, follow the EpigraphV2 devcontainer DB recipe in CLAUDE.md.

---

## Phase 1 — Issue #30: Persist `PlannedClaim.properties` to `claims.properties`

**Why first:** Silent data loss on every ingest. ~1,300 claims from yesterday's wiki run all have `properties = '{}'`. Level/section/generality filters return empty without a single error. Trivial fix, high payoff.

**Approach:** Add a surgical `set_properties` repo method (one UPDATE per new claim). Don't touch the kernel `Claim` struct or `ClaimRepository::create`'s 44 callers. Only call `set_properties` on the *new-claim* path in `do_ingest_document` so re-ingesting an existing claim doesn't silently overwrite a sibling paper's properties.

### Task 1.1: Add `ClaimRepository::set_properties`

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs` (add method to `impl ClaimRepository`)
- Test: `crates/epigraph-db/src/repos/claim.rs` (extend existing `#[cfg(test)] mod tests`)

- [ ] **Step 1.1.1: Write the failing test**

Add to the test module at the bottom of `claim.rs`:

```rust
#[sqlx::test]
async fn set_properties_writes_jsonb_column(pool: sqlx::PgPool) {
    let agent = epigraph_test_support::seed_agent(&pool).await;
    let claim = Claim::new(
        "Test claim for properties".to_string(),
        agent.id,
        agent.public_key,
        TruthValue::clamped(0.5),
    );
    let persisted = ClaimRepository::create(&pool, &claim).await.unwrap();
    let props = serde_json::json!({"level": 3, "section": "Body", "source_type": "Wiki"});

    ClaimRepository::set_properties(&pool, persisted.id, props.clone())
        .await
        .unwrap();

    let row: (serde_json::Value,) = sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
        .bind(Uuid::from(persisted.id))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.0, props);
}
```

If `epigraph_test_support::seed_agent` does not exist verbatim, follow the existing test pattern in `claim.rs` for inserting an agent (search for `INSERT INTO agents` in the test module and copy that pattern).

- [ ] **Step 1.1.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-db --features db set_properties_writes_jsonb_column
```

Expected: FAIL — `no method named set_properties`.

- [ ] **Step 1.1.3: Implement `set_properties`**

Add to `impl ClaimRepository` in `crates/epigraph-db/src/repos/claim.rs` (place near `create`, around line 140):

```rust
/// Set the `properties` JSONB column on an existing claim. Overwrites the
/// existing value (does not merge). Used by ingest to attach hierarchy
/// metadata (level, section, source_type, generality) at creation time.
///
/// # Errors
/// Returns `DbError::QueryFailed` if the database query fails.
#[instrument(skip(pool, properties))]
pub async fn set_properties(
    pool: &PgPool,
    claim_id: ClaimId,
    properties: serde_json::Value,
) -> Result<(), DbError> {
    let id: Uuid = claim_id.into();
    sqlx::query!(
        "UPDATE claims SET properties = $2, updated_at = NOW() WHERE id = $1",
        id,
        properties
    )
    .execute(pool)
    .await?;
    Ok(())
}
```

- [ ] **Step 1.1.4: Run the test to confirm it passes**

```bash
cargo test -p epigraph-db --features db set_properties_writes_jsonb_column
```

Expected: PASS.

- [ ] **Step 1.1.5: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs
git commit -m "feat(db): add ClaimRepository::set_properties for ingest metadata"
```

### Task 1.2: Wire `set_properties` into `do_ingest_document` for new claims

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/ingestion.rs:497-630` (the planned-claim loop)

- [ ] **Step 1.2.1: Write the failing integration test**

Add to `crates/epigraph-mcp/tests/ingestion_integration.rs` (create file if missing — follow the pattern of any existing integration test in that crate; if no such file/pattern exists, add the test inline at the bottom of `crates/epigraph-mcp/src/tools/ingestion.rs` under `#[cfg(test)]`):

```rust
#[sqlx::test]
async fn ingest_document_persists_planned_properties(pool: sqlx::PgPool) {
    let server = epigraph_mcp::test_support::spawn_test_server(pool.clone()).await;
    let extraction = epigraph_mcp::test_support::minimal_extraction_with_one_atom(
        "props-test:001",
        "A single atomic claim with hierarchy metadata.",
    );

    do_ingest_document(&server, &extraction).await.unwrap();

    let count_with_props: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE properties::text != '{}'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(count_with_props > 0,
        "expected at least one claim with non-empty properties");

    let level_zero: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE properties->>'level' = '0'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(level_zero, 1, "thesis (level 0) should be queryable by properties->>'level'");
}
```

If `test_support::spawn_test_server` and `minimal_extraction_with_one_atom` do not exist, study how `do_ingest_document` is currently called in tests (`git grep -n 'do_ingest_document' crates/epigraph-mcp/`) and adapt. The test must drive a real `do_ingest_document` against a real `pool` so the DB write path is exercised.

- [ ] **Step 1.2.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-mcp --features db ingest_document_persists_planned_properties
```

Expected: FAIL — `assertion failed: count_with_props > 0`.

- [ ] **Step 1.2.3: Implement the fix**

In `crates/epigraph-mcp/src/tools/ingestion.rs`, find the new-claim path (around line 555, just after `let formatted_evidence = format!(...);` and before the evidence-write block — the exact location is the branch that runs only when `persisted_id == planned.id && !already_had_trace`).

Add this call **after** `ClaimRepository::create(...)` returns successfully and we've established this is a new claim (after the early `continue` for the dedup branch at line 547), but **before** any expensive embed/DS work — so a write failure aborts the per-claim loop early:

```rust
// Persist hierarchy metadata (level, section, source_type, generality)
// from the ingest plan onto the new claim's `properties` column.
ClaimRepository::set_properties(
    pool,
    ClaimId::from_uuid(persisted_id),
    planned.properties.clone(),
)
.await
.map_err(internal_error)?;
```

If `ClaimId::from_uuid` is not in scope, add it to the existing `use epigraph_core::...` block at the top of the file.

- [ ] **Step 1.2.4: Run the test to confirm it passes**

```bash
cargo test -p epigraph-mcp --features db ingest_document_persists_planned_properties
```

Expected: PASS.

- [ ] **Step 1.2.5: Commit**

```bash
git add crates/epigraph-mcp/src/tools/ingestion.rs crates/epigraph-mcp/tests/ingestion_integration.rs
git commit -m "fix(ingest): persist PlannedClaim.properties to claims.properties (#30)"
```

---

## Phase 2 — Issue #29: Drop self-loop `decomposes_to` edges after id_map remap

**Why second:** Hard ingest crash on real corpus inputs (compound text == its single atom). Aborts mid-document, leaves partial state. Cheapest correct fix is filter-on-write inside `do_ingest_document`, not changing `ClaimRepository::create`'s dedup semantics (the doc comment on `create` explicitly defers cross-agent collapse to a separate migration).

**Approach:** Issue's fix proposal #2. After the `id_map` remap of an edge's source/target, drop the edge if it would collapse to a self-loop on the same `(id, type)`. Five lines, additive, doesn't touch the kernel or repos.

### Task 2.1: Filter self-loop edges in `do_ingest_document`

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/ingestion.rs:636-672` (the edge-persist loop)

- [ ] **Step 2.1.1: Write the failing test**

Add to the same test module/file as Phase 1's integration test:

```rust
#[sqlx::test]
async fn ingest_document_handles_compound_equals_atom(pool: sqlx::PgPool) {
    let server = epigraph_mcp::test_support::spawn_test_server(pool.clone()).await;

    // Reproduces the wrhq 2026-04-30 collision: paragraph compound text
    // is identical to its sole atom — same content_hash → same persisted
    // claim → planned decomposes_to becomes a self-loop after id_map.
    let extraction_json = serde_json::json!({
        "source": {
            "title": "compound-atom-test",
            "doi": "wrhq:test/compound-atom-collision",
            "source_type": "InternalDocument",
            "authors": [{"name": "test", "affiliations": [], "roles": ["author"]}],
            "year": 2026,
            "metadata": {}
        },
        "thesis": "Test of compound==atom collision.",
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Body",
            "summary": "One section, one paragraph, one atom.",
            "paragraphs": [{
                "compound": "Class B agents have a contract.active flag.",
                "supporting_text": "Class B agents have a contract.active flag.",
                "atoms": ["Class B agents have a contract.active flag."],
                "generality": [0],
                "confidence": 0.8,
                "methodology": "extraction",
                "evidence_type": "testimonial"
            }]
        }],
        "relationships": []
    });
    let extraction: epigraph_ingest::DocumentExtraction =
        serde_json::from_value(extraction_json).unwrap();

    // Must not panic and must not return Err with a CHECK violation.
    let result = do_ingest_document(&server, &extraction).await;
    assert!(result.is_ok(), "expected ingest to succeed, got: {result:?}");

    // No self-loop edges should exist.
    let self_loops: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = target_id"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(self_loops, 0, "self-loop edges should be filtered, found {self_loops}");
}
```

- [ ] **Step 2.1.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-mcp --features db ingest_document_handles_compound_equals_atom
```

Expected: FAIL — error from sqlx with `edges_no_self_loop` constraint violation, OR test returns `Err`.

- [ ] **Step 2.1.3: Implement the fix**

In `crates/epigraph-mcp/src/tools/ingestion.rs`, locate the edge-persist loop starting at the comment `// ── 5. Plan edges ──` (around line 635). After the existing remapping block sets `(src, src_type)` and `tgt`, but BEFORE the `EdgeRepository::create_if_not_exists` call, add:

```rust
        // Filter self-loops introduced by content-hash dedup collapsing
        // distinct planned UUIDs (e.g. compound paragraph and its sole
        // atom that share text) onto the same persisted claim. The
        // semantically correct outcome is a no-op decomposition; the DB
        // would otherwise reject this with edges_no_self_loop.
        if src == tgt && src_type == edge.target_type {
            continue;
        }

        EdgeRepository::create_if_not_exists(
```

The trailing `EdgeRepository::create_if_not_exists(` is the existing line — leave it intact. The `continue` skips the create call.

- [ ] **Step 2.1.4: Run the test to confirm it passes**

```bash
cargo test -p epigraph-mcp --features db ingest_document_handles_compound_equals_atom
```

Expected: PASS.

- [ ] **Step 2.1.5: Run Phase 1's test to confirm no regression**

```bash
cargo test -p epigraph-mcp --features db ingest_document_persists_planned_properties
```

Expected: PASS (still).

- [ ] **Step 2.1.6: Commit**

```bash
git add crates/epigraph-mcp/src/tools/ingestion.rs crates/epigraph-mcp/tests/ingestion_integration.rs
git commit -m "fix(ingest): drop self-loop decomposes_to edges from compound==atom dedup (#29)"
```

---

## Phase 3 — Issue #33: Add `exclude_agent_id` to `GET /api/v1/claims`

**Why third:** Smallest of the EpiClaw-blocking endpoints. Verified on origin/main `claims_query.rs:85-89`: `created_after` and `created_before` already exist in `PaginationParams` and are wired into both code paths (~line 376 and ~line 583). Only `exclude_agent_id` is missing. ~20 LOC.

### Task 3.1: Add `exclude_agent_id` filter

**Files:**
- Modify: `crates/epigraph-api/src/routes/claims_query.rs:70-100` (struct), `:370-380` and `:572-585` (filters — both `db` and non-`db` branches)

- [ ] **Step 3.1.1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` in `claims_query.rs`:

```rust
#[tokio::test]
async fn list_claims_excludes_agent_id() {
    let state = test_state().await;
    let agent_a = AgentId::new();
    let agent_b = AgentId::new();
    insert_test_claim_with_agent(&state, "from agent A", 0.5, agent_a).await;
    insert_test_claim_with_agent(&state, "from agent B", 0.5, agent_b).await;

    let router = test_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/claims?exclude_agent_id={}", agent_a.as_uuid()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = parse_body(response).await;
    let claims = body["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["content"], "from agent B");
}
```

If helpers like `test_state`, `test_router`, `insert_test_claim_with_agent`, or `parse_body` look slightly different in the existing tests, mirror those exactly — don't invent new ones.

- [ ] **Step 3.1.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-api --features db list_claims_excludes_agent_id
```

Expected: FAIL — unknown query parameter or wrong count.

- [ ] **Step 3.1.3: Add the field to `PaginationParams`**

In `crates/epigraph-api/src/routes/claims_query.rs`, find the `PaginationParams` struct (around line 70) and add this field after `pub agent_id: Option<Uuid>`:

```rust
    /// Exclude claims created by this agent. Composes with `agent_id`
    /// (if both are set, `agent_id` filters in and `exclude_agent_id`
    /// filters out — useful for "all claims except those from the host").
    pub exclude_agent_id: Option<Uuid>,
```

- [ ] **Step 3.1.4: Apply the filter in both code paths**

There are two `list_claims_query` functions (one with `db` feature at ~line 174, one fallback at ~line 452) and two filter blocks (~line 370 and ~line 572). In **each** filter block, locate the `// Filter by agent_id` block:

```rust
    // Filter by agent_id
    if let Some(agent_id) = params.agent_id {
        claims.retain(|c| c.agent_id.as_uuid() == agent_id);
    }
```

Add directly after it:

```rust
    // Filter out a specific agent (composes with agent_id above)
    if let Some(exclude_agent_id) = params.exclude_agent_id {
        claims.retain(|c| c.agent_id.as_uuid() != exclude_agent_id);
    }
```

Apply this addition to **both** filter blocks (~line 370 and ~line 572).

- [ ] **Step 3.1.5: Run the test to confirm it passes**

```bash
cargo test -p epigraph-api --features db list_claims_excludes_agent_id
```

Expected: PASS.

- [ ] **Step 3.1.6: Commit**

```bash
git add crates/epigraph-api/src/routes/claims_query.rs
git commit -m "feat(api): add exclude_agent_id filter to GET /api/v1/claims (#33)"
```

---

## Phase 4 — Issue #31: `GET /api/v1/workflows/:id`

**Why fourth:** Mirror of `GET /api/v1/claims/:id` filtered by the `'workflow'` label. ~30 LOC. Unblocks EpiClaw scheduler firing single-workflow lookups.

### Task 4.1: Add `get_workflow` handler

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs` (add handler near `list_workflows`, around line 384)
- Modify: `crates/epigraph-api/src/routes/mod.rs:285-290` (register route)

- [ ] **Step 4.1.1: Write the failing test**

Add to `workflows.rs`'s test module (find existing `#[cfg(test)] mod tests` or create one matching the file's existing patterns):

```rust
#[tokio::test]
async fn get_workflow_returns_single_workflow() {
    let state = test_state().await;
    let workflow_id = seed_test_workflow(&state, "deploy-canary", &["step1", "step2"]).await;

    let router = workflow_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/workflows/{workflow_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = parse_body(response).await;
    assert_eq!(body["workflow_id"], workflow_id.to_string());
    assert!(body["content"].is_string() || body["content"].is_object());
    assert!(body["truth_value"].is_number());
    assert!(body["properties"].is_object());
}

#[tokio::test]
async fn get_workflow_returns_404_for_non_workflow_claim() {
    let state = test_state().await;
    // Insert a claim WITHOUT 'workflow' label
    let claim_id = seed_plain_claim(&state, "not a workflow").await;

    let router = workflow_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/workflows/{claim_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
```

If `seed_test_workflow` / `seed_plain_claim` don't exist, write minimal helpers in the test module — pattern off `store_workflow`'s SQL at `workflows.rs:135` for workflow seeding, and a plain `INSERT INTO claims (...) VALUES (...)` for non-workflow.

- [ ] **Step 4.1.2: Run the tests to confirm they fail**

```bash
cargo test -p epigraph-api --features db get_workflow_returns_single_workflow get_workflow_returns_404_for_non_workflow_claim
```

Expected: FAIL — handler not found / route not registered.

- [ ] **Step 4.1.3: Implement `get_workflow`**

In `crates/epigraph-api/src/routes/workflows.rs`, add this handler after `list_workflows` (around line 385). Use the existing `WorkflowContentRow` struct already in the file (line 908):

```rust
/// GET /api/v1/workflows/:id - Fetch a single workflow by ID.
///
/// Returns 404 if the claim does not exist or is not labeled `workflow`.
#[cfg(feature = "db")]
pub async fn get_workflow(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = sqlx::query_as::<_, WorkflowContentRow>(
        "SELECT id, content, truth_value, properties \
         FROM claims WHERE id = $1 AND 'workflow' = ANY(labels)",
    )
    .bind(workflow_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch workflow: {e}"),
    })?
    .ok_or(ApiError::NotFound {
        resource: format!("workflow {workflow_id}"),
    })?;

    Ok(Json(serde_json::json!({
        "workflow_id": row.id,
        "content": serde_json::from_str::<serde_json::Value>(&row.content)
            .unwrap_or_else(|_| serde_json::Value::String(row.content)),
        "truth_value": row.truth_value,
        "properties": row.properties,
    })))
}
```

If `ApiError::NotFound` doesn't have a `resource` field with that exact name, check the existing `ApiError` enum in `crates/epigraph-api/src/errors.rs` and use whatever variant returns `404 Not Found` (search for `StatusCode::NOT_FOUND` in that file).

- [ ] **Step 4.1.4: Register the route**

In `crates/epigraph-api/src/routes/mod.rs`, find the workflow route block (around line 275–290) and add this route. Place it before the `:id/outcome` route so axum's path matching prefers the more specific routes first:

```rust
        .route("/api/v1/workflows/:id", get(workflows::get_workflow))
```

If `get` is not already imported at the top of `mod.rs`, add it to the existing axum imports.

- [ ] **Step 4.1.5: Run the tests to confirm they pass**

```bash
cargo test -p epigraph-api --features db get_workflow_returns_single_workflow get_workflow_returns_404_for_non_workflow_claim
```

Expected: PASS.

- [ ] **Step 4.1.6: Commit**

```bash
git add crates/epigraph-api/src/routes/workflows.rs crates/epigraph-api/src/routes/mod.rs
git commit -m "feat(api): add GET /api/v1/workflows/:id (#31)"
```

---

## Phase 5 — Issue #28: Policy + policy-challenge endpoints

**Why fifth:** Largest of the EpiClaw additions (~250 LOC). Reference impl exists in deprecated `epigraph-nano/src/persistence.rs:7332-7530`. All seven queries map cleanly to the public `claims` schema using existing labels (`policy:active`, `policy:network`, `policy:challenge`).

**Approach:** One new module file. Seven handlers. Minimal types. Tests exercise each endpoint round-trip.

### Task 5.1: Create the module skeleton and types

**Files:**
- Create: `crates/epigraph-api/src/routes/policies.rs`
- Modify: `crates/epigraph-api/src/routes/mod.rs` (add `pub mod policies;` and route registrations)

- [ ] **Step 5.1.1: Create the file with types and an empty handler stub**

Write `crates/epigraph-api/src/routes/policies.rs`:

```rust
//! /api/v1/policies/* — labeled-claim view over network access policies.
//!
//! All policies are stored as ordinary claims with `policy:active` and
//! `policy:network` labels and `host`/`port`/`protocol`/`decay_exempt`
//! fields in `properties`. Challenges are claims with `policy:challenge`
//! and a `status` field in `properties`.
//!
//! Reference implementation: `epigraph-nano/src/persistence.rs:7332-7530`.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{errors::ApiError, AppState};

#[derive(Debug, Deserialize)]
pub struct ListPoliciesQuery {
    #[serde(default = "default_min_truth")]
    pub min_truth: f64,
}
const fn default_min_truth() -> f64 {
    0.5
}

#[derive(Debug, Deserialize)]
pub struct OutcomeRequest {
    pub supports: bool,
    pub strength: f64,
}

#[derive(Debug, Deserialize)]
pub struct CreateChallengeRequest {
    pub host: String,
    pub port: i64,
    pub protocol: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveChallengeRequest {
    pub approved: bool,
}
```

- [ ] **Step 5.1.2: Wire the module into `routes/mod.rs`**

In `crates/epigraph-api/src/routes/mod.rs`, near the other `pub mod` lines (around line 35), add:

```rust
#[cfg(feature = "db")]
pub mod policies;
```

Don't register routes yet — we'll add them after each handler exists.

- [ ] **Step 5.1.3: Build to confirm types compile**

```bash
cargo check -p epigraph-api --features db
```

Expected: clean, no warnings about unused types (Rust will warn — `#[allow(dead_code)]` is fine to add to silence, but only on `pub` types if needed).

- [ ] **Step 5.1.4: Commit**

```bash
git add crates/epigraph-api/src/routes/policies.rs crates/epigraph-api/src/routes/mod.rs
git commit -m "scaffold(api): policies module with request/response types (#28)"
```

### Task 5.2: `GET /api/v1/policies/network`

- [ ] **Step 5.2.1: Write the failing test**

Add to `policies.rs` under `#[cfg(test)] mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // (use the same test scaffolding pattern as workflows.rs / claims_query.rs)

    #[tokio::test]
    async fn list_network_policies_returns_active_policies_above_min_truth() {
        let state = test_state().await;
        seed_policy(&state, "example.com", 443, "https", 0.92, false).await;
        seed_policy(&state, "blocked.com", 443, "https", 0.10, false).await;

        let router = policy_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policies/network?min_truth=0.5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = parse_body(response).await;
        let policies = body["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0]["host"], "example.com");
    }
}
```

`seed_policy` is a small helper to insert a `claims` row with `labels = ARRAY['policy:active','policy:network']` and the right `properties`/`truth_value`. Inline it in the test module.

- [ ] **Step 5.2.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-api --features db list_network_policies_returns_active_policies_above_min_truth
```

Expected: FAIL — handler / route not present.

- [ ] **Step 5.2.3: Implement the handler**

In `policies.rs`:

```rust
/// GET /api/v1/policies/network — list active network-access policies.
#[cfg(feature = "db")]
pub async fn list_network_policies(
    State(state): State<AppState>,
    Query(params): Query<ListPoliciesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let min_truth = params.min_truth.clamp(0.0, 1.0);
    let rows: Vec<(Uuid, f64, serde_json::Value)> = sqlx::query_as(
        "SELECT id, truth_value, properties \
         FROM claims \
         WHERE 'policy:active' = ANY(labels) \
           AND 'policy:network' = ANY(labels) \
           AND truth_value >= $1 \
         ORDER BY truth_value DESC",
    )
    .bind(min_truth)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to list policies: {e}"),
    })?;

    let policies: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, truth_value, properties)| {
            serde_json::json!({
                "claim_id": id,
                "host": properties.get("host"),
                "port": properties.get("port"),
                "protocol": properties.get("protocol"),
                "truth_value": truth_value,
                "decay_exempt": properties.get("decay_exempt").and_then(|v| v.as_bool()).unwrap_or(false),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "policies": policies })))
}
```

- [ ] **Step 5.2.4: Register the route**

In `crates/epigraph-api/src/routes/mod.rs`, after the existing graph routes (around line 410), add:

```rust
        .route("/api/v1/policies/network", get(policies::list_network_policies))
```

- [ ] **Step 5.2.5: Run the test to confirm it passes**

```bash
cargo test -p epigraph-api --features db list_network_policies_returns_active_policies_above_min_truth
```

Expected: PASS.

- [ ] **Step 5.2.6: Commit**

```bash
git add crates/epigraph-api/src/routes/policies.rs crates/epigraph-api/src/routes/mod.rs
git commit -m "feat(api): GET /api/v1/policies/network (#28)"
```

### Task 5.3: `POST /api/v1/policies/:claim_id/outcome`

- [ ] **Step 5.3.1: Write the failing test**

In `policies.rs` test module:

```rust
#[tokio::test]
async fn outcome_supports_true_increases_truth_value() {
    let state = test_state().await;
    let claim_id = seed_policy(&state, "example.com", 443, "https", 0.5, false).await;

    let router = policy_router(state.clone());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/api/v1/policies/{claim_id}/outcome"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"supports": true, "strength": 0.05}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let new_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&state.db_pool)
        .await
        .unwrap();
    assert!(new_truth > 0.5, "expected truth to increase, got {new_truth}");
    assert!(new_truth <= 0.99);
}
```

- [ ] **Step 5.3.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-api --features db outcome_supports_true_increases_truth_value
```

Expected: FAIL.

- [ ] **Step 5.3.3: Implement the handler**

```rust
/// POST /api/v1/policies/:claim_id/outcome — Bayesian-style nudge.
///
/// `supports = true` increases truth toward 1.0; `false` decreases.
/// `strength` is the magnitude in (0, 1]; clamped server-side.
#[cfg(feature = "db")]
pub async fn record_outcome(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(req): Json<OutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let strength = req.strength.clamp(0.0, 1.0);
    let signed = if req.supports { strength } else { -strength };

    // Same closed-form update as epigraph-nano/src/persistence.rs:7430.
    let row: Option<(f64,)> = sqlx::query_as(
        "UPDATE claims SET \
            truth_value = LEAST(0.99, GREATEST(0.01, \
                truth_value + $1 * (1.0 - truth_value) * \
                CASE WHEN $1 > 0 THEN 1.0 ELSE truth_value END)), \
            updated_at = NOW() \
         WHERE id = $2 AND 'policy:active' = ANY(labels) \
         RETURNING truth_value",
    )
    .bind(signed)
    .bind(claim_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to update policy outcome: {e}"),
    })?;

    let new_truth = row
        .ok_or(ApiError::NotFound {
            resource: format!("policy {claim_id}"),
        })?
        .0;

    Ok(Json(serde_json::json!({
        "claim_id": claim_id,
        "truth_value": new_truth,
    })))
}
```

- [ ] **Step 5.3.4: Register the route**

In `routes/mod.rs`:

```rust
        .route("/api/v1/policies/:claim_id/outcome", post(policies::record_outcome))
```

- [ ] **Step 5.3.5: Run the test, then commit**

```bash
cargo test -p epigraph-api --features db outcome_supports_true_increases_truth_value
```

Expected: PASS.

```bash
git add crates/epigraph-api/src/routes/policies.rs crates/epigraph-api/src/routes/mod.rs
git commit -m "feat(api): POST /api/v1/policies/:id/outcome (#28)"
```

### Task 5.4: `POST /api/v1/policies/decay-sweep`

- [ ] **Step 5.4.1: Write the failing test**

```rust
#[tokio::test]
async fn decay_sweep_pulls_stale_truth_toward_one_half() {
    let state = test_state().await;
    let stale_id = seed_policy_with_age(&state, "stale.com", 443, "https", 0.9, false, 100).await;
    let fresh_id = seed_policy_with_age(&state, "fresh.com", 443, "https", 0.9, false, 1).await;
    let exempt_id = seed_policy_with_age(&state, "exempt.com", 443, "https", 0.9, true, 100).await;

    let router = policy_router(state.clone());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/policies/decay-sweep")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = parse_body(response).await;
    assert_eq!(body["rows_affected"], 1);

    let stale_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(stale_id)
        .fetch_one(&state.db_pool).await.unwrap();
    assert!(stale_truth < 0.9 && stale_truth > 0.5);

    let fresh_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(fresh_id).fetch_one(&state.db_pool).await.unwrap();
    assert_eq!(fresh_truth, 0.9);

    let exempt_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(exempt_id).fetch_one(&state.db_pool).await.unwrap();
    assert_eq!(exempt_truth, 0.9);
}
```

`seed_policy_with_age(state, host, port, protocol, truth, decay_exempt, days_old)` is another small helper — INSERT then `UPDATE claims SET updated_at = NOW() - INTERVAL '<days> days' WHERE id = $1`.

- [ ] **Step 5.4.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-api --features db decay_sweep_pulls_stale_truth_toward_one_half
```

Expected: FAIL.

- [ ] **Step 5.4.3: Implement the handler**

```rust
/// POST /api/v1/policies/decay-sweep — pull stale active policies toward 0.5.
///
/// Skips claims with `properties->>'decay_exempt' = 'true'`. Returns the
/// number of rows updated.
#[cfg(feature = "db")]
pub async fn decay_sweep(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = sqlx::query(
        "UPDATE claims SET \
            truth_value = truth_value + 0.1 * (0.5 - truth_value), \
            updated_at = NOW() \
         WHERE 'policy:active' = ANY(labels) \
           AND COALESCE((properties->>'decay_exempt')::boolean, false) IS NOT TRUE \
           AND updated_at < NOW() - INTERVAL '90 days'",
    )
    .execute(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Decay sweep failed: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "rows_affected": result.rows_affected(),
    })))
}
```

- [ ] **Step 5.4.4: Register the route, run the test, commit**

```rust
        .route("/api/v1/policies/decay-sweep", post(policies::decay_sweep))
```

```bash
cargo test -p epigraph-api --features db decay_sweep_pulls_stale_truth_toward_one_half
```

Expected: PASS.

```bash
git add crates/epigraph-api/src/routes/policies.rs crates/epigraph-api/src/routes/mod.rs
git commit -m "feat(api): POST /api/v1/policies/decay-sweep (#28)"
```

### Task 5.5: Policy challenges (3 endpoints)

- [ ] **Step 5.5.1: Write the failing tests**

```rust
#[tokio::test]
async fn create_challenge_returns_id_and_persists_pending() {
    let state = test_state().await;
    let router = policy_router(state.clone());

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/policy-challenges")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"host":"example.com","port":443}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = parse_body(response).await;
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let (labels, properties): (Vec<String>, serde_json::Value) =
        sqlx::query_as("SELECT labels, properties FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(&state.db_pool)
            .await
            .unwrap();
    assert!(labels.contains(&"policy:challenge".to_string()));
    assert_eq!(properties["host"], "example.com");
    assert_eq!(properties["port"], 443);
    assert_eq!(properties["status"], "pending");
}

#[tokio::test]
async fn get_challenge_returns_404_when_not_a_challenge() {
    let state = test_state().await;
    let claim_id = seed_plain_claim(&state, "not a challenge").await;
    let router = policy_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/policy-challenges/{claim_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn resolve_challenge_denied_strengthens_default_deny() {
    let state = test_state().await;
    // Seed a default-deny policy at 0.6 truth — name it via the well-known
    // sentinel host the production system uses (per nano: '*' / 'default').
    let default_deny_id =
        seed_policy(&state, "*", 0, "*", 0.6, false /* decay_exempt */).await;
    let challenge_id = create_challenge_via_handler(&state, "blocked.com", 443).await;

    let router = policy_router(state.clone());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/api/v1/policy-challenges/{challenge_id}/resolve"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"approved": false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let default_deny_truth: f64 =
        sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
            .bind(default_deny_id)
            .fetch_one(&state.db_pool)
            .await
            .unwrap();
    assert!((default_deny_truth - 0.63).abs() < 1e-6,
        "expected 0.6 + 0.03 = 0.63, got {default_deny_truth}");
}
```

- [ ] **Step 5.5.2: Run the tests to confirm they fail**

```bash
cargo test -p epigraph-api --features db \
    create_challenge_returns_id_and_persists_pending \
    get_challenge_returns_404_when_not_a_challenge \
    resolve_challenge_denied_strengthens_default_deny
```

Expected: 3 FAILs.

- [ ] **Step 5.5.3: Implement the three handlers**

In `policies.rs`:

```rust
/// POST /api/v1/policy-challenges — create a pending challenge claim.
#[cfg(feature = "db")]
pub async fn create_challenge(
    State(state): State<AppState>,
    Json(req): Json<CreateChallengeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sys_agent_id = crate::routes::workflows::get_or_create_system_agent(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to resolve system agent: {e}"),
        })?;

    let content = format!(
        "Network access challenge: {}:{} ({})",
        req.host,
        req.port,
        req.protocol.as_deref().unwrap_or("any")
    );
    let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY['policy','policy:challenge'], $4) \
         RETURNING id",
    )
    .bind(&content)
    .bind(content_hash.as_slice())
    .bind(sys_agent_id)
    .bind(serde_json::json!({
        "host": req.host,
        "port": req.port,
        "protocol": req.protocol,
        "status": "pending",
    }))
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create challenge: {e}"),
    })?;

    Ok(Json(serde_json::json!({ "id": id })))
}

/// GET /api/v1/policy-challenges/:id — fetch a challenge by ID.
#[cfg(feature = "db")]
pub async fn get_challenge(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row: Option<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT id, properties FROM claims \
         WHERE id = $1 AND 'policy:challenge' = ANY(labels)",
    )
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch challenge: {e}"),
    })?;

    let (id, properties) = row.ok_or(ApiError::NotFound {
        resource: format!("policy-challenge {id}"),
    })?;

    Ok(Json(serde_json::json!({
        "id": id,
        "host": properties.get("host"),
        "port": properties.get("port"),
        "protocol": properties.get("protocol"),
        "status": properties.get("status"),
    })))
}

/// POST /api/v1/policy-challenges/:id/resolve — approve or deny.
///
/// On `approved=false`, also strengthens the default-deny policy claim
/// by +0.03 (capped at 0.99) — mirrors nano's behavior at
/// `epigraph-nano/src/persistence.rs:7483`.
#[cfg(feature = "db")]
pub async fn resolve_challenge(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveChallengeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let new_status = if req.approved { "approved" } else { "denied" };

    let updated: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE claims SET \
            properties = jsonb_set(properties, '{status}', to_jsonb($2::text), true), \
            updated_at = NOW() \
         WHERE id = $1 AND 'policy:challenge' = ANY(labels) \
         RETURNING id",
    )
    .bind(id)
    .bind(new_status)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to resolve challenge: {e}"),
    })?;

    if updated.is_none() {
        return Err(ApiError::NotFound {
            resource: format!("policy-challenge {id}"),
        });
    }

    if !req.approved {
        // Strengthen the default-deny policy claim. Identified by host='*'
        // in properties; matches the nano sentinel.
        sqlx::query(
            "UPDATE claims SET \
                truth_value = LEAST(0.99, truth_value + 0.03), \
                updated_at = NOW() \
             WHERE 'policy:active' = ANY(labels) \
               AND properties->>'host' = '*'",
        )
        .execute(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to strengthen default-deny: {e}"),
        })?;
    }

    Ok(Json(serde_json::json!({
        "id": id,
        "status": new_status,
    })))
}
```

If `crate::routes::workflows::get_or_create_system_agent` is private, change its visibility to `pub(crate)` in `workflows.rs:863` (search for `async fn get_or_create_system_agent`).

- [ ] **Step 5.5.4: Register the routes**

```rust
        .route("/api/v1/policy-challenges", post(policies::create_challenge))
        .route("/api/v1/policy-challenges/:id", get(policies::get_challenge))
        .route("/api/v1/policy-challenges/:id/resolve", post(policies::resolve_challenge))
```

- [ ] **Step 5.5.5: Run all tests, commit**

```bash
cargo test -p epigraph-api --features db \
    create_challenge_returns_id_and_persists_pending \
    get_challenge_returns_404_when_not_a_challenge \
    resolve_challenge_denied_strengthens_default_deny
```

Expected: 3 PASSes.

```bash
git add crates/epigraph-api/src/routes/policies.rs \
        crates/epigraph-api/src/routes/mod.rs \
        crates/epigraph-api/src/routes/workflows.rs
git commit -m "feat(api): policy-challenge endpoints (create/get/resolve) (#28)"
```

---

## Phase 6 — Issue #32: Ed25519 signature verification

**Why sixth (security-sensitive, last among substantive phases):** This is the only phase that can fail-open if implemented sloppily. Lands after the smaller endpoints so a security review can focus on this single PR. Required pieces already exist: `SignatureVerifier::verify` in `epigraph-crypto`, agent public keys in `agents.public_key`, `validate_packet` is currently sync — needs to become async.

**Approach:** Make verification mandatory whenever a `signature` is present (issue's option (a)). Make `validate_packet` async. Fetch the agent's public key by `packet.claim.agent_id`. Recompute canonical bytes. Verify. Reject only on `Ok(false)` from the verifier.

### Task 6.1: Make `validate_packet` async, fetch pubkey, verify

**Files:**
- Modify: `crates/epigraph-api/src/routes/submit.rs` (`validate_packet` signature + body around line 326 and 660)

- [ ] **Step 6.1.1: Write the failing test**

In `crates/epigraph-api/src/routes/submit.rs`, find the existing test module (`#[cfg(test)] mod tests`). Add:

```rust
#[tokio::test]
async fn submit_with_valid_signature_succeeds() {
    let state = test_state_with_required_signatures().await;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let agent_id = seed_agent_with_pubkey(&state, signing_key.verifying_key().to_bytes()).await;

    let claim = build_test_claim(agent_id, "Verifiable claim content.");
    let canonical = canonical_packet_bytes(&claim, /* evidence */ &[], /* trace */ &());
    let signature = signing_key.sign(&canonical);

    let packet = build_packet(claim, signature.to_bytes());

    let response = submit_endpoint(state, packet).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn submit_with_invalid_signature_returns_401() {
    let state = test_state_with_required_signatures().await;
    let real_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let attacker_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let agent_id = seed_agent_with_pubkey(&state, real_key.verifying_key().to_bytes()).await;

    let claim = build_test_claim(agent_id, "Forged content.");
    let canonical = canonical_packet_bytes(&claim, &[], &());
    let bad_signature = attacker_key.sign(&canonical); // wrong key

    let packet = build_packet(claim, bad_signature.to_bytes());
    let response = submit_endpoint(state, packet).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn submit_with_unknown_agent_id_returns_401() {
    let state = test_state_with_required_signatures().await;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let unknown_agent = AgentId::new(); // never inserted

    let claim = build_test_claim(unknown_agent, "Orphan claim.");
    let canonical = canonical_packet_bytes(&claim, &[], &());
    let signature = signing_key.sign(&canonical);

    let packet = build_packet(claim, signature.to_bytes());
    let response = submit_endpoint(state, packet).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
```

`canonical_packet_bytes` must produce **exactly** the same bytes that the server's verifier will reconstruct. Search the existing codebase for the canonicalization helper used at submit time (likely something via `epigraph-crypto::canonical::Canonical` trait or a `to_canonical_bytes` method on the packet types). Use that helper directly — never reimplement the canonical layout in the test, or you'll silently test the wrong thing.

- [ ] **Step 6.1.2: Run the tests to confirm they fail**

```bash
cargo test -p epigraph-api --features db submit_with_valid_signature_succeeds submit_with_invalid_signature_returns_401 submit_with_unknown_agent_id_returns_401
```

Expected: 3 FAILs (all returning 401 today regardless of signature validity).

- [ ] **Step 6.1.3: Make `validate_packet` async and accept a pool**

In `crates/epigraph-api/src/routes/submit.rs:325-340`, change:

```rust
fn validate_packet(
    packet: &EpistemicPacket,
    state: &AppState,
) -> Result<(), (StatusCode, ErrorResponse)> {
```

to:

```rust
async fn validate_packet(
    packet: &EpistemicPacket,
    state: &AppState,
) -> Result<(), (StatusCode, ErrorResponse)> {
```

Then update the single caller of `validate_packet` (search the file: there's exactly one) to `.await` the call.

- [ ] **Step 6.1.4: Replace the signature-verification stub**

Find the block at `submit.rs:660-676` starting with `// TODO(security): Implement Ed25519 signature verification here.` and ending with the `return Err((StatusCode::UNAUTHORIZED, ...));`. Replace the entire block with:

```rust
        // Look up the claim agent's public key.
        let agent_id: Uuid = packet.claim.agent_id.into();
        let pub_key_row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT public_key FROM agents WHERE id = $1",
        )
        .bind(agent_id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::with_details(
                    "InternalError",
                    "Failed to look up agent public key",
                    serde_json::json!({ "error": e.to_string() }),
                ),
            )
        })?;

        let pub_key_bytes: [u8; 32] = pub_key_row
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    ErrorResponse::with_details(
                        "SignatureError",
                        "Agent not registered",
                        serde_json::json!({ "field": "claim.agent_id" }),
                    ),
                )
            })?
            .0
            .try_into()
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::with_details(
                        "InternalError",
                        "Stored public key has wrong length",
                        serde_json::json!({}),
                    ),
                )
            })?;

        // Decode the hex signature.
        let mut sig_bytes = [0u8; 64];
        hex::decode_to_slice(&packet.signature, &mut sig_bytes).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::with_details(
                    "SignatureError",
                    "Signature contains invalid hex characters",
                    serde_json::json!({ "field": "signature" }),
                ),
            )
        })?;

        // Recompute the canonical bytes the client should have signed.
        // NOTE: must match exactly what the SDK signs over.
        let canonical = packet.canonical_bytes_for_signature().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::with_details(
                    "InternalError",
                    "Failed to canonicalize packet for verification",
                    serde_json::json!({ "error": e.to_string() }),
                ),
            )
        })?;

        match epigraph_crypto::SignatureVerifier::verify(&pub_key_bytes, &canonical, &sig_bytes) {
            Ok(true) => { /* fall through */ }
            Ok(false) | Err(_) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    ErrorResponse::with_details(
                        "SignatureError",
                        "Signature verification failed",
                        serde_json::json!({ "field": "signature" }),
                    ),
                ));
            }
        }
    }

    Ok(())
}
```

If `EpistemicPacket::canonical_bytes_for_signature` does not exist, search the file for how the SDK is *expected* to canonicalize (look for `Canonical` trait impls on `EpistemicPacket`, or the field-by-field byte concatenation pattern used elsewhere). Whatever the SDK signs is what the server must verify. If it's not implemented anywhere, **stop and surface this back to the user before proceeding** — silently inventing a canonicalization scheme would create a permanent compatibility break.

- [ ] **Step 6.1.5: Add `hex` to api crate deps if missing**

```bash
grep -A1 '^hex' crates/epigraph-api/Cargo.toml || cargo add --package epigraph-api hex
```

- [ ] **Step 6.1.6: Run the tests to confirm they pass**

```bash
cargo test -p epigraph-api --features db submit_with_valid_signature_succeeds submit_with_invalid_signature_returns_401 submit_with_unknown_agent_id_returns_401
```

Expected: 3 PASSes. If `submit_with_valid_signature_succeeds` fails with a 401, the canonicalization in the test does not match the server's canonicalization — fix the test (use the same helper the SDK uses), not the verifier.

- [ ] **Step 6.1.7: Run the full submit test suite to catch regressions**

```bash
cargo test -p epigraph-api --features db submit
```

Expected: all PASS.

- [ ] **Step 6.1.8: Commit**

```bash
git add crates/epigraph-api/src/routes/submit.rs crates/epigraph-api/Cargo.toml
git commit -m "fix(security): implement Ed25519 signature verification in submit_packet (#32)"
```

---

## Phase 7 — Issue #19: `?relationships=` query param on graph endpoints

**Why last:** Quality-of-life. References #13/#18 (already merged via PR #23). Adds an opt-in override of the `GRAPH_VIEW_RELATIONSHIPS` allowlist. ~50 LOC.

### Task 7.1: Add `relationships` to `NeighborhoodParams` and `ExpandParams`

**Files:**
- Modify: `crates/epigraph-api/src/routes/graph.rs:135-160` (param structs), `:344-380` (`fetch_subgraph_edges`)

- [ ] **Step 7.1.1: Write the failing test**

In `graph.rs`'s test module:

```rust
#[tokio::test]
async fn neighborhood_relationships_param_overrides_allowlist() {
    let state = test_state().await;
    let (a, b) = seed_two_claims(&state).await;
    seed_edge(&state, a, b, "produced").await; // intentionally NOT in default allowlist

    let router = graph_router(state);
    // Without relationships override: edge is filtered.
    let response = router.clone()
        .oneshot(neighborhood_request(a, None))
        .await
        .unwrap();
    let body: serde_json::Value = parse_body(response).await;
    assert_eq!(body["edges"].as_array().unwrap().len(), 0);
    assert_eq!(body["filtered_edge_count"], 1);

    // With relationships=produced: edge is returned.
    let response = router
        .oneshot(neighborhood_request(a, Some("produced")))
        .await
        .unwrap();
    let body: serde_json::Value = parse_body(response).await;
    assert_eq!(body["edges"].as_array().unwrap().len(), 1);
    assert_eq!(body["edges"][0]["relationship"], "produced");
}
```

- [ ] **Step 7.1.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-api --features db neighborhood_relationships_param_overrides_allowlist
```

Expected: FAIL — query param ignored, edges still filtered.

- [ ] **Step 7.1.3: Add the field to both param structs**

In `crates/epigraph-api/src/routes/graph.rs`, find `NeighborhoodParams` (~line 142) and `ExpandParams` (~line 134). Add to each:

```rust
    /// Override the default relationship allowlist for this request.
    /// Comma-separated list of relationship strings, or "*" / "all" for no filter.
    /// When absent, uses `GRAPH_VIEW_RELATIONSHIPS`.
    #[serde(default)]
    pub relationships: Option<String>,
```

- [ ] **Step 7.1.4: Resolve the effective allowlist in handlers**

Add a helper near the top of `graph.rs` (right under `GRAPH_VIEW_RELATIONSHIPS`):

```rust
/// Resolve the effective relationship allowlist for a single request.
///
/// `None` → default (`GRAPH_VIEW_RELATIONSHIPS`).
/// `Some("*")` or `Some("all")` → returns `None` (caller treats as "no filter").
/// Otherwise → comma-split, trimmed, non-empty entries.
fn resolve_relationship_filter(override_param: Option<&str>) -> Option<Vec<String>> {
    match override_param {
        None => Some(GRAPH_VIEW_RELATIONSHIPS.iter().map(|s| (*s).to_string()).collect()),
        Some(s) if s == "*" || s.eq_ignore_ascii_case("all") => None,
        Some(s) => Some(
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        ),
    }
}
```

Update `fetch_subgraph_edges` to accept `Option<&[String]>`:

```rust
async fn fetch_subgraph_edges(
    pool: &PgPool,
    node_ids: &[Uuid],
    rel_list: Option<&[String]>,
) -> Result<(Vec<EdgeOut>, i64), (axum::http::StatusCode, String)> {
    if node_ids.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let rows: Vec<(Uuid, Uuid, String, bool)> = match rel_list {
        Some(allowlist) => sqlx::query_as(
            "SELECT source_id, target_id, relationship, \
                    (relationship = ANY($2)) AS is_allowed \
             FROM edges \
             WHERE source_id = ANY($1) AND target_id = ANY($1)",
        )
        .bind(node_ids)
        .bind(allowlist)
        .fetch_all(pool)
        .await,
        None => sqlx::query_as(
            "SELECT source_id, target_id, relationship, true AS is_allowed \
             FROM edges \
             WHERE source_id = ANY($1) AND target_id = ANY($1)",
        )
        .bind(node_ids)
        .fetch_all(pool)
        .await,
    }
    .map_err(internal)?;

    let mut edges = Vec::new();
    let mut filtered: i64 = 0;
    for (source, target, relationship, is_allowed) in rows {
        if is_allowed {
            edges.push(EdgeOut { source, target, relationship });
        } else {
            filtered += 1;
        }
    }
    Ok((edges, filtered))
}
```

Update both callers (`expand` and `neighborhood`) to thread the param:

```rust
let allowlist = resolve_relationship_filter(params.relationships.as_deref());
let (edges, filtered_edge_count) =
    fetch_subgraph_edges(pool, &node_ids, allowlist.as_deref()).await?;
```

(Keep the existing `&[&str]` ↔ `&[String]` distinction — `Option<&[String]>` is what `rel_list` becomes.)

- [ ] **Step 7.1.5: Run the test to confirm it passes**

```bash
cargo test -p epigraph-api --features db neighborhood_relationships_param_overrides_allowlist
```

Expected: PASS.

- [ ] **Step 7.1.6: Run the full graph test suite for regressions**

```bash
cargo test -p epigraph-api --features db graph
```

Expected: all PASS.

- [ ] **Step 7.1.7: Commit**

```bash
git add crates/epigraph-api/src/routes/graph.rs
git commit -m "feat(api): add ?relationships= override to graph endpoints (#19)"
```

---

## Wrap-up

- [ ] **Step W.1: Run the full workspace test suite**

```bash
cargo test --workspace --features db
```

Expected: all PASS. Failures unrelated to this branch's commits should be flagged but not blockers (check `git log origin/main..HEAD` versus the failure to determine ownership).

- [ ] **Step W.2: Run linting**

```bash
cargo clippy --workspace --features db --all-targets -- -D warnings
cargo fmt --all --check
```

Expected: no warnings, no formatting diffs.

- [ ] **Step W.3: Open the PR**

```bash
gh pr create --base main --title "feat: address open issues #19, #28-#33" --body "$(cat <<'EOF'
## Summary

Closes:
- #30 — Persist `PlannedClaim.properties` to `claims.properties`
- #29 — Drop self-loop `decomposes_to` edges from compound==atom dedup
- #33 — Add `exclude_agent_id` filter to `GET /api/v1/claims`
- #31 — Add `GET /api/v1/workflows/:id`
- #28 — Policy + policy-challenge endpoints
- #32 — Implement Ed25519 signature verification in `submit_packet`
- #19 — Add `?relationships=` override to graph endpoints

Each issue is a separate commit so it can be cherry-picked or reverted independently.

## Test plan

- [ ] `cargo test --workspace --features db` passes
- [ ] Manual sanity ingest of one wiki paper, then verify `SELECT count(*) FROM claims WHERE properties::text != '{}'` is non-zero
- [ ] Manual `curl` exercise of each new endpoint against a dev DB
- [ ] Manual signed-submit test using a known dev agent's keypair
EOF
)"
```

---

## Self-review checklist

After implementing, run through this:

- [ ] Phase 1: `properties` column populated on every new claim — verified via SQL.
- [ ] Phase 2: Re-ingesting the wrhq compound==atom JSON returns Ok and creates 0 self-loop edges.
- [ ] Phase 3: `?exclude_agent_id=...` composes with `?agent_id=...` (both set behaves as filter-in-then-filter-out).
- [ ] Phase 4: 404 on a non-workflow claim, 200 on a workflow.
- [ ] Phase 5: All seven policy queries exercised; default-deny strengthening only fires on `approved=false`.
- [ ] Phase 6: A signed submit with a *correct* signature succeeds; an *incorrect* one returns 401; an unknown agent returns 401.
- [ ] Phase 7: Default behavior unchanged (no `?relationships` → same response as before); `?relationships=*` returns previously-filtered edges.

If any of these fail, do not merge. Fix and re-test.
