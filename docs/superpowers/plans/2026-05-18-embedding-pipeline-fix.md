# Embedding Pipeline Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the embedding gap (6.33% and growing, backlog `92eedc8b`) by fixing every claim-write path that bypasses the embedder, and enforcing the `is_current=false → no embedding` invariant in every supersession path. Document the contract in `CLAUDE.md` so future write paths are auditable.

**Architecture:** Four discrete fixes, each scoped to one or two files:

1. `POST /api/v1/claims` (the source of the post-2026-04-30 explosion in the gap since `epiclaw-host` migrated to HTTP) must embed inline post-commit, best-effort, matching the existing `POST /api/v1/submit/packet` pattern.
2. `ClaimRepository::mark_duplicate` must null the duplicate's embedding inside its existing transaction, matching `ClaimRepository::supersede`.
3. `epigraph-ingest-executor` (which uses raw `INSERT INTO claims` and has no embedder dependency) returns the inserted claim ids+content so each caller embeds with its own embedder. The MCP caller uses `server.embedder.embed_and_store`; the HTTP route uses `state.embedding_service()`.
4. A new `## Embedding policy` section in `CLAUDE.md` documents the four write paths, the two is_current=false cleanup paths, and how to audit future code.

The 26.7k existing un-embedded claims and the missing `backfill_embeddings.py` are out of scope — filed as follow-up in the postscript.

**Tech stack:** Rust, axum, sqlx, pgvector, OpenAI embeddings (via `epigraph-embeddings::EmbeddingService` in the HTTP API and `McpEmbedder` in MCP).

---

## File Structure

**Modified:**
- `crates/epigraph-api/src/routes/claims.rs` — embed inline in `create_claim` (line 293, after `tx.commit()` at line 562)
- `crates/epigraph-db/src/repos/claim.rs` — null embedding inside `mark_duplicate` tx (line 2076)
- `crates/epigraph-ingest-executor/src/workflow.rs` — return `Vec<(Uuid, String)>` of newly inserted claim ids+content (currently only counts)
- `crates/epigraph-ingest-executor/src/workflow_steps.rs` — same for `add_step`
- `crates/epigraph-mcp/src/tools/workflow_ingest.rs` — iterate executor output, call `server.embedder.embed_and_store`
- `crates/epigraph-mcp/src/tools/step_ops.rs` — same for `add_step`
- `crates/epigraph-api/src/routes/workflows.rs` — same for the two `execute_workflow_ingest_plan` callsites (line 225, line 1196)
- `CLAUDE.md` — append `## Embedding policy` section

**Created:**
- `crates/epigraph-api/tests/integration/embed_on_create_claim.rs` — verifies `POST /api/v1/claims` embeds via mocked `EmbeddingService`
- `crates/epigraph-db/tests/mark_duplicate_nulls_embedding.rs` — verifies cleanup
- `crates/epigraph-ingest-executor/tests/workflow_ingest_returns_inserted.rs` — verifies the executor surfaces ids+content for caller-side embedding

---

## Task 1: `POST /api/v1/claims` embeds inline (HTTP path leak)

**Files:**
- Modify: `crates/epigraph-api/src/routes/claims.rs:560-644` (after `tx.commit()`)
- Test: `crates/epigraph-api/tests/integration/embed_on_create_claim.rs` (new)

The HTTP route never invoked `state.embedding_service()`. Pattern to copy is `crates/epigraph-api/src/routes/submit.rs:1480-1531`.

- [ ] **Step 1: Write the failing integration test**

Create `crates/epigraph-api/tests/integration/embed_on_create_claim.rs`:

```rust
//! POST /api/v1/claims must embed the claim inline post-commit, best-effort.
//! Regression guard for backlog item 92eedc8b (embedding gap).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use epigraph_api::{create_router, state::AppState, ApiConfig};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn create_claim_embeds_inline(pool: PgPool) {
    let provider = MockProvider::new(EmbeddingConfig::local(1536));
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state = AppState::with_db(pool.clone(), ApiConfig::default())
        .with_embedding_service(service.clone());
    let app = create_router(state);

    // Create an agent row the route can reference.
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind([0u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    let body = json!({
        "agent_id": agent_id,
        "content": "regression: embedding must be populated on create",
        "privacy_tier": "public",
        "initial_truth": 0.5,
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/claims")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let claim_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

    let has_embedding: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(has_embedding, "claim {claim_id} should have embedding populated by create_claim");
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-api --test embed_on_create_claim --features db
```

Expected: FAIL with `has_embedding == false`.

- [ ] **Step 3: Add the embed block after commit in `create_claim`**

In `crates/epigraph-api/src/routes/claims.rs`, immediately after the `tx.commit()` block at line 560-562 and before the `EdgeRepository::create` AUTHORED call at line 565, insert:

```rust
    // Embed inline, best-effort. Mirrors POST /api/v1/submit/packet
    // (routes/submit.rs:1480-1507). Failures are warned but never fail the
    // claim create — embedding is recoverable via backfill; the claim is not.
    // Skip embedding when privacy_tier != "public" — encrypted/fully_private
    // claims have placeholder or ciphertext content that wouldn't yield a
    // useful semantic vector.
    if privacy_tier == "public" {
        if let Some(embedder) = state.embedding_service() {
            match embedder.generate(&request.content).await {
                Ok(embedding) => {
                    let pgvector_str = format!(
                        "[{}]",
                        embedding.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")
                    );
                    if let Err(e) = sqlx::query(
                        "UPDATE claims SET embedding = $1::vector WHERE id = $2",
                    )
                    .bind(&pgvector_str)
                    .bind(claim_uuid)
                    .execute(&state.db_pool)
                    .await
                    {
                        tracing::warn!(
                            claim_id = %claim_uuid,
                            error = %e,
                            "Failed to store embedding on create_claim"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        claim_id = %claim_uuid,
                        error = %e,
                        "Failed to generate embedding on create_claim"
                    );
                }
            }
        } else {
            tracing::debug!(
                claim_id = %claim_uuid,
                "embedding_service not configured; create_claim skipping embed"
            );
        }
    }
```

- [ ] **Step 4: Re-run the test**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-api --test embed_on_create_claim --features db
```

Expected: PASS.

- [ ] **Step 5: Verify the rest of `epigraph-api` still compiles + tests pass**

```bash
SQLX_OFFLINE=true cargo check -p epigraph-api --features db
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-api --features db
```

Expected: clean build, existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-api/src/routes/claims.rs crates/epigraph-api/tests/integration/embed_on_create_claim.rs
git commit -m "fix(api): embed inline in POST /api/v1/claims (closes 92eedc8b)"
```

---

## Task 2: `mark_duplicate` nulls the embedding (is_current=false invariant)

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs:2076-2124`
- Test: `crates/epigraph-db/tests/mark_duplicate_nulls_embedding.rs` (new)

`supersede` already nulls embedding at line 1401. `mark_duplicate` flips `is_current=false` but leaves the embedding live, so the duplicate keeps showing up in `recall()`/semantic search.

- [ ] **Step 1: Write the failing test**

Create `crates/epigraph-db/tests/mark_duplicate_nulls_embedding.rs`:

```rust
//! mark_duplicate must null the duplicate's embedding so superseded claims
//! drop out of semantic search. Mirrors supersede() at claim.rs:1401.

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_nulls_embedding(pool: PgPool) {
    // Seed one agent row.
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind([0u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    // Seed two claim rows directly via SQL — bypasses any cross-crate helper
    // churn. Both get a stub embedding; we use a tiny 3-dim vector because the
    // column accepts any pgvector dim (prod is 1536/3072; size is irrelevant
    // for the null-on-mark_duplicate behavior under test).
    let canonical_id = Uuid::new_v4();
    let dup_id = Uuid::new_v4();
    let stub_vec = "[0.1,0.2,0.3]";
    for (id, content) in [(canonical_id, "canonical"), (dup_id, "duplicate")] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding) \
             VALUES ($1, $2, $3, $4, 0.5, $5::vector)",
        )
        .bind(id)
        .bind(content)
        .bind(blake3::hash(content.as_bytes()).as_bytes().as_slice())
        .bind(agent_id)
        .bind(stub_vec)
        .execute(&pool)
        .await
        .unwrap();
    }

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup_id),
        ClaimId::from_uuid(canonical_id),
    )
    .await
    .unwrap();

    let dup_has_embedding: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(dup_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let canon_has_embedding: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(canonical_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(!dup_has_embedding, "duplicate {dup_id} embedding should be NULL after mark_duplicate");
    assert!(canon_has_embedding, "canonical {canonical_id} embedding must be preserved");
}
```

> **Note:** If the `claims` table has additional NOT NULL columns the test INSERT doesn't supply, add them — read `migrations/001_initial_schema.sql` for the canonical column list. Common required additions: `created_at` (usually has a default), `is_current` (usually defaults to `true`).

- [ ] **Step 2: Run the test to verify it fails**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-db --test mark_duplicate_nulls_embedding
```

Expected: FAIL with `!dup_has_embedding` assertion (embedding still set).

- [ ] **Step 3: Add the null-embedding UPDATE inside the existing tx**

In `crates/epigraph-db/src/repos/claim.rs`, modify the `mark_duplicate` body (line 2118-2122). Replace:

```rust
        sqlx::query(
            "UPDATE claims SET supersedes = $1, is_current = false, updated_at = NOW() WHERE id = $2",
        )
        .bind(canon_uuid).bind(dup_uuid).execute(&mut *tx).await?;
        tx.commit().await?;
```

with:

```rust
        sqlx::query(
            "UPDATE claims SET supersedes = $1, is_current = false, updated_at = NOW() WHERE id = $2",
        )
        .bind(canon_uuid).bind(dup_uuid).execute(&mut *tx).await?;

        // is_current=false invariant: drop the duplicate from semantic search.
        // Mirrors supersede() at line 1401. See CLAUDE.md "Embedding policy".
        sqlx::query("UPDATE claims SET embedding = NULL WHERE id = $1")
            .bind(dup_uuid)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
```

- [ ] **Step 4: Re-run the test**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-db --test mark_duplicate_nulls_embedding
```

Expected: PASS.

- [ ] **Step 5: Run the epigraph-db test suite to confirm no regression**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-db
```

Expected: existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs crates/epigraph-db/tests/mark_duplicate_nulls_embedding.rs
git commit -m "fix(db): mark_duplicate nulls embedding to enforce is_current=false invariant"
```

---

## Task 3: `epigraph-ingest-executor` surfaces inserted ids+content for caller-side embed

The executor owns raw `INSERT INTO claims` calls but has no embedder dependency (and shouldn't — it's pure-DB by design). Add a return value listing `(claim_id, content)` for every newly inserted claim so each caller embeds in its own context using its own embedder (MCP: `McpEmbedder`; HTTP: `dyn EmbeddingService`).

### Task 3a: `execute_workflow_ingest_plan` returns inserted ids+content

**Files:**
- Modify: `crates/epigraph-ingest-executor/src/workflow.rs:22-39` (extend `WorkflowIngestExecutionResult`)
- Modify: `crates/epigraph-ingest-executor/src/workflow.rs:156-225` (capture id+content during the walk)
- Test: `crates/epigraph-ingest-executor/tests/workflow_ingest_returns_inserted.rs` (new)

- [ ] **Step 1: Write the failing test**

Create `crates/epigraph-ingest-executor/tests/workflow_ingest_returns_inserted.rs`:

```rust
//! execute_workflow_ingest_plan must return (claim_id, content) for every
//! newly inserted claim so callers can embed them. Regression guard for the
//! is_current=true → has-embedding invariant (CLAUDE.md "Embedding policy").

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use sqlx::PgPool;

fn build_extraction(canonical_name: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: "verify executor surfaces (id, content) for caller-side embed".into(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("Executor must surface inserts for embedding".into()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase 1".into(),
            summary: "Single phase with one step and two operations".into(),
            steps: vec![Step {
                compound: "Invoke executor and check returned inserts".into(),
                rationale: "Embedding contract".into(),
                operations: vec![
                    "Call execute_workflow_ingest_plan".into(),
                    "Assert result.inserted contains every inserted claim".into(),
                ],
                generality: vec![2, 1],
                confidence: 0.9,
            }],
        }],
        relationships: vec![],
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_inserted_claim_ids_and_content(pool: PgPool) {
    let extraction = build_extraction("executor-embed-surfacing-test");
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let planned_count = plan.claims.len();
    assert!(planned_count > 0, "fixture should produce at least one planned claim");

    // First run: every planned claim is newly inserted and must be surfaced.
    let r1 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("first call");
    assert!(!r1.already_ingested);
    assert_eq!(r1.claims_ingested, planned_count);
    assert_eq!(
        r1.inserted.len(),
        planned_count,
        "executor must surface (id, content) for every newly inserted claim"
    );
    // Cross-check content matches the planned input order-insensitively.
    let planned_contents: std::collections::HashSet<&str> =
        plan.claims.iter().map(|c| c.content.as_str()).collect();
    for (id, content) in &r1.inserted {
        assert!(planned_contents.contains(content.as_str()), "{id} content mismatch");
    }

    // Second run: idempotency gate fires; no new surfacing.
    let r2 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("second call");
    assert!(r2.already_ingested);
    assert!(r2.inserted.is_empty(), "idempotent re-run must surface no new inserts");
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-ingest-executor --test workflow_ingest_returns_inserted
```

Expected: compile failure (`inserted` field does not exist on `WorkflowIngestExecutionResult`).

- [ ] **Step 3: Extend the result struct**

In `crates/epigraph-ingest-executor/src/workflow.rs`, modify `WorkflowIngestExecutionResult` (line 22-39). Add one field:

```rust
pub struct WorkflowIngestExecutionResult {
    pub workflow_id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub claims_ingested: usize,
    pub claims_skipped_dedup: usize,
    pub executes_edges_created: usize,
    pub variant_of_edge_created: bool,
    pub relationship_edges_created: usize,
    pub already_ingested: bool,
    /// (claim_id, content) for every newly inserted claim in this run.
    /// Empty on idempotent re-ingest. Callers embed these to satisfy the
    /// is_current=true → has-embedding invariant; see CLAUDE.md
    /// "Embedding policy".
    pub inserted: Vec<(Uuid, String)>,
}
```

Update both `Ok(...)` returns to include the new field:

- The early-return at line 72-83 (idempotency-gate short-circuit) gets `inserted: Vec::new(),`.
- The final return at line 281-291 gets `inserted,` (variable populated in Step 4).

- [ ] **Step 4: Capture id+content during the walk**

In `crates/epigraph-ingest-executor/src/workflow.rs`, in the claim-walk loop (line 156-225), add a vector alongside the existing counters at line 157-159:

```rust
    let mut claims_ingested = 0_usize;
    let mut claims_skipped_dedup = 0_usize;
    let mut inserted: Vec<(Uuid, String)> = Vec::new();
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();
```

Then on the `was_new` success branch, after `claims_ingested += 1;` at line 219, push:

```rust
            claims_ingested += 1;
            inserted.push((planned.id, planned.content.clone()));
```

The `planned` variable is the loop binding from line 161; `planned.id` is the claim UUID and `planned.content` is the text.

- [ ] **Step 5: Re-run the test**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-ingest-executor --test workflow_ingest_returns_inserted
```

Expected: PASS.

- [ ] **Step 6: Run sqlx prepare**

If you added/changed any `sqlx::query!`/`query_as!` macros, run:

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo sqlx prepare --workspace -- --tests
git add .sqlx/
```

If you only used the non-macro `sqlx::query(...)` form, skip this step.

- [ ] **Step 7: Commit**

```bash
git add crates/epigraph-ingest-executor/src/workflow.rs \
        crates/epigraph-ingest-executor/tests/workflow_ingest_returns_inserted.rs
git commit -m "feat(ingest-executor): surface inserted (id, content) for caller-side embed"
```

### Task 3b: `add_step` returns inserted id+content

**Files:**
- Modify: `crates/epigraph-ingest-executor/src/workflow_steps.rs:17` (extend `AddStepResult`)
- Modify: `crates/epigraph-ingest-executor/src/workflow_steps.rs:180-223` (capture on insert)

- [ ] **Step 1: Extend `AddStepResult`**

In `crates/epigraph-ingest-executor/src/workflow_steps.rs`, modify `AddStepResult` (line 22-32). Add one field:

```rust
#[derive(Debug, Clone)]
pub struct AddStepResult {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_index: u32,
    pub step_lineage_id: Uuid,
    pub already_present: bool,
    /// Content of the step claim if this call inserted a new row;
    /// `None` if the step was already present (idempotent re-add). The
    /// caller embeds when `Some(_)`; see CLAUDE.md "Embedding policy".
    pub inserted_content: Option<String>,
}
```

- [ ] **Step 2: Capture content on the insert path**

In the same file, the idempotent early-return at lines 189-195 returns `AddStepResult { workflow_id, step_claim_id, step_index, step_lineage_id, already_present: true }`. Add `inserted_content: None,` to that struct literal.

The insert path that runs the `INSERT INTO claims` at line 206-223 builds a final `AddStepResult` further down the function. Find that final return and add `inserted_content: Some(step_text.to_string()),` — `step_text` is the function parameter holding the new step's text.

- [ ] **Step 3: Build check**

```bash
SQLX_OFFLINE=true cargo check -p epigraph-ingest-executor
```

Expected: clean build (existing test `crates/epigraph-ingest-executor/tests/lineage_assignment.rs` may need `inserted_content: None` added to its destructuring — fix if so).

- [ ] **Step 4: Run existing executor tests**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-ingest-executor
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-ingest-executor/src/workflow_steps.rs
git commit -m "feat(ingest-executor): surface inserted_content from add_step"
```

### Task 3c: MCP callers embed the executor output

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflow_ingest.rs` (around line 54)
- Modify: `crates/epigraph-mcp/src/tools/step_ops.rs` (search for `add_step` calls)

- [ ] **Step 1: Embed in `workflow_ingest`**

In `crates/epigraph-mcp/src/tools/workflow_ingest.rs`, after the `execute_workflow_ingest_plan` call returns `result` (around line 54), add:

```rust
    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Failures warn and continue —
    // embedding is recoverable via backfill; the workflow ingest is not.
    for (claim_id, content) in &result.inserted {
        let _ = server.embedder.embed_and_store(*claim_id, content).await;
    }
```

- [ ] **Step 2: Embed in `step_ops::add_step`**

In `crates/epigraph-mcp/src/tools/step_ops.rs`, the executor call binds its result to `r` (line 66-73). After that block and before the `success_json(&AddStepResponse { ... })` return at line 74, insert:

```rust
    if let Some(ref content) = r.inserted_content {
        let _ = server
            .embedder
            .embed_and_store(r.step_claim_id, content)
            .await;
    }
```

- [ ] **Step 3: Build + test MCP**

```bash
SQLX_OFFLINE=true cargo check -p epigraph-mcp
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-mcp
```

Expected: clean build, existing tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/src/tools/workflow_ingest.rs crates/epigraph-mcp/src/tools/step_ops.rs
git commit -m "fix(mcp): embed inserted claims from ingest-executor (workflow_ingest, add_step)"
```

### Task 3d: HTTP API callers embed the executor output

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs:225` (one callsite)
- Modify: `crates/epigraph-api/src/routes/workflows.rs:1196` (second callsite)

- [ ] **Step 1: Embed at both `execute_workflow_ingest_plan` callsites**

After each call to `epigraph_ingest_executor::execute_workflow_ingest_plan` that returns `result`, add the embed block. The pattern (re-using the helper from Task 1 if extracted; otherwise inline):

```rust
    if let Some(embedder) = state.embedding_service() {
        for (claim_id, content) in &result.inserted {
            match embedder.generate(content).await {
                Ok(embedding) => {
                    let pgvector_str = format!(
                        "[{}]",
                        embedding.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")
                    );
                    if let Err(e) = sqlx::query(
                        "UPDATE claims SET embedding = $1::vector WHERE id = $2",
                    )
                    .bind(&pgvector_str)
                    .bind(*claim_id)
                    .execute(&state.db_pool)
                    .await
                    {
                        tracing::warn!(claim_id = %claim_id, error = %e, "Failed to store embedding for ingested workflow claim");
                    }
                }
                Err(e) => {
                    tracing::warn!(claim_id = %claim_id, error = %e, "Failed to generate embedding for ingested workflow claim");
                }
            }
        }
    }
```

Apply this block immediately after both `execute_workflow_ingest_plan` callsites (line 225 region and line 1196 region).

- [ ] **Step 2: Build + test API**

```bash
SQLX_OFFLINE=true cargo check -p epigraph-api --features db
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-api --features db
```

Expected: clean build, existing tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-api/src/routes/workflows.rs
git commit -m "fix(api): embed inserted claims at execute_workflow_ingest_plan callsites"
```

---

## Task 4: `CLAUDE.md` documents the embedding policy

**Files:**
- Modify: `CLAUDE.md` (append at end)

- [ ] **Step 1: Append `## Embedding policy` section**

Append to `CLAUDE.md`:

```markdown

## Embedding policy

**Invariant:** every claim with `is_current = true` should have an embedding;
every claim with `is_current = false` should have `embedding = NULL`. Semantic
recall (`recall()`, `recall_with_context()`, `theme_cluster`, `find_workflow`'s
semantic path) reads from `embedding`, so violations either hide live claims
or surface stale ones.

### Write paths (must embed on insert)

When adding a new code path that inserts a claim, embed inline post-commit,
best-effort (warn on failure, never block the write). Current call-sites:

- **MCP `submit_claim`** — `crates/epigraph-mcp/src/tools/claims.rs:217`
- **MCP `memorize`** — `crates/epigraph-mcp/src/tools/memory.rs:103`
- **MCP `batch_submit_claims`** — delegates to `submit_claim`
- **MCP `ingest_document`** — `crates/epigraph-mcp/src/tools/ingestion.rs:321`
- **MCP `workflow_ingest`** — embeds executor output; `crates/epigraph-mcp/src/tools/workflow_ingest.rs`
- **MCP `add_step`** — embeds when `AddStepResult::inserted_content` is `Some`
- **HTTP `POST /api/v1/claims`** — `crates/epigraph-api/src/routes/claims.rs` (after `tx.commit()` in `create_claim`)
- **HTTP `POST /api/v1/submit/packet`** — `crates/epigraph-api/src/routes/submit.rs:1480`
- **HTTP `POST /api/v1/workflows/ingest`** (both callsites) — `crates/epigraph-api/src/routes/workflows.rs`

`epigraph-ingest-executor` is pure-DB and does **not** embed itself; it returns
`inserted: Vec<(Uuid, String)>` / `AddStepResult::inserted_content` so each
caller embeds with its own configured embedder.

### Cleanup paths (must null on `is_current = false`)

When superseding or otherwise flipping `is_current` to false, null the
embedding in the same transaction:

- **`ClaimRepository::supersede`** — `crates/epigraph-db/src/repos/claim.rs:1401`
- **`ClaimRepository::mark_duplicate`** — `crates/epigraph-db/src/repos/claim.rs:2076`

If you add a third path that flips `is_current = false`, add the matching
`UPDATE claims SET embedding = NULL WHERE id = $1` inside the same tx.

### Auditing the gap

```sql
SELECT COUNT(*) FILTER (WHERE is_current AND embedding IS NULL) AS live_missing,
       COUNT(*) FILTER (WHERE NOT is_current AND embedding IS NOT NULL) AS stale_present
FROM claims;
```

Both should trend toward zero. `live_missing` growing means a write path is
bypassing the embedder; `stale_present` growing means a cleanup path is
missing the null. Track via `system_stats` if exposed; otherwise spot-check.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude): embedding policy for is_current invariant + write/cleanup paths"
```

---

## Final verification

- [ ] **Step 1: Full workspace build + test**

```bash
SQLX_OFFLINE=true cargo check --workspace
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test --workspace
```

Expected: clean.

- [ ] **Step 2: Run the audit query against the dev DB**

```bash
psql "$EPIGRAPH_DATABASE_URL" -c "
SELECT COUNT(*) FILTER (WHERE is_current AND embedding IS NULL) AS live_missing,
       COUNT(*) FILTER (WHERE NOT is_current AND embedding IS NOT NULL) AS stale_present
FROM claims;
"
```

Record baseline. After the fix lands and a few hours of writes flow through,
`live_missing` should stop growing (existing 26.7k stays — covered by the
backfill follow-up below).

- [ ] **Step 3: Open PR**

Branch off `main`, push, and open with title:
`fix(embeddings): close write-path leaks + enforce is_current=false null`

Body should reference backlog item `92eedc8b` and list the four touched
subsystems (HTTP create_claim, mark_duplicate, ingest-executor surfacing,
CLAUDE.md policy).

- [ ] **Step 4: Retire the backlog item via `resolve_backlog_item`**

After merge:

```python
mcp__epigraph__resolve_backlog_item(
    original_id="92eedc8b-7017-4c7b-9e04-28c8fc27b6fa",
    resolution_content=(
        "Closed embedding write-path leaks: POST /api/v1/claims now embeds "
        "inline (matched submit/packet pattern); mark_duplicate now nulls "
        "embedding inside its tx (matched supersede); epigraph-ingest-executor "
        "surfaces inserted (id, content) for caller-side embed at MCP + HTTP "
        "callsites; CLAUDE.md documents the is_current invariant. Existing "
        "26.7k-claim backlog backfill is filed separately as the script "
        "referenced at routes/claims.rs:1177 does not exist."
    ),
)
```

---

## Follow-up (out of scope for this plan)

1. **One-shot backfill for the 26.7k existing un-embedded `is_current = true` claims.** The comment at `crates/epigraph-api/src/routes/claims.rs:1177` references `backfill_embeddings.py` — that script does not exist anywhere in `epigraph`, `epigraph-internal`, or `epiclaw-host`. File a new backlog item: write the script (or a Rust CLI under `crates/epigraph-cli/`) that pages `GET /api/v1/claims/needing-embeddings`, generates an embedding per claim, and POSTs back via the existing `embedding: Option<Vec<f32>>` field on `update_claim` at `routes/claims.rs:1177-1190`.
2. **Stale-embedding sweeper.** Daily job that runs `UPDATE claims SET embedding = NULL WHERE NOT is_current AND embedding IS NOT NULL` as a safety net for any future cleanup-path miss.
3. **Lift the inline-embed-on-create block in `routes/claims.rs` into a shared helper** (e.g. `crates/epigraph-api/src/services/embed.rs`) so the three HTTP callsites (`create_claim`, `submit_packet`, `workflows.ingest_workflow`) share one implementation. Deferred to keep this plan minimal — the duplication is small and the helper extraction is mechanical.
