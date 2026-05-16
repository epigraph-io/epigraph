# Backlog Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make backlog retirement coherent — one canonical convention (label-based), a read-side MCP/HTTP that exposes retirement state, a one-call write-side tool, a cleanup of existing stale items, and a daily reconciler.

**Architecture:** All SQL stays in `ClaimRepository` (the shared repo layer that both the HTTP API and the MCP server call). The HTTP API gains one new route. The MCP gains one new tool and extends two existing ones. The Python cleanup and reconciler scripts call the HTTP API via `httpx` — no direct DB access from scripts.

**Tech Stack:** Rust (axum, sqlx, rmcp); PostgreSQL; Python 3 (httpx). Existing crates: `epigraph-db`, `epigraph-api`, `epigraph-mcp`, `epigraph-core`.

**Spec:** `docs/superpowers/specs/2026-05-16-backlog-retirement-design.md`

---

## File Structure

**Files to create:**

- `scripts/cleanup_backlog_labels.py` — one-shot cleanup of existing stale backlog items
- `scripts/reconcile_backlog_labels.py` — daily reconciler for drift
- `docs/conventions/backlog-retirement.md` — canonical convention doc (epigraph repo has no CLAUDE.md; this is the equivalent)

**Files to modify:**

- `crates/epigraph-db/src/repos/claim.rs` — extend `ClaimRow`, `claim_from_row`, and `list_by_labels`
- `crates/epigraph-mcp/src/types.rs` — extend `ClaimResponse`, `QueryClaimsByLabelParams`; add `ResolveBacklogItemParams`
- `crates/epigraph-mcp/src/tools/paper_queries.rs` — extend `query_claims_by_label` handler
- `crates/epigraph-mcp/src/tools/claims.rs` — extend `get_claim` handler; add `resolve_backlog_item`
- `crates/epigraph-mcp/src/server.rs` — register the new `resolve_backlog_item` tool
- `crates/epigraph-mcp/src/scope_map.rs` — scope for `resolve_backlog_item` (`claims:write`)
- `crates/epigraph-api/src/routes/claims.rs` — add `GET /api/v1/claims/by-labels` handler
- `crates/epigraph-api/src/routes/mod.rs` — register the new route
- `/home/jeremy/epiclaw-host/release/epiclaw/CLAUDE.md` — add retire-backlog convention section

**Each file has one responsibility.** Repo SQL stays in `epigraph-db`; HTTP routing stays in `epigraph-api`; MCP tool surface stays in `epigraph-mcp`; convention prose stays in docs and CLAUDE.md.

---

## Sequencing Notes

- Task 1 is a hard prerequisite for Tasks 2–9 (everything downstream reads the extended repo output).
- Tasks 2–4 (MCP read-side) are independent of Task 5 (HTTP route) — can be done in any order after Task 1.
- Task 6 (`resolve_backlog_item`) is independent of Tasks 2–5 but should land before Task 7 (cleanup script) so the cleanup can use it for the auto-patch operation.
- Task 8 (reconciler) depends on Task 5 (HTTP route).
- Task 9 (docs) can land last but should reference the merged tool names exactly.

---

## Task 1: Extend `ClaimRepository::list_by_labels` with new params and output fields

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs:865-901` (`list_by_labels`)
- Modify: `crates/epigraph-db/src/repos/claim.rs:1664-1672` (`ClaimRow` struct)
- Modify: `crates/epigraph-db/src/repos/claim.rs:71-103` (`claim_from_row`)
- Test: `crates/epigraph-db/tests/list_by_labels.rs` (new file)

The domain `Claim` struct already has `supersedes: Option<ClaimId>` and `is_current: bool` (see `crates/epigraph-core/src/domain/claim.rs:70,76`). The `ClaimRow` and `claim_from_row` in `claim.rs` currently drop them. We surface them, then add `labels: Vec<String>` to the return tuple alongside the `Claim`.

- [ ] **Step 1: Write the failing integration test**

Create `crates/epigraph-db/tests/list_by_labels.rs`:

```rust
use epigraph_db::ClaimRepository;
use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn list_by_labels_returns_labels_is_current_supersedes(pool: PgPool) {
    // Seed: one current backlog claim, one resolved backlog claim, one superseded backlog claim
    let backlog_open = seed_claim(&pool, &["backlog"], true, None).await;
    let backlog_resolved = seed_claim(&pool, &["backlog", "resolved"], true, None).await;
    let backlog_superseded = seed_claim(
        &pool,
        &["backlog"],
        false,
        Some(ClaimId::new()),
    )
    .await;

    // Default call: returns all three with labels populated
    let rows = ClaimRepository::list_by_labels(
        &pool,
        &["backlog".to_string()],
        &[],          // exclude_labels
        false,        // current_only
        0.0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    let labels_for = |id: ClaimId| {
        rows.iter()
            .find(|(c, _)| c.id == id)
            .map(|(_, l)| l.clone())
            .unwrap()
    };
    assert_eq!(labels_for(backlog_open), vec!["backlog"]);
    assert!(labels_for(backlog_resolved).contains(&"resolved".to_string()));
    let superseded_row = rows.iter().find(|(c, _)| c.id == backlog_superseded).unwrap();
    assert!(!superseded_row.0.is_current);
    assert!(superseded_row.0.supersedes.is_some());

    // exclude_labels=["resolved"] drops the resolved one
    let filtered = ClaimRepository::list_by_labels(
        &pool,
        &["backlog".to_string()],
        &["resolved".to_string()],
        false,
        0.0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|(c, _)| c.id != backlog_resolved));

    // current_only=true drops the superseded one
    let current = ClaimRepository::list_by_labels(
        &pool,
        &["backlog".to_string()],
        &[],
        true,
        0.0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(current.len(), 2);
    assert!(current.iter().all(|(c, _)| c.id != backlog_superseded));

    // Both filters combined: only the live open backlog claim
    let open = ClaimRepository::list_by_labels(
        &pool,
        &["backlog".to_string()],
        &["resolved".to_string()],
        true,
        0.0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].0.id, backlog_open);
}

async fn seed_claim(
    pool: &PgPool,
    labels: &[&str],
    is_current: bool,
    supersedes: Option<ClaimId>,
) -> ClaimId {
    let id = ClaimId::new();
    let agent_id = AgentId::new();
    let content_hash = [0u8; 32];
    let public_key = [0u8; 32];
    sqlx::query(
        "INSERT INTO agents (id, did, public_key, agent_type, created_at) \
         VALUES ($1, $2, $3, 'unknown', NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(agent_id.as_uuid())
    .bind(format!("did:test:{}", agent_id.as_uuid()))
    .bind(&public_key[..])
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO claims (id, content, truth_value, agent_id, public_key, content_hash, \
         created_at, updated_at, labels, is_current, supersedes) \
         VALUES ($1, $2, 0.5, $3, $4, $5, NOW(), NOW(), $6, $7, $8)",
    )
    .bind(id.as_uuid())
    .bind(format!("test claim {}", id.as_uuid()))
    .bind(agent_id.as_uuid())
    .bind(&public_key[..])
    .bind(&content_hash[..])
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes.map(|s| s.as_uuid()))
    .execute(pool)
    .await
    .unwrap();
    id
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-db --test list_by_labels list_by_labels_returns_labels_is_current_supersedes`

Expected: FAIL with a signature-mismatch compile error (current `list_by_labels` takes 4 args, test passes 6).

- [ ] **Step 3: Update `ClaimRow` to include the new columns**

In `crates/epigraph-db/src/repos/claim.rs` around line 1664, replace the struct:

```rust
#[derive(sqlx::FromRow)]
struct ClaimRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    agent_id: Uuid,
    trace_id: Option<Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    labels: Vec<String>,
    is_current: bool,
    supersedes: Option<Uuid>,
}
```

- [ ] **Step 4: Update `claim_from_row` to thread `is_current`/`supersedes` through**

In `crates/epigraph-db/src/repos/claim.rs` around line 71, replace the function signature and body:

```rust
fn claim_from_row(
    id: Uuid,
    content: String,
    agent_id: Uuid,
    trace_id: Option<Uuid>,
    truth_value: TruthValue,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Claim {
    let content_hash_vec = ContentHasher::hash(content.as_bytes());
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_vec);
    let public_key = [0u8; 32];
    let signature = None;

    let mut claim = Claim::with_id(
        ClaimId::from_uuid(id),
        content,
        AgentId::from_uuid(agent_id),
        public_key,
        content_hash,
        trace_id.map(TraceId::from_uuid),
        signature,
        truth_value,
        created_at,
        updated_at,
    );
    claim.is_current = is_current;
    claim.supersedes = supersedes.map(ClaimId::from_uuid);
    claim
}
```

You will get compile errors in every other call site of `claim_from_row`. Fix each one by passing `row.is_current` and `row.supersedes` when the surrounding `SELECT` includes those columns. Many callers (e.g. `get_by_id` at line 337–367) do NOT select those columns — for those, pass literal `true` and `None` respectively. They're the safe defaults and Task 4 will properly thread them through for `get_by_id`. Use grep to find every call:

```bash
grep -n 'claim_from_row(' crates/epigraph-db/src/repos/claim.rs
```

For each call site where the surrounding `SELECT` already selects `is_current` and `supersedes`, thread them through. For call sites where the surrounding `SELECT` doesn't, pass literal `true` and `None` — do NOT silently extend the SELECT, that's out of scope for this task.

- [ ] **Step 5: Rewrite `list_by_labels` with new params**

Replace lines 865–901 in `crates/epigraph-db/src/repos/claim.rs`:

```rust
pub async fn list_by_labels(
    pool: &PgPool,
    labels: &[String],
    exclude_labels: &[String],
    current_only: bool,
    min_truth: f64,
    limit: i64,
) -> Result<Vec<(Claim, Vec<String>)>, DbError> {
    let limit = limit.clamp(1, 1000);
    // Build the WHERE clause. `labels @> $1` uses the GIN index; the optional
    // NOT (labels && $2) and is_current=true filters are applied after.
    let rows = sqlx::query_as::<_, ClaimRow>(
        r#"
        SELECT id, content, truth_value, agent_id, trace_id,
               created_at, updated_at, labels, is_current, supersedes
        FROM claims
        WHERE labels @> $1
          AND truth_value >= $2
          AND ($3::text[] = '{}'::text[] OR NOT (labels && $3))
          AND ($4 = false OR is_current = true)
        ORDER BY created_at DESC
        LIMIT $5
        "#,
    )
    .bind(labels)
    .bind(min_truth)
    .bind(exclude_labels)
    .bind(current_only)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let truth_value = TruthValue::new(row.truth_value)?;
        let claim = claim_from_row(
            row.id,
            row.content,
            row.agent_id,
            row.trace_id,
            truth_value,
            row.created_at,
            row.updated_at,
            row.is_current,
            row.supersedes,
        );
        out.push((claim, row.labels));
    }
    Ok(out)
}
```

- [ ] **Step 6: Fix the other call site of `list_by_labels`**

Search and fix every caller of `list_by_labels`:

```bash
grep -rn "list_by_labels(" crates/
```

The signature change (4→6 args and `Vec<Claim>` → `Vec<(Claim, Vec<String>)>`) will break the MCP `query_claims_by_label` caller at `crates/epigraph-mcp/src/tools/paper_queries.rs:208`. Defer fixing that to Task 3 — for now, add the new args with sensible defaults (`&[]`, `false`) at every existing call and destructure the tuple as `(claim, _labels)` to drop the labels:

```rust
// Example fix at paper_queries.rs:208
let claims = ClaimRepository::list_by_labels(&server.pool, &params.labels, &[], false, min_truth, limit)
    .await
    .map_err(internal_error)?;
let claims: Vec<Claim> = claims.into_iter().map(|(c, _)| c).collect();
```

(Task 3 will rewrite this properly to thread labels through.)

- [ ] **Step 7: Run the test**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-db --test list_by_labels`

Expected: PASS.

If the `epigraph_db_repo_test` database doesn't exist, create it once: `psql -U epigraph -d postgres -c "CREATE DATABASE epigraph_db_repo_test"` and apply migrations: `sqlx migrate run --database-url postgres://epigraph:epigraph@localhost/epigraph_db_repo_test`.

- [ ] **Step 8: Run the rest of the repo test suite to check nothing else broke**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-db`

Expected: PASS for all existing tests. If any fail because they assert on `Claim`/`ClaimRow` shape, update them to match the new field set (passing through `is_current=true`/`supersedes=None` is the safe default).

- [ ] **Step 9: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs crates/epigraph-mcp/src/tools/paper_queries.rs crates/epigraph-db/tests/list_by_labels.rs
git commit -m "feat(db): extend list_by_labels with exclude_labels + current_only

Surface labels, is_current, and supersedes alongside the Claim so the
MCP and HTTP readers can distinguish live, resolved, and superseded
claims. Add two new filter params; defaults preserve existing behavior.
Caller at MCP query_claims_by_label adjusted to drop labels for now
(Task 3 wires them through).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Extend MCP `ClaimResponse` with retirement fields

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs:577-584` (`ClaimResponse`)

This is a pure type change. The new fields are read by Tasks 3 and 4.

- [ ] **Step 1: Update the struct**

In `crates/epigraph-mcp/src/types.rs` around line 577:

```rust
#[derive(Debug, Serialize)]
pub struct ClaimResponse {
    pub id: String,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: String,
    pub content_hash: String,
    pub created_at: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default = "default_true")]
    pub is_current: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
}

fn default_true() -> bool { true }
```

- [ ] **Step 2: Compile to verify the struct still parses**

Run: `cargo check -p epigraph-mcp`

Expected: passes. (Construction sites in `claims.rs` and `paper_queries.rs` will now compile-warn or error because they don't set the new fields — fixed in Tasks 3 and 4.)

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-mcp/src/types.rs
git commit -m "feat(mcp): add labels/is_current/supersedes to ClaimResponse

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Wire `query_claims_by_label` to surface and filter on new fields

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs:209-220` (`QueryClaimsByLabelParams`)
- Modify: `crates/epigraph-mcp/src/tools/paper_queries.rs:193-225` (`query_claims_by_label`)
- Test: `crates/epigraph-mcp/tests/query_claims_by_label.rs` (new file)

- [ ] **Step 1: Write the failing test**

Create `crates/epigraph-mcp/tests/query_claims_by_label.rs`:

```rust
// Integration test: spin up the MCP server pool, seed the same three claims
// as the Task 1 repo test (open / resolved / superseded), and assert the
// MCP handler returns the new fields and respects exclude_labels/current_only.
//
// Implementation note: follow the pattern in existing
// crates/epigraph-mcp/tests/*.rs for spinning up an EpiGraphMcpFull harness.
// If none exists, model after the patterns in crates/epigraph-api/tests/.

use epigraph_mcp::types::QueryClaimsByLabelParams;
// ... (test harness setup mirrors existing MCP integration tests)

#[sqlx::test]
async fn query_by_label_returns_labels_and_filters(pool: PgPool) {
    // Seed three backlog claims (same as Task 1)
    // Build a minimal EpiGraphMcpFull with this pool
    // Call query_claims_by_label with exclude_labels=["resolved"], current_only=true
    // Assert: returns exactly the open one with labels=["backlog"], is_current=true
}
```

Before writing this test, run `ls crates/epigraph-mcp/tests/` to find an existing harness pattern to clone. If none exists, write a minimal one mirroring `crates/epigraph-api/tests/` patterns.

- [ ] **Step 2: Run test to verify it fails**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-mcp --test query_claims_by_label`

Expected: FAIL with `exclude_labels`/`current_only` not on `QueryClaimsByLabelParams`.

- [ ] **Step 3: Extend `QueryClaimsByLabelParams`**

In `crates/epigraph-mcp/src/types.rs` around line 209:

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryClaimsByLabelParams {
    #[schemars(
        description = "Labels to filter by — returns claims containing ALL specified labels (e.g. [\"backlog\", \"pending\"]). Uses PostgreSQL array containment (@>) with GIN index."
    )]
    pub labels: Vec<String>,

    #[schemars(
        description = "Labels to exclude — drops claims containing ANY of these labels (e.g. [\"resolved\"]). Default: no exclusion."
    )]
    #[serde(default)]
    pub exclude_labels: Vec<String>,

    #[schemars(
        description = "When true, returns only claims with is_current = true (drops superseded/retired claims). Default: false."
    )]
    #[serde(default)]
    pub current_only: bool,

    #[schemars(description = "Minimum truth value (0.0-1.0, default 0.0)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum results (default 20)")]
    pub limit: Option<i64>,
}
```

- [ ] **Step 4: Rewrite the handler to use the new repo signature and surface the new fields**

Replace `crates/epigraph-mcp/src/tools/paper_queries.rs:193-225`:

```rust
pub async fn query_claims_by_label(
    server: &EpiGraphMcpFull,
    params: QueryClaimsByLabelParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min_truth = params.min_truth.unwrap_or(0.0);

    if params.labels.is_empty() {
        return Err(McpError {
            code: rmcp::model::ErrorCode::INVALID_PARAMS,
            message: std::borrow::Cow::Borrowed("labels must contain at least one label"),
            data: None,
        });
    }

    let rows = ClaimRepository::list_by_labels(
        &server.pool,
        &params.labels,
        &params.exclude_labels,
        params.current_only,
        min_truth,
        limit,
    )
    .await
    .map_err(internal_error)?;

    let results: Vec<ClaimResponse> = rows
        .into_iter()
        .map(|(c, labels)| ClaimResponse {
            id: c.id.as_uuid().to_string(),
            content: c.content.clone(),
            truth_value: c.truth_value.value(),
            agent_id: c.agent_id.as_uuid().to_string(),
            content_hash: ContentHasher::to_hex(&c.content_hash),
            created_at: c.created_at.to_rfc3339(),
            labels,
            is_current: c.is_current,
            supersedes: c.supersedes.map(|s| s.as_uuid().to_string()),
        })
        .collect();

    success_json(&results)
}
```

- [ ] **Step 5: Run the test**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-mcp --test query_claims_by_label`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-mcp/src/types.rs crates/epigraph-mcp/src/tools/paper_queries.rs crates/epigraph-mcp/tests/query_claims_by_label.rs
git commit -m "feat(mcp): query_claims_by_label gains exclude_labels + current_only

Output now includes labels, is_current, supersedes. Defaults preserve
existing behavior — existing callers see the same filtered set with
extra fields. New filters let the open-backlog query work in one call.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Update MCP `get_claim` to return new fields

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/claims.rs:281-299` (`get_claim`)
- Test: `crates/epigraph-mcp/tests/get_claim.rs` (new file)

- [ ] **Step 1: Write the failing test**

Create `crates/epigraph-mcp/tests/get_claim.rs` mirroring the Task 3 harness pattern. Seed a single claim with labels=`["backlog"]`, is_current=true, supersedes=None. Call `get_claim`, assert response contains those three fields with correct values. Then seed a superseded claim and assert `is_current=false` and `supersedes` is populated.

- [ ] **Step 2: Run test to verify it fails**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-mcp --test get_claim`

Expected: FAIL — current handler doesn't set the new fields.

- [ ] **Step 3: Update the handler**

The current `get_claim` calls `ClaimRepository::get_by_id` which returns `Option<Claim>`. The `Claim` already has `is_current` and `supersedes` (after Task 1's `claim_from_row` fix). But it does NOT have `labels` — those live on the row, not the domain object. Add a new repo method to fetch labels separately, OR change `get_by_id` to also return labels. The simpler path: add a thin repo helper.

Add to `crates/epigraph-db/src/repos/claim.rs` (near the other `get_by_id` methods):

```rust
pub async fn get_labels(pool: &PgPool, id: ClaimId) -> Result<Vec<String>, DbError> {
    let row: Option<(Vec<String>,)> =
        sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
            .bind(id.as_uuid())
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(l,)| l).unwrap_or_default())
}
```

Then replace `crates/epigraph-mcp/src/tools/claims.rs:281-299`:

```rust
pub async fn get_claim(
    server: &EpiGraphMcpFull,
    params: GetClaimParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let claim_id = ClaimId::from_uuid(id);
    let claim = ClaimRepository::get_by_id(&server.pool, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;
    let labels = ClaimRepository::get_labels(&server.pool, claim_id)
        .await
        .map_err(internal_error)?;

    success_json(&ClaimResponse {
        id: claim.id.as_uuid().to_string(),
        content: claim.content.clone(),
        truth_value: claim.truth_value.value(),
        agent_id: claim.agent_id.as_uuid().to_string(),
        content_hash: ContentHasher::to_hex(&claim.content_hash),
        created_at: claim.created_at.to_rfc3339(),
        labels,
        is_current: claim.is_current,
        supersedes: claim.supersedes.map(|s| s.as_uuid().to_string()),
    })
}
```

Verify `get_by_id` returns a `Claim` whose `is_current` and `supersedes` reflect the row by checking `crates/epigraph-db/src/repos/claim.rs:337`. If its `SELECT` doesn't include those columns, add them (small in-scope change because Task 1's `claim_from_row` now expects them). If you only see `is_current` selected in some queries and not others, normalize the `SELECT` lists in this same commit.

- [ ] **Step 4: Run the test**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-mcp --test get_claim`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs crates/epigraph-mcp/src/tools/claims.rs crates/epigraph-mcp/tests/get_claim.rs
git commit -m "feat(mcp): get_claim returns labels/is_current/supersedes

Adds ClaimRepository::get_labels helper and threads the new fields
through the MCP get_claim handler.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Add HTTP route `GET /api/v1/claims/by-labels`

**Files:**
- Modify: `crates/epigraph-api/src/routes/claims.rs` (add handler near `update_labels` at line 1482)
- Modify: `crates/epigraph-api/src/routes/mod.rs:221,855` (register the new route)
- Test: `crates/epigraph-api/tests/claims_by_labels.rs` (new file, or add to existing claims test file)

This route is what the Python cleanup and reconciler scripts will call. It mirrors the extended MCP `query_claims_by_label`.

- [ ] **Step 1: Write the failing test**

Find the existing claims-route test file (probably `crates/epigraph-api/tests/claims.rs`). Add a test:

```rust
#[sqlx::test]
async fn get_claims_by_labels_filters_and_returns_new_fields(pool: PgPool) {
    let app = test_app(pool.clone()).await;
    // Seed three claims (same pattern as Task 1)
    // GET /api/v1/claims/by-labels?labels=backlog&exclude_labels=resolved&current_only=true
    // Assert: 200 OK, exactly 1 claim returned, has labels/is_current/supersedes in JSON
}
```

If no `test_app` helper exists yet, model after the existing integration test pattern in `crates/epigraph-api/tests/` (look for one that calls a GET route).

- [ ] **Step 2: Run test to verify it fails**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-api --test claims_by_labels`

Expected: FAIL with 404 or route-not-found.

- [ ] **Step 3: Add the handler**

In `crates/epigraph-api/src/routes/claims.rs`, near the existing `update_labels` handler:

```rust
#[derive(Deserialize)]
pub struct ClaimsByLabelsQuery {
    /// Comma-separated labels to match (all must be present)
    pub labels: String,
    /// Comma-separated labels to exclude (any match excludes)
    #[serde(default)]
    pub exclude_labels: Option<String>,
    #[serde(default)]
    pub current_only: Option<bool>,
    #[serde(default)]
    pub min_truth: Option<f64>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct ClaimByLabelsResponse {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: Uuid,
    pub created_at: String,
    pub labels: Vec<String>,
    pub is_current: bool,
    pub supersedes: Option<Uuid>,
}

#[cfg(feature = "db")]
pub async fn list_by_labels(
    State(state): State<AppState>,
    Query(q): Query<ClaimsByLabelsQuery>,
) -> Result<Json<Vec<ClaimByLabelsResponse>>, ApiError> {
    let labels: Vec<String> = q.labels.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
    if labels.is_empty() {
        return Err(ApiError::BadRequest("labels query parameter required".into()));
    }
    let exclude_labels: Vec<String> = q.exclude_labels
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let current_only = q.current_only.unwrap_or(false);
    let min_truth = q.min_truth.unwrap_or(0.0);
    let limit = q.limit.unwrap_or(50).clamp(MIN_PAGE_LIMIT, MAX_PAGE_LIMIT);

    let rows = ClaimRepository::list_by_labels(
        &state.db_pool, &labels, &exclude_labels, current_only, min_truth, limit,
    )
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(|(c, labels)| ClaimByLabelsResponse {
                id: *c.id.as_uuid(),
                content: c.content,
                truth_value: c.truth_value.value(),
                agent_id: *c.agent_id.as_uuid(),
                created_at: c.created_at.to_rfc3339(),
                labels,
                is_current: c.is_current,
                supersedes: c.supersedes.map(|s| *s.as_uuid()),
            })
            .collect(),
    ))
}
```

If `ApiError::BadRequest` doesn't exist, use whichever bad-request variant the existing routes use (`ApiError::Validation`, `ApiError::InvalidRequest`, etc.) — grep `enum ApiError` in `crates/epigraph-api/src/errors.rs`.

- [ ] **Step 4: Register the route in `mod.rs`**

In `crates/epigraph-api/src/routes/mod.rs`, near line 221 and 855 (both router-build sites), add:

```rust
.route("/api/v1/claims/by-labels", get(claims::list_by_labels))
```

Use `axum::routing::get`.

- [ ] **Step 5: Run the test**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-api --test claims_by_labels`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-api/src/routes/claims.rs crates/epigraph-api/src/routes/mod.rs crates/epigraph-api/tests/claims_by_labels.rs
git commit -m "feat(api): GET /api/v1/claims/by-labels with exclude_labels filter

HTTP route mirrors the extended MCP query_claims_by_label so Python
cleanup/reconciler scripts can read without direct DB access.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: New MCP tool `resolve_backlog_item`

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs` (add `ResolveBacklogItemParams`)
- Modify: `crates/epigraph-mcp/src/tools/claims.rs` (add `resolve_backlog_item` handler)
- Modify: `crates/epigraph-mcp/src/server.rs:385` area (register tool wrapper)
- Modify: `crates/epigraph-mcp/src/scope_map.rs:45` (add scope)
- Test: `crates/epigraph-mcp/tests/resolve_backlog_item.rs` (new file)

- [ ] **Step 1: Write the failing test**

Create `crates/epigraph-mcp/tests/resolve_backlog_item.rs`:

```rust
#[sqlx::test]
async fn resolve_backlog_item_creates_resolution_and_patches_original(pool: PgPool) {
    // Seed an open backlog claim
    let backlog_id = seed_claim(&pool, &["backlog"], true, None).await;

    let server = mcp_server(pool.clone()).await;
    let result = resolve_backlog_item(
        &server,
        ResolveBacklogItemParams {
            original_id: backlog_id.as_uuid().to_string(),
            resolution_content: "Fixed in PR #999 by adding the missing index".into(),
            methodology: None,
        },
    )
    .await
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&extract_text(&result)).unwrap();

    // Resolution claim exists, has labels=["resolved"], content prefixed with Resolves <id>:
    let resolution_id = body["resolution_claim_id"].as_str().unwrap();
    let resolution = ClaimRepository::get_by_id(&pool, ClaimId::from_str(resolution_id).unwrap())
        .await.unwrap().unwrap();
    assert!(resolution.content.starts_with(&format!("Resolves {}:", backlog_id.as_uuid())));
    let resolution_labels = ClaimRepository::get_labels(&pool, resolution.id).await.unwrap();
    assert!(resolution_labels.contains(&"resolved".to_string()));

    // Original claim now has both backlog and resolved
    let orig_labels = ClaimRepository::get_labels(&pool, backlog_id).await.unwrap();
    assert!(orig_labels.contains(&"backlog".to_string()));
    assert!(orig_labels.contains(&"resolved".to_string()));

    // Original's is_current is still true (operational resolve, not epistemic supersede)
    let orig = ClaimRepository::get_by_id(&pool, backlog_id).await.unwrap().unwrap();
    assert!(orig.is_current);
    assert!(orig.supersedes.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-mcp --test resolve_backlog_item`

Expected: FAIL — handler doesn't exist.

- [ ] **Step 3: Add the params struct**

In `crates/epigraph-mcp/src/types.rs` (in the Claims section near other Params structs):

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveBacklogItemParams {
    #[schemars(description = "UUID of the backlog claim being retired")]
    pub original_id: String,

    #[schemars(
        description = "Narrative explaining how the issue was resolved. Will be prefixed with 'Resolves <original_id>: '."
    )]
    pub resolution_content: String,

    #[schemars(
        description = "Methodology for the resolution claim (default: 'resolution'). Use 'refutation' if the resolution proves the original was wrong."
    )]
    pub methodology: Option<String>,
}
```

- [ ] **Step 4: Add the handler**

In `crates/epigraph-mcp/src/tools/claims.rs` (near `update_labels`):

```rust
pub async fn resolve_backlog_item(
    server: &EpiGraphMcpFull,
    params: crate::types::ResolveBacklogItemParams,
) -> Result<CallToolResult, McpError> {
    let original_id = parse_uuid(&params.original_id)?;
    let original_claim_id = ClaimId::from_uuid(original_id);

    // Warn-only: confirm the target exists; do NOT reject if it lacks ["backlog"]
    // (sometimes you resolve something that was never labeled).
    let original = ClaimRepository::get_by_id(&server.pool, original_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {original_id} not found")))?;

    // 1. Submit the resolution claim with labels=["resolved"]
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();
    let resolution_content = format!(
        "Resolves {}: {}",
        original_id, params.resolution_content
    );
    let content_hash = ContentHasher::hash(resolution_content.as_bytes());
    let mut content_hash_arr = [0u8; 32];
    content_hash_arr.copy_from_slice(&content_hash);
    let mut resolution = Claim::new(
        agent_id_typed,
        pub_key,
        resolution_content,
        content_hash_arr,
        None,
        TruthValue::new(0.5).unwrap(),
    );
    resolution.signature = Some(server.signer.sign(&content_hash_arr));
    let resolution_id = ClaimRepository::create(&server.pool, &resolution)
        .await
        .map_err(internal_error)?;
    // Tag the resolution claim with "resolved"
    ClaimRepository::update_labels(&server.pool, *resolution_id.as_uuid(), &["resolved".to_string()], &[])
        .await
        .map_err(internal_error)?;

    // 2. Patch the original's labels: add "resolved", keep "backlog"
    // Best-effort: if this fails, return the partial-success error including the resolution UUID.
    let after_labels = match ClaimRepository::update_labels(
        &server.pool,
        original_id,
        &["resolved".to_string()],
        &[],
    )
    .await
    {
        Ok(labels) => labels,
        Err(e) => {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INTERNAL_ERROR,
                message: format!(
                    "resolution claim {} created but failed to patch original {}: {}",
                    resolution_id.as_uuid(),
                    original_id,
                    e
                )
                .into(),
                data: Some(serde_json::json!({
                    "resolution_claim_id": resolution_id.as_uuid().to_string(),
                    "original_id": original_id.to_string(),
                })),
            });
        }
    };

    let _ = original; // silence unused (kept for future "warn if no backlog label" hook)
    success_json(&serde_json::json!({
        "resolution_claim_id": resolution_id.as_uuid().to_string(),
        "original_id": original_id.to_string(),
        "original_labels": after_labels,
    }))
}
```

Check `Claim::new` and `ClaimRepository::create` signatures exactly — adjust the construction to whatever the canonical `submit_claim` MCP handler does (look at `crates/epigraph-mcp/src/tools/claims.rs` around `pub async fn submit_claim`). Mirror its construction (this avoids drift from the canonical submit path).

- [ ] **Step 5: Register the tool**

In `crates/epigraph-mcp/src/server.rs`, find where `query_claims_by_label` is registered (around line 385) and add a wrapper for `resolve_backlog_item` following the same pattern:

```rust
async fn resolve_backlog_item(
    &self,
    params: ResolveBacklogItemParams,
) -> Result<CallToolResult, McpError> {
    tools::claims::resolve_backlog_item(self, params).await
}
```

Also register it in the `#[tool_router]` macro or whichever mechanism the file uses (check the existing pattern — likely a list of tool definitions).

In `crates/epigraph-mcp/src/scope_map.rs:45` area, add:

```rust
("resolve_backlog_item", "claims:write"),
```

- [ ] **Step 6: Run the test**

Run: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo test -p epigraph-mcp --test resolve_backlog_item`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/epigraph-mcp/src/types.rs crates/epigraph-mcp/src/tools/claims.rs crates/epigraph-mcp/src/server.rs crates/epigraph-mcp/src/scope_map.rs crates/epigraph-mcp/tests/resolve_backlog_item.rs
git commit -m "feat(mcp): resolve_backlog_item one-call retirement tool

Submits a resolution claim labelled [resolved] with 'Resolves <id>:'
prose AND patches the original claim's labels with add=[resolved].
Single tool call so agents can't half-apply the convention.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: One-shot cleanup script

**Files:**
- Create: `scripts/cleanup_backlog_labels.py`

The script pages through `[backlog]` items via `GET /api/v1/claims/by-labels`, matches them against `[resolved]` claims with "Resolves <UUID>" prose AND against `supersedes`-based retirements, then PATCHes labels via `PATCH /api/v1/claims/:id/labels`. Dry-run by default; `--apply` actually patches.

- [ ] **Step 1: Write the script**

Create `scripts/cleanup_backlog_labels.py`:

```python
#!/usr/bin/env python3
"""One-shot cleanup: retire stale backlog claims by patching ["resolved"] label.

Walks every [backlog] claim, looks for a downstream resolution signal:
  - A [resolved] claim whose content mentions the backlog UUID, OR
  - is_current=false on the backlog claim itself, OR
  - The backlog claim's UUID appearing as another claim's supersedes target.

Auto-patches unambiguous matches; buckets ambiguous ones (multiple resolution
claims with conflicting narratives) into a "needs-review" report.

Usage:
    python3 scripts/cleanup_backlog_labels.py            # dry-run, write report only
    python3 scripts/cleanup_backlog_labels.py --apply    # also patch labels
    python3 scripts/cleanup_backlog_labels.py --base-url http://localhost:8080

Output: docs/superpowers/reports/backlog-cleanup-YYYY-MM-DD.md
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

import httpx

UUID_RE = re.compile(
    r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
    re.IGNORECASE,
)


def page_claims(base_url: str, labels: list[str], exclude: list[str], current_only: bool) -> list[dict]:
    """Page through all claims matching the filter (limit=100 per page, no offset
    yet — repeat with min_truth windowing if needed; the dataset is ~100 rows so a
    single page is enough for the cleanup pass)."""
    params = {
        "labels": ",".join(labels),
        "limit": 100,
    }
    if exclude:
        params["exclude_labels"] = ",".join(exclude)
    if current_only:
        params["current_only"] = "true"
    r = httpx.get(f"{base_url}/api/v1/claims/by-labels", params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def patch_labels(base_url: str, claim_id: str, add: list[str]) -> dict:
    r = httpx.patch(
        f"{base_url}/api/v1/claims/{claim_id}/labels",
        json={"add": add, "remove": []},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--apply", action="store_true", help="Actually PATCH labels (default: dry-run)")
    p.add_argument("--base-url", default="http://localhost:8080")
    args = p.parse_args()

    # 1. Pull all open backlog claims
    open_backlog = page_claims(args.base_url, ["backlog"], ["resolved"], current_only=False)
    print(f"Found {len(open_backlog)} open backlog claims (not already labelled resolved)")

    # 2. Pull all resolved claims and build a UUID-prefix index of which backlog ids they mention
    resolved_claims = page_claims(args.base_url, ["resolved"], [], current_only=False)
    resolved_by_uuid: dict[str, list[dict]] = {}
    for rc in resolved_claims:
        for m in UUID_RE.findall(rc["content"]):
            resolved_by_uuid.setdefault(m.lower(), []).append(rc)
    print(f"Indexed {len(resolved_claims)} resolved claims mentioning {len(resolved_by_uuid)} distinct UUIDs")

    auto_patch: list[tuple[dict, dict]] = []
    needs_review: list[tuple[dict, list[dict]]] = []
    still_open: list[dict] = []
    superseded: list[dict] = []

    for bc in open_backlog:
        bid = bc["id"].lower()
        # supersedes-based retirement: the backlog claim itself is_current=false or has supersedes
        if not bc.get("is_current", True) or bc.get("supersedes"):
            superseded.append(bc)
            continue
        matches = resolved_by_uuid.get(bid, [])
        if not matches:
            still_open.append(bc)
        elif len(matches) == 1:
            auto_patch.append((bc, matches[0]))
        else:
            needs_review.append((bc, matches))

    # 3. Apply (or report)
    if args.apply:
        for bc, _ in auto_patch:
            try:
                patch_labels(args.base_url, bc["id"], ["resolved"])
                print(f"PATCHED resolved → {bc['id']}")
            except httpx.HTTPError as e:
                print(f"FAIL {bc['id']}: {e}", file=sys.stderr)
        for bc in superseded:
            try:
                patch_labels(args.base_url, bc["id"], ["resolved"])
                print(f"PATCHED resolved (supersedes-retired) → {bc['id']}")
            except httpx.HTTPError as e:
                print(f"FAIL {bc['id']}: {e}", file=sys.stderr)

    # 4. Write report
    today = datetime.date.today().isoformat()
    report_dir = Path("docs/superpowers/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"backlog-cleanup-{today}.md"
    with report_path.open("w") as f:
        f.write(f"# Backlog cleanup — {today}\n\n")
        f.write(f"Mode: {'APPLY' if args.apply else 'DRY-RUN'}\n\n")
        f.write(f"## Auto-patched ({len(auto_patch)})\n\n")
        for bc, rc in auto_patch:
            f.write(f"- `{bc['id']}` → resolved by `{rc['id']}`\n")
            f.write(f"  - backlog: {bc['content'][:120].strip()}…\n")
            f.write(f"  - resolution: {rc['content'][:120].strip()}…\n")
        f.write(f"\n## Supersedes-retired auto-patched ({len(superseded)})\n\n")
        for bc in superseded:
            f.write(f"- `{bc['id']}` (is_current={bc['is_current']}, supersedes={bc.get('supersedes')})\n")
        f.write(f"\n## Needs review — multiple resolutions ({len(needs_review)})\n\n")
        for bc, matches in needs_review:
            f.write(f"### `{bc['id']}`\n")
            f.write(f"- backlog: {bc['content'][:200].strip()}\n")
            for rc in matches:
                f.write(f"- candidate `{rc['id']}`: {rc['content'][:200].strip()}\n")
            f.write("\n")
        f.write(f"\n## Still open ({len(still_open)})\n\n")
        for bc in still_open:
            f.write(f"- `{bc['id']}`: {bc['content'][:120].strip()}…\n")
    print(f"Report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Smoke-test in dry-run mode**

Run: `python3 scripts/cleanup_backlog_labels.py --base-url http://localhost:8080`

Expected: prints counts, writes `docs/superpowers/reports/backlog-cleanup-YYYY-MM-DD.md`, makes no DB changes. Confirm `1c31a529-97bf-4471-bbeb-d1b81717c930` appears in the "needs review" bucket (it has both `4485beac` complete and `6d28afba` NOT-A-BUG resolutions).

- [ ] **Step 3: Review the report manually**

Open the report file and sanity-check that the auto-patch bucket looks safe. If anything in `auto-patch` should actually be `needs-review`, refine the matcher (e.g. require the resolution content to contain "Resolves" or "Supersedes" as a literal keyword adjacent to the UUID).

- [ ] **Step 4: Run with --apply**

Run: `python3 scripts/cleanup_backlog_labels.py --apply --base-url http://localhost:8080`

Expected: prints `PATCHED resolved → <uuid>` for each auto-patched item. Verify by re-querying `mcp__epigraph__query_claims_by_label(labels=["backlog"], exclude_labels=["resolved"])` — the result should be markedly shorter.

- [ ] **Step 5: Commit the script and the report**

```bash
git add scripts/cleanup_backlog_labels.py docs/superpowers/reports/backlog-cleanup-*.md
git commit -m "chore: one-shot cleanup of stale backlog labels

Script pages backlog items, matches against resolved-label claims that
mention the backlog UUID, auto-patches unambiguous matches. The
committed report records what was patched and what needs manual review.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Daily reconciler

**Files:**
- Create: `scripts/reconcile_backlog_labels.py`

Reuses 80% of Task 7. Difference: scoped to claims created in the past 7 days, runs on a schedule, writes append-only log file, never auto-patches ambiguous matches.

- [ ] **Step 1: Write the script**

Create `scripts/reconcile_backlog_labels.py`:

```python
#!/usr/bin/env python3
"""Daily reconciler: catch backlog items that were resolved via free-text
"Resolves <UUID>" claims without using the resolve_backlog_item tool.

Scans open backlog claims, looks for [resolved] claims created in the past
RECON_WINDOW_DAYS that mention the backlog UUID. PATCHes unambiguous matches.
Ambiguous matches are appended to docs/superpowers/reports/reconciler-needs-review.log
for human triage.

Schedule: daily. Idempotent. Safe to run repeatedly.
"""
import argparse
import datetime
import os
import re
import sys
from pathlib import Path

import httpx

UUID_RE = re.compile(
    r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
    re.IGNORECASE,
)
RECON_WINDOW_DAYS = int(os.environ.get("RECON_WINDOW_DAYS", "7"))


def page_claims(base_url: str, labels: list[str], exclude: list[str]) -> list[dict]:
    params = {"labels": ",".join(labels), "limit": 100}
    if exclude:
        params["exclude_labels"] = ",".join(exclude)
    r = httpx.get(f"{base_url}/api/v1/claims/by-labels", params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def patch_labels(base_url: str, claim_id: str, add: list[str]) -> dict:
    r = httpx.patch(
        f"{base_url}/api/v1/claims/{claim_id}/labels",
        json={"add": add, "remove": []},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--apply", action="store_true", default=True)
    p.add_argument("--base-url", default=os.environ.get("EPIGRAPH_API", "http://localhost:8080"))
    args = p.parse_args()

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=RECON_WINDOW_DAYS)
    open_backlog = page_claims(args.base_url, ["backlog"], ["resolved"])
    resolved_recent = [
        rc for rc in page_claims(args.base_url, ["resolved"], [])
        if datetime.datetime.fromisoformat(rc["created_at"]) >= cutoff
    ]

    resolved_by_uuid: dict[str, list[dict]] = {}
    for rc in resolved_recent:
        for m in UUID_RE.findall(rc["content"]):
            resolved_by_uuid.setdefault(m.lower(), []).append(rc)

    log_path = Path("docs/superpowers/reports/reconciler-needs-review.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    patched = 0
    review = 0
    for bc in open_backlog:
        matches = resolved_by_uuid.get(bc["id"].lower(), [])
        if not matches:
            continue
        if len(matches) == 1:
            if args.apply:
                try:
                    patch_labels(args.base_url, bc["id"], ["resolved"])
                    patched += 1
                except httpx.HTTPError as e:
                    print(f"FAIL {bc['id']}: {e}", file=sys.stderr)
        else:
            with log_path.open("a") as f:
                f.write(f"{datetime.datetime.utcnow().isoformat()} AMBIGUOUS {bc['id']} "
                        f"matches={[m['id'] for m in matches]}\n")
            review += 1

    print(f"Reconciler: patched={patched} needs_review={review}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Smoke-test**

Run: `python3 scripts/reconcile_backlog_labels.py --base-url http://localhost:8080`

Expected: prints `Reconciler: patched=N needs_review=M`. After Task 7 has run, expect both numbers small.

- [ ] **Step 3: Wire it into the scheduled-task harness**

Locate the scheduled-task config. Look in `/home/jeremy/epiclaw-host/` for a scheduler config (likely a TOML or YAML listing scheduled scripts). Add an entry:

```toml
# Example shape — adapt to actual config format
[[task]]
name = "reconcile_backlog_labels"
schedule = "0 4 * * *"  # daily at 04:00 UTC
command = "python3 /opt/epigraph/scripts/reconcile_backlog_labels.py"
group = "main"
```

If you can't find the scheduler config, ask the user where scheduled tasks are configured — the memory mentions `epiclaw-host/src/host/scheduler.rs` which may contain a static task list.

- [ ] **Step 4: Commit**

```bash
git add scripts/reconcile_backlog_labels.py
git commit -m "feat: daily reconciler for backlog label drift

Catches future free-text 'Resolves <UUID>' claims filed without the
resolve_backlog_item tool. Unambiguous matches auto-patched; ambiguous
ones appended to a human-review log.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

If scheduler wiring is committed in a separate repo (`epiclaw-host`), commit it there following that repo's PR conventions and link from this commit message.

---

## Task 9: Convention documentation

**Files:**
- Create: `docs/conventions/backlog-retirement.md`
- Modify: `/home/jeremy/epiclaw-host/release/epiclaw/CLAUDE.md` (add a section)

- [ ] **Step 1: Write the convention doc**

Create `docs/conventions/backlog-retirement.md`:

```markdown
# Backlog Retirement Convention

**Authoritative source:** `docs/superpowers/specs/2026-05-16-backlog-retirement-design.md`

## Filing a backlog item

Use `submit_claim` (or `memorize`) with `labels=["backlog"]` and a self-contained
description of the issue. Include enough context that a future agent or human can
act on it without the original conversation.

## Retiring a backlog item

**ALWAYS use `mcp__epigraph__resolve_backlog_item`.** This single tool call both
creates a resolution claim (labelled `["resolved"]`, prefixed with `"Resolves
<id>: "`) AND patches the original claim's labels with `add=["resolved"]`.

Do NOT:
- File a free-text "Resolves <UUID>" claim alone. The original keeps the
  `[backlog]` label and stays visible in every backlog query forever.
- Use `supersedes`/`is_current` for status. Those are reserved for *epistemic*
  claim replacement (one claim refining another's factual content), not
  operational status.

If you find yourself reaching for raw SQL or `update_labels` after a resolution,
that's a sign you should be using `resolve_backlog_item` instead.

## Querying open backlog

```python
mcp__epigraph__query_claims_by_label(
    labels=["backlog"],
    exclude_labels=["resolved"],
    current_only=True,
)
```

This returns claims labelled `backlog` that are not also labelled `resolved`
and have not been epistemically superseded. The result is the live, actionable
backlog — not the historical "everything ever filed" view.

## Drift safety net

A daily reconciler (`scripts/reconcile_backlog_labels.py`) scans for cases
where someone filed a free-text "Resolves <UUID>" claim without using
`resolve_backlog_item`, and back-fills the label patch. Ambiguous matches
(multiple resolution claims referencing the same backlog UUID) are logged for
human triage at `docs/superpowers/reports/reconciler-needs-review.log`.
```

- [ ] **Step 2: Update EpiClaw CLAUDE.md**

In `/home/jeremy/epiclaw-host/release/epiclaw/CLAUDE.md`, add a new section under "Critical Rules":

```markdown
8. **Retiring backlog items.** When you complete or refute a backlog item,
   use `mcp__epigraph__resolve_backlog_item(original_id, resolution_content)`.
   It creates the resolution claim AND patches the original's labels in one
   call. Free-text "Resolves <UUID>" alone leaves the original looking open
   forever. See `docs/conventions/backlog-retirement.md` in the epigraph
   repo. To find live items: `query_claims_by_label(labels=["backlog"],
   exclude_labels=["resolved"], current_only=True)`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/conventions/backlog-retirement.md
git commit -m "docs: backlog retirement convention

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

For the EpiClaw CLAUDE.md change in `/home/jeremy/epiclaw-host/`: commit in that repo following its conventions (likely a PR).

---

## Final verification

- [ ] **Acceptance criteria 1**: `mcp__epigraph__query_claims_by_label(labels=["backlog"], exclude_labels=["resolved"])` returns a meaningfully shorter list than the current 100. Run it from MCP and report the count.

- [ ] **Acceptance criteria 2**: `mcp__epigraph__get_claim` returns `labels`, `is_current`, and `supersedes` for every claim. Verify on three claims: an open backlog item, a resolved one, and a superseded one (`1c31a529`, an auto-patched item from Task 7, and `6949d004`).

- [ ] **Acceptance criteria 3**: `mcp__epigraph__resolve_backlog_item` exists and, in one call, creates a resolution claim and PATCHes the original's labels. Test by resolving a freshly-created throwaway backlog claim.

- [ ] **Acceptance criteria 4**: The cleanup script has been run once with `--apply` and the cleanup report is committed (done in Task 7 step 5).

- [ ] **Acceptance criteria 5**: The reconciler runs daily (scheduled in Task 8 step 3) and its log file contains only `needs-review` entries (auto-patches happen silently). Wait one week, then check.

- [ ] **Acceptance criteria 6**: Convention docs merged to `docs/conventions/backlog-retirement.md` (in this repo, done in Task 9) and `/home/jeremy/epiclaw-host/release/epiclaw/CLAUDE.md` (in epiclaw-host repo).

When all six are checked, open a PR for the feature branch.
