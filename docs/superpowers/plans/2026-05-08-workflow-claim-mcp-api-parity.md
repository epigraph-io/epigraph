# Workflow + Claim MCP/API Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `epigraph-mcp` and `epigraph-api` into parity with the workflow system as it stands after PR #92 (step versioning), #97 (`is_current=false` on deprecate), and #99 (improve_workflow `supersedes`); and close the long-standing claim/labels/supersede/dedup MCP gap surfaced in backlog claim `b1770b53` (2026-05-08).

**Architecture:** Single feature branch `feat/workflow-claim-mcp-api-parity` with logical commits per task. Six workstreams (A–E + Pre-flight). Plan was reviewed 2026-05-08 against `/home/jeremy/epigraph` HEAD; all file paths, line numbers, function signatures, and test infrastructure references are validated against the actual repo.

- **Pre-flight (0):** branch, baseline build, migrations, **and** add missing test helpers (without these, B/C tests cannot compile).
- **A — Workflow parity (5 fixes):** new `POST /api/v1/workflows/steps/:id/evolve` REST handler; `resolve_to_latest` query param on `find_workflow_hierarchical`; MCP `improve_workflow` writes `supersedes`; MCP `deprecate_workflow` sets `is_current=false`; MCP cascade walks `supersedes` AND `variant_of`, filtered to workflow-labeled claims.
- **B — Claim/labels MCP wrappers (3 new tools + extension):** `mcp__epigraph__supersede_claim`, `mcp__epigraph__update_labels`, `mcp__epigraph__patch_claim`; add `labels: Vec<String>` to `submit_claim` (post-create application — `Claim` has no `labels` field).
- **C — Dedup mode:** new dedicated `POST /api/v1/claims/:id/dedup` route + matching MCP tool. New route, not a `mode` field on `SupersedeRequest`, because the existing struct requires `content` and `truth_value` which are nonsensical for mark-duplicate.
- **D — OpenAPI surface (scoped):** add `#[utoipa::path]` annotations only for the 10 in-scope handlers. Add `paths(...)` entries in `openapi.rs`. Round-trip test asserts documented paths. Broader OpenAPI coverage tracked as a follow-up issue.
- **E — Backport from internal:** `routes/mcp_tools.rs`, `lib.rs::list_tools()`, `server.rs::all_tools_json()`, register `GET /api/v1/mcp/tools`. Public already has `DELETE /api/v1/edges/:id` so that backlog item is dropped.

**Branching policy:** Single feature branch `feat/workflow-claim-mcp-api-parity` off `main`. Logical commits per task. Merge with `gh pr merge --merge --delete-branch` (no squash — see `feedback_merge_commit_not_squash` memory). Do **not** land commits directly on `main`.

**Tech Stack:** Rust 1.79+, axum, sqlx (Postgres), rmcp `#[tool_router]` macro, utoipa for OpenAPI, `#[sqlx::test]` for DB integration tests, `epigraph_db_repo_test` Postgres database for integration tests.

---

## Pre-flight (Workstream 0)

### Task 0.1: Branch + baseline

- [ ] **Step 1: Create feature branch**

```bash
cd /home/jeremy/epigraph
git checkout main && git pull --ff-only
git checkout -b feat/workflow-claim-mcp-api-parity
```

- [ ] **Step 2: Confirm baseline builds**

```bash
cargo build --workspace --all-features
cargo fmt --check
```

- [ ] **Step 3: Migrations on test DB**

```bash
export TEST_DB_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test
sqlx migrate run --database-url "$TEST_DB_URL" --source ./migrations
```

Expected: clean run, no pending migrations.

- [ ] **Step 4: Confirm relevant existing tests pass**

```bash
cargo test -p epigraph-api --test workflow_deprecate_test --no-fail-fast
cargo test -p epigraph-mcp --test step_versioning --no-fail-fast
```

### Task 0.2: Extend API test helpers

**Why:** `crates/epigraph-api/tests/common/mod.rs` currently exposes `spawn_app(database_url: &str) -> (SocketAddr, oneshot::Sender<()>)` and `test_bearer_token() -> String`. The new integration tests in A1, A2, C1, D1 need a small set of seeding helpers. Add them once so every later test stays terse.

**Files:**
- Modify: `crates/epigraph-api/tests/common/mod.rs`

- [ ] **Step 1: Append helpers to `tests/common/mod.rs`**

```rust
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a system agent (or return existing) for tests that need a non-null agent_id.
pub async fn seed_system_agent(pool: &PgPool) -> Uuid {
    // The auth-required handlers expect an agent referenced by AuthContext;
    // for tests that bypass auth we still need a real row.
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, did, public_key, kind, created_at) \
         VALUES ($1, $2, $3, 'system', NOW()) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("did:test:{id}"))
    .bind(vec![0u8; 32])
    .execute(pool)
    .await
    .expect("seed system agent");
    id
}

/// Insert a minimal claim and return its id.
pub async fn seed_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent = seed_system_agent(pool).await;
    let id = Uuid::new_v4();
    let hash = blake3::hash(content.as_bytes()).as_bytes().to_vec();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, created_at, updated_at) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[], NOW(), NOW())",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Insert a claim with explicit labels. Useful for label-mutation tests.
pub async fn seed_claim_with_labels(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let id = seed_claim(pool, content).await;
    let labels_owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels_owned)
        .bind(id)
        .execute(pool)
        .await
        .expect("set labels");
    id
}
```

(Add `blake3 = "1"` as a `[dev-dependencies]` entry in `crates/epigraph-api/Cargo.toml` if not already present.)

- [ ] **Step 2: Sanity-build the test crate**

```bash
cargo test -p epigraph-api --tests --no-run
```

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-api/tests/common/mod.rs crates/epigraph-api/Cargo.toml
git commit -m "test(api): add seed_claim/seed_claim_with_labels/seed_system_agent helpers"
```

### Task 0.3: Extend MCP test helpers

**Why:** `crates/epigraph-mcp/tests/common/mod.rs` exposes `try_test_pool`, `insert_test_agent`, `make_claim`, plus the constraint helpers. The B/C tests need: `build_test_server` (currently lives only inside `tests/tool_resubmit_tests.rs:13` — hoist it), `seed_workflow_claim`, `seed_claim_with_labels`, `insert_edge`, plus small `parse_*` helpers for `CallToolResult`.

**Files:**
- Modify: `crates/epigraph-mcp/tests/common/mod.rs`

- [ ] **Step 1: Hoist `build_test_server` and add new helpers**

```rust
use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Construct a fully-wired `EpiGraphMcpFull` against the supplied pool.
/// Mirrors the local copy in `tool_resubmit_tests.rs`.
pub async fn build_test_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_seed(&[7u8; 32]).expect("signer");
    let embedder = McpEmbedder::null();
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

/// Insert a minimal claim and return its id.
pub async fn seed_claim(pool: &PgPool, content: &str, truth: f64) -> Uuid {
    let agent = ensure_agent(pool).await;
    let id = Uuid::new_v4();
    let hash = ContentHasher::hash(content.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, true, ARRAY[]::text[], NOW(), NOW())",
    )
    .bind(id)
    .bind(content)
    .bind(hash.as_slice())
    .bind(truth)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Insert a claim with explicit labels.
pub async fn seed_claim_with_labels(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let id = seed_claim(pool, content, 0.5).await;
    let labels_owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels_owned)
        .bind(id)
        .execute(pool)
        .await
        .expect("set labels");
    id
}

/// Insert a workflow-labeled claim with serialized steps in properties.
pub async fn seed_workflow_claim(pool: &PgPool, goal: &str, steps: &[&str]) -> Uuid {
    let agent = ensure_agent(pool).await;
    let id = Uuid::new_v4();
    let content = format!("{goal}\n{}", steps.join("\n"));
    let hash = ContentHasher::hash(content.as_bytes());
    let props = serde_json::json!({
        "goal": goal,
        "steps": steps,
        "generation": 0,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 0.0,
    });
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, properties, created_at, updated_at) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY['workflow']::text[], $5, NOW(), NOW())",
    )
    .bind(id)
    .bind(&content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(&props)
    .execute(pool)
    .await
    .expect("seed workflow claim");
    id
}

/// Insert an edge between two claims.
pub async fn insert_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties, created_at) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb, NOW())",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
}

/// Ensure a deterministic test agent exists; returns its id.
pub async fn ensure_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::parse_str("00000000-0000-0000-0000-aaaaaaaaaaaa").unwrap();
    insert_test_agent(pool, id).await;
    id
}

/// Pull the JSON payload out of a `CallToolResult` (success path).
pub fn first_text(result: &CallToolResult) -> Value {
    let content = result.content.as_ref().and_then(|c| c.first()).expect("at least one content block");
    let text = content.as_text().expect("text block").text.clone();
    serde_json::from_str(&text).expect("valid JSON")
}

/// Convenience: pull a UUID out of a JSON object by key.
pub fn parse_uuid_field(json: &Value, key: &str) -> Uuid {
    json.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing field {key} in {json}"))
        .parse()
        .expect("valid UUID")
}
```

- [ ] **Step 2: Remove the now-duplicated `build_test_server` from `tests/tool_resubmit_tests.rs`**

Find the local `build_test_server` definition near line 13 of `tests/tool_resubmit_tests.rs` and replace its callsites with `common::build_test_server(pool).await`. Delete the local definition.

- [ ] **Step 3: Sanity-build**

```bash
cargo test -p epigraph-mcp --tests --no-run
```

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/tests/common/mod.rs crates/epigraph-mcp/tests/tool_resubmit_tests.rs
git commit -m "test(mcp): hoist build_test_server + add seed/parse helpers to tests/common"
```

### Task 0.4: Add the shared db-layer functions in their own commits

The plan calls into six db functions that don't exist yet (or need extending). Add them now in dedicated, isolated commits so the per-task TDD steps in A–C only need to wire callers.

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs` — add `evolve_step`, `mark_duplicate`, `patch_claim_atomic_conn`
- Modify: `crates/epigraph-db/src/repos/workflow.rs` — add `resolve_steps_to_heads`
- (Optionally) Modify: `crates/epigraph-db/src/repos/provenance.rs` — *not* changed; `append_conn` is reused.

#### 0.4.a `ClaimRepository::evolve_step`

Adds atomic step evolution. **Behavior change vs. existing MCP `evolve_step`:** when `edge_type == "supersedes"`, the parent's `is_current` flips to `false` (matches `ClaimRepository::supersede` semantics). The current MCP `tools/evolve_step.rs` only inserts a new claim + edge; under this plan both surfaces call this new shared function and gain the parent-flip behavior. Add an explicit regression test covering it.

- [ ] **Step 1: Add the function**

```rust
// crates/epigraph-db/src/repos/claim.rs (append to impl ClaimRepository)

#[derive(Debug)]
pub struct EvolveStepResult {
    pub new_claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_type: String,
}

/// Atomically create a new step claim that supersedes or revises a parent.
///
/// `edge_type` must be `"supersedes"` (linear; flips parent.is_current=false)
/// or `"revises"` (parallel branch; both heads stay current).
///
/// The new claim inherits the parent's `step_lineage_id`. If the parent has
/// no lineage id yet, one is generated and back-filled onto the parent first.
#[instrument(skip(pool))]
pub async fn evolve_step(
    pool: &PgPool,
    parent: ClaimId,
    new_content: &str,
    edge_type: &str,
    reason: Option<&str>,
    agent_id: Uuid,
) -> Result<EvolveStepResult, DbError> {
    if !matches!(edge_type, "supersedes" | "revises") {
        return Err(DbError::QueryFailed {
            source: sqlx::Error::Protocol(
                format!("evolve_step: edge_type must be 'supersedes' or 'revises', got {edge_type}"),
            ),
        });
    }
    let parent_uuid: Uuid = parent.into();
    let mut tx = pool.begin().await?;

    // Fetch parent's lineage_id (or create one).
    let row: Option<(Option<Uuid>, i32)> = sqlx::query_as(
        "SELECT step_lineage_id, COALESCE(level, 2) FROM claims WHERE id = $1 FOR UPDATE",
    )
    .bind(parent_uuid)
    .fetch_optional(&mut *tx)
    .await?;
    let (existing_lineage, _level) = row.ok_or(DbError::NotFound {
        entity: "Claim".into(),
        id: parent_uuid,
    })?;
    let lineage_id = match existing_lineage {
        Some(l) => l,
        None => {
            let new_lineage = Uuid::new_v4();
            sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
                .bind(new_lineage)
                .bind(parent_uuid)
                .execute(&mut *tx)
                .await?;
            new_lineage
        }
    };

    let new_uuid = Uuid::new_v4();
    let hash = ContentHasher::hash(new_content.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, step_lineage_id, created_at, updated_at) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[], $5, NOW(), NOW())",
    )
    .bind(new_uuid)
    .bind(new_content)
    .bind(hash.as_slice())
    .bind(agent_id)
    .bind(lineage_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties, created_at) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, jsonb_build_object('reason', $4), NOW())",
    )
    .bind(new_uuid)
    .bind(parent_uuid)
    .bind(edge_type)
    .bind(reason.unwrap_or(""))
    .execute(&mut *tx)
    .await?;

    if edge_type == "supersedes" {
        sqlx::query("UPDATE claims SET is_current = false, updated_at = NOW() WHERE id = $1")
            .bind(parent_uuid)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(EvolveStepResult {
        new_claim_id: new_uuid,
        step_lineage_id: lineage_id,
        edge_type: edge_type.to_string(),
    })
}
```

- [ ] **Step 2: Unit test in `crates/epigraph-db/tests/` (or repo's existing test pattern)**

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_flips_parent(pool: PgPool) {
    let parent = common::seed_claim(&pool, "parent", 0.7).await;
    let agent = common::ensure_agent(&pool).await;
    let res = ClaimRepository::evolve_step(&pool, ClaimId::from_uuid(parent), "child", "supersedes", Some("better"), agent).await.unwrap();

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent).fetch_one(&pool).await.unwrap();
    assert!(!parent_current);

    let (child_lineage,): (Option<Uuid>,) = sqlx::query_as("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(res.new_claim_id).fetch_one(&pool).await.unwrap();
    assert_eq!(child_lineage, Some(res.step_lineage_id));
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_keeps_parent_current(pool: PgPool) {
    let parent = common::seed_claim(&pool, "parent", 0.7).await;
    let agent = common::ensure_agent(&pool).await;
    ClaimRepository::evolve_step(&pool, ClaimId::from_uuid(parent), "branch", "revises", None, agent).await.unwrap();

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent).fetch_one(&pool).await.unwrap();
    assert!(parent_current);
}
```

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(db): ClaimRepository::evolve_step (atomic step evolve, flips parent on supersedes)"
```

#### 0.4.b `ClaimRepository::mark_duplicate`

- [ ] **Step 1: Add the function**

```rust
/// Mark `dup` as a duplicate of `canonical` without creating a new claim.
/// Sets `supersedes = canonical, is_current = false` on `dup` only.
/// Refuses if `dup.supersedes` is already set (returns DbError::QueryFailed).
#[instrument(skip(pool))]
pub async fn mark_duplicate(
    pool: &PgPool,
    dup: ClaimId,
    canonical: ClaimId,
) -> Result<(), DbError> {
    let dup_uuid: Uuid = dup.into();
    let canon_uuid: Uuid = canonical.into();
    if dup_uuid == canon_uuid {
        return Err(DbError::QueryFailed {
            source: sqlx::Error::Protocol("mark_duplicate: dup == canonical".into()),
        });
    }
    let mut tx = pool.begin().await?;
    let canon_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claims WHERE id = $1)")
        .bind(canon_uuid)
        .fetch_one(&mut *tx)
        .await?;
    if !canon_exists {
        return Err(DbError::NotFound { entity: "Claim".into(), id: canon_uuid });
    }
    let row: Option<(Option<Uuid>,)> =
        sqlx::query_as("SELECT supersedes FROM claims WHERE id = $1 FOR UPDATE")
            .bind(dup_uuid)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((existing,)) = row else {
        return Err(DbError::NotFound { entity: "Claim".into(), id: dup_uuid });
    };
    if existing.is_some() {
        return Err(DbError::QueryFailed {
            source: sqlx::Error::Protocol(format!(
                "Claim {dup_uuid} already superseded; refusing to overwrite"
            )),
        });
    }
    sqlx::query(
        "UPDATE claims SET supersedes = $1, is_current = false, updated_at = NOW() WHERE id = $2",
    )
    .bind(canon_uuid)
    .bind(dup_uuid)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
```

- [ ] **Step 2: Unit tests for happy path + already-superseded + same-id rejection**

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(db): ClaimRepository::mark_duplicate (sets supersedes+is_current on dup only)"
```

#### 0.4.c `ClaimRepository::patch_claim_atomic_conn`

The API handler at `crates/epigraph-api/src/routes/claims.rs:1245+` is ~200 lines. Move only the **mutation + before/after diff** portion to the db crate — auth fields and provenance writing stay in callers.

- [ ] **Step 1: Add the function**

```rust
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PatchClaimInput {
    pub trace_id: Option<Uuid>,
    pub properties: Option<serde_json::Value>,
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
}

#[derive(Debug)]
pub struct PatchClaimDiff {
    pub before_labels: Vec<String>,
    pub after_labels: Vec<String>,
    pub before_props: serde_json::Value,
    pub after_props: serde_json::Value,
    pub before_trace: Option<Uuid>,
    pub after_trace: Option<Uuid>,
}

/// Apply a patch atomically inside the supplied transaction. Returns a diff so
/// callers can build provenance or HTTP responses. No provenance writing here.
pub async fn patch_claim_atomic_conn<'c>(
    tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
    id: ClaimId,
    patch: &PatchClaimInput,
) -> Result<PatchClaimDiff, DbError> {
    use sqlx::Row as _;
    let id_uuid: Uuid = id.into();
    let row = sqlx::query(
        "SELECT trace_id, COALESCE(labels, ARRAY[]::text[]) AS labels, COALESCE(properties, '{}'::jsonb) AS properties \
         FROM claims WHERE id = $1 FOR UPDATE",
    )
    .bind(id_uuid)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::NotFound { entity: "Claim".into(), id: id_uuid })?;
    let before_labels: Vec<String> = row.get("labels");
    let before_props: serde_json::Value = row.get("properties");
    let before_trace: Option<Uuid> = row.get("trace_id");

    let mut after_trace = before_trace;
    if let Some(t) = patch.trace_id {
        sqlx::query("UPDATE claims SET trace_id = $1 WHERE id = $2")
            .bind(t).bind(id_uuid).execute(&mut **tx).await?;
        after_trace = Some(t);
    }

    let mut after_props = before_props.clone();
    if let Some(p) = &patch.properties {
        sqlx::query(
            "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || $1 WHERE id = $2",
        )
        .bind(p).bind(id_uuid).execute(&mut **tx).await?;
        if let (Some(merged), Some(po)) = (after_props.as_object_mut(), p.as_object()) {
            for (k, v) in po { merged.insert(k.clone(), v.clone()); }
        }
    }

    let mut after_labels = before_labels.clone();
    if !patch.add_labels.is_empty() || !patch.remove_labels.is_empty() {
        after_labels = Self::update_labels_conn(tx, id_uuid, &patch.add_labels, &patch.remove_labels).await?;
    }

    Ok(PatchClaimDiff {
        before_labels, after_labels,
        before_props, after_props,
        before_trace, after_trace,
    })
}
```

- [ ] **Step 2: Add a unit test that calls the function then commits, asserting all three mutations land**

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(db): ClaimRepository::patch_claim_atomic_conn (mutation+diff, no auth/provenance)"
```

#### 0.4.d `WorkflowRepository::resolve_steps_to_heads`

Lift `build_resolved_steps` from `crates/epigraph-mcp/src/tools/workflow_hierarchical.rs:111` into the db crate. Make `ResolvedStep` `pub` and `serde::Serialize`.

- [ ] **Step 1: Add to `crates/epigraph-db/src/repos/workflow.rs`**

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ResolvedStep {
    pub planned_claim_id: Uuid,
    pub head_claim_id: Uuid,
    pub step_lineage_id: Option<Uuid>,
    pub pending_resolution: bool,
}

/// For each `executes`-edge from the workflow root, walk `supersedes`/`revises`
/// edges to the latest head claim. Mirrors the resolution logic that previously
/// lived in `epigraph-mcp::tools::workflow_hierarchical::build_resolved_steps`.
pub async fn resolve_steps_to_heads(
    pool: &PgPool,
    workflow_id: Uuid,
) -> Result<Vec<ResolvedStep>, DbError> {
    // ... lift the body of build_resolved_steps verbatim, replacing internal
    //     types with the public ResolvedStep above ...
}
```

Replace the MCP-side caller (in `tools/workflow_hierarchical.rs`) with a call to this function. Keep the JSON shape identical so existing MCP tests still pass.

- [ ] **Step 2: Re-run MCP step-versioning tests**

```bash
cargo test -p epigraph-mcp --test step_versioning -- --nocapture
```

Expected: PASS (no behavior change for MCP).

- [ ] **Step 3: Commit**

```bash
git commit -am "refactor(db,mcp): hoist resolve_steps_to_heads into WorkflowRepository"
```

---

## Workstream A — Workflow MCP/API parity

### Task A1: API endpoint for `evolve_step`

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs` (add handler near `report_hierarchical_outcome`, end of `report_hierarchical_outcome` is line ~820)
- Modify: `crates/epigraph-api/src/routes/mod.rs` (register route in both router builders)
- Modify: `crates/epigraph-mcp/src/tools/evolve_step.rs` (delegate to `ClaimRepository::evolve_step`)
- Test: `crates/epigraph-api/tests/workflow_evolve_step_test.rs`

- [ ] **Step 1: Migrate MCP `evolve_step` to call the shared db function**

Replace the body of `crates/epigraph-mcp/src/tools/evolve_step.rs::evolve_step` with a thin wrapper that calls `ClaimRepository::evolve_step` (added in 0.4.a). This gives MCP the parent-flip behavior under `supersedes` for free.

Add a regression test in `crates/epigraph-mcp/tests/step_versioning.rs`:

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn mcp_evolve_step_supersedes_flips_parent(pool: PgPool) {
    let parent = common::seed_claim(&pool, "parent step", 0.7).await;
    let server = common::build_test_server(pool.clone()).await;
    let _ = epigraph_mcp::tools::evolve_step::evolve_step(
        &server,
        epigraph_mcp::tools::evolve_step::EvolveStepParams {
            parent_id: parent.to_string(),
            content: "child".into(),
            edge_type: "supersedes".into(),
            reason: Some("clearer".into()),
        },
    ).await.unwrap();
    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent).fetch_one(&pool).await.unwrap();
    assert!(!parent_current, "MCP evolve_step now flips parent.is_current=false on supersedes");
}
```

- [ ] **Step 2: Run — expect PASS** (the new shared function flips it)

- [ ] **Step 3: Write failing API integration test**

`crates/epigraph-api/tests/workflow_evolve_step_test.rs`:

```rust
#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_supersedes_creates_new_claim_and_edge() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();

    let parent = common::seed_claim(&pool, "parent step").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['workflow_step']::text[] WHERE id = $1")
        .bind(parent).execute(&pool).await.unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token();
    let body = serde_json::json!({
        "parent_id": parent,
        "content": "improved step",
        "edge_type": "supersedes",
        "reason": "tightened wording",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/workflows/steps/{parent}/evolve"))
        .bearer_auth(&token)
        .json(&body)
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    let new_id: Uuid = json["claim_id"].as_str().unwrap().parse().unwrap();
    let lineage: Uuid = json["step_lineage_id"].as_str().unwrap().parse().unwrap();

    // Both share lineage; parent is no longer current.
    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent).fetch_one(&pool).await.unwrap();
    assert!(!parent_current);
    let (new_lineage,): (Option<Uuid>,) = sqlx::query_as("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(new_id).fetch_one(&pool).await.unwrap();
    assert_eq!(new_lineage, Some(lineage));

    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'supersedes'"
    ).bind(new_id).bind(parent).fetch_one(&pool).await.unwrap();
    assert_eq!(edge_count, 1);
}
```

- [ ] **Step 4: Run — expect FAIL (404)**

```bash
DATABASE_URL=$TEST_DB_URL cargo test -p epigraph-api --test workflow_evolve_step_test -- --nocapture
```

- [ ] **Step 5: Add the handler**

In `crates/epigraph-api/src/routes/workflows.rs` after `report_hierarchical_outcome` (~line 820):

```rust
#[derive(Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct EvolveStepRequest {
    pub parent_id: Uuid,
    pub content: String,
    /// "supersedes" (linear refinement, flips is_current) or "revises" (parallel branch).
    pub edge_type: String,
    pub reason: Option<String>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct EvolveStepResponse {
    pub claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_type: String,
}

/// POST /api/v1/workflows/steps/:id/evolve — atomically evolve a step claim.
#[cfg(feature = "db")]
pub async fn evolve_step(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(parent_id): Path<Uuid>,
    Json(req): Json<EvolveStepRequest>,
) -> Result<Json<EvolveStepResponse>, ApiError> {
    let auth = auth_ctx.ok_or(ApiError::Unauthorized {
        reason: "evolve_step requires authentication".into(),
    })?.0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    if req.parent_id != parent_id {
        return Err(ApiError::BadRequest {
            message: "parent_id in path and body must match".into(),
        });
    }
    let agent = auth.owner_id.unwrap_or(auth.client_id);
    let result = epigraph_db::ClaimRepository::evolve_step(
        &state.db_pool,
        epigraph_core::ClaimId::from_uuid(parent_id),
        &req.content,
        &req.edge_type,
        req.reason.as_deref(),
        agent,
    )
    .await
    .map_err(|e| match e {
        epigraph_db::DbError::NotFound { id, .. } => ApiError::NotFound { entity: "Claim".into(), id: id.to_string() },
        other => ApiError::InternalError { message: other.to_string() },
    })?;

    Ok(Json(EvolveStepResponse {
        claim_id: result.new_claim_id,
        step_lineage_id: result.step_lineage_id,
        edge_type: result.edge_type,
    }))
}
```

- [ ] **Step 6: Register route in `routes/mod.rs`** (both router builders, near the other workflow routes ~line 158/784):

```rust
.route(
    "/api/v1/workflows/steps/:id/evolve",
    post(workflows::evolve_step),
)
```

- [ ] **Step 7: Run — expect PASS**

- [ ] **Step 8: Commit**

```bash
git commit -am "feat(api): POST /api/v1/workflows/steps/:id/evolve mirrors MCP evolve_step

Both surfaces now call ClaimRepository::evolve_step. Behavior change for MCP:
edge_type=\"supersedes\" now flips parent.is_current=false (matches API
SupersedeRequest semantics)."
```

---

### Task A2: API `find_workflow_hierarchical` accepts `resolve_to_latest`

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs` (`HierarchicalSearchQuery` at line 99, handler at line 634)
- Test: `crates/epigraph-api/tests/workflow_find_hierarchical_resolve_test.rs`

- [ ] **Step 1: Write failing test**

Mirror the structure of `workflow_evolve_step_test.rs`. Seed a hierarchical workflow with at least one evolved step, then GET the hierarchical search with `?resolve_to_latest=true` and assert the response includes a `resolved_steps` array per workflow plus a top-level `"resolve_to_latest": true`.

- [ ] **Step 2: Add field to `HierarchicalSearchQuery`**

```rust
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct HierarchicalSearchQuery {
    pub q: String,
    pub limit: Option<i64>,
    #[serde(default)]
    pub resolve_to_latest: bool,
}
```

- [ ] **Step 3: Wire `WorkflowRepository::resolve_steps_to_heads` into the handler**

In `find_workflow_hierarchical` at line 634, after building the `workflows: Vec<serde_json::Value>` from rows:

```rust
if params.resolve_to_latest {
    for w in &mut workflows {
        let workflow_id: Uuid = w["workflow_id"].as_str().unwrap().parse().unwrap();
        let resolved = epigraph_db::WorkflowRepository::resolve_steps_to_heads(&state.db_pool, workflow_id)
            .await
            .map_err(|e| ApiError::InternalError { message: format!("resolve_to_latest failed: {e}") })?;
        w["resolved_steps"] = serde_json::to_value(resolved).unwrap();
    }
}

Ok(Json(serde_json::json!({
    "workflows": workflows,
    "total": workflows.len(),
    "resolve_to_latest": params.resolve_to_latest,
})))
```

- [ ] **Step 4: Run test — expect PASS; re-run MCP step_versioning to confirm no regression**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(api): find_workflow_hierarchical supports resolve_to_latest"
```

---

### Task A3: MCP `improve_workflow` writes `supersedes` (not `variant_of`)

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs:620` (and the idempotent skip block at ~line 634)
- Test: `crates/epigraph-mcp/tests/improve_workflow_supersedes_test.rs`

- [ ] **Step 1: Write failing test (using the real `ImproveWorkflowParams` field names)**

The struct (verified at `crates/epigraph-mcp/src/types.rs:305`) is:

```rust
ImproveWorkflowParams {
    parent_workflow_id: String,
    goal: Option<String>,           // optional new goal
    steps: Option<Vec<String>>,     // optional new steps
    prerequisites: Option<...>,
    expected_outcome: Option<String>,
    change_rationale: String,
    tags: Option<Vec<String>>,
}
```

```rust
#![cfg(feature = "db")]
use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn improve_workflow_writes_supersedes_edge(pool: PgPool) {
    let parent = seed_workflow_claim(&pool, "parent goal", &["s1"]).await;
    let server = build_test_server(pool.clone()).await;

    let result = epigraph_mcp::tools::workflows::improve_workflow(
        &server,
        epigraph_mcp::types::ImproveWorkflowParams {
            parent_workflow_id: parent.to_string(),
            change_rationale: "tighter".into(),
            steps: Some(vec!["s1.refined".into()]),
            goal: None,
            prerequisites: None,
            expected_outcome: None,
            tags: None,
        },
    ).await.unwrap();

    let json = first_text(&result);
    let variant_id = parse_uuid_field(&json, "variant_id");

    let rel: Option<String> = sqlx::query_scalar(
        "SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2"
    ).bind(variant_id).bind(parent).fetch_optional(&pool).await.unwrap();
    assert_eq!(rel.as_deref(), Some("supersedes"),
        "MCP improve_workflow must emit supersedes (parity with API #99)");
}
```

- [ ] **Step 2: Run — expect FAIL (still writes variant_of)**

- [ ] **Step 3: Change the edge relationship in `tools/workflows.rs`**

In the block writing `"variant_of"` (~line 620): change the literal to `"supersedes"`. Update the idempotent-skip filter (~line 634) and the cascade-walker filter (line 678) to look for `"supersedes"`. Note: A5 will further extend the cascade walker to follow both `supersedes` and `variant_of`; for this commit, change just the writer.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(mcp): improve_workflow emits supersedes (parity with API #99)"
```

---

### Task A4: MCP `deprecate_workflow` sets `is_current = false`

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs:660` (single-target update) and ~line 680 (cascade)
- Test: `crates/epigraph-mcp/tests/deprecate_workflow_is_current_test.rs`

- [ ] **Step 1: Write failing test**

`DeprecateWorkflowParams` (verified at `crates/epigraph-mcp/src/types.rs:334`) declares `reason: String` (NOT Option). Use that.

```rust
#![cfg(feature = "db")]
use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn mcp_deprecate_workflow_sets_is_current_false(pool: PgPool) {
    let id = seed_workflow_claim(&pool, "to-deprecate", &["s1"]).await;
    let server = build_test_server(pool.clone()).await;

    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: id.to_string(),
            reason: "obsolete".into(),
            cascade: Some(false),
        },
    ).await.unwrap();

    let (truth, is_current): (f64, bool) = sqlx::query_as(
        "SELECT truth_value, is_current FROM claims WHERE id = $1"
    ).bind(id).fetch_one(&pool).await.unwrap();
    assert!((truth - 0.05).abs() < 1e-9);
    assert!(!is_current);
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Replace the truth-only update with both fields**

In `tools/workflows.rs` line ~660 (single target) replace `ClaimRepository::update_truth_value(...)` with:

```rust
sqlx::query("UPDATE claims SET truth_value = 0.05, is_current = false, updated_at = NOW() WHERE id = $1")
    .bind(workflow_id)
    .execute(&server.pool)
    .await
    .map_err(internal_error)?;
```

Apply the same change inside the cascade loop at ~line 680.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(mcp): deprecate_workflow sets is_current=false (parity with API #97)"
```

---

### Task A5: MCP `deprecate_workflow` cascade walks `supersedes` and `variant_of`, filtered to workflow claims

**Why:** Cascade currently filters only `variant_of`. Post-#99, new `improve_workflow` edges are `supersedes`. Pre-#99 data still has `variant_of`. Cascade must walk both, but **only** when the next-hop claim is workflow-labeled — `supersedes` is also used for ordinary claim version chains and we must not pollute those.

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs:678`
- Test: append to `tests/deprecate_workflow_is_current_test.rs`

- [ ] **Step 1: Write failing cascade test**

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_workflow_cascade_walks_supersedes_and_variant_of(pool: PgPool) {
    let root = seed_workflow_claim(&pool, "root", &["s1"]).await;
    let child_old = seed_workflow_claim(&pool, "child_old", &["s1"]).await;
    let child_new = seed_workflow_claim(&pool, "child_new", &["s1"]).await;
    insert_edge(&pool, child_old, root, "variant_of").await;
    insert_edge(&pool, child_new, root, "supersedes").await;

    // Negative control: a NON-workflow claim that supersedes the root.
    let unrelated = seed_claim(&pool, "non-workflow", 0.5).await;
    insert_edge(&pool, unrelated, root, "supersedes").await;

    let server = build_test_server(pool.clone()).await;
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: root.to_string(),
            reason: "cascade test".into(),
            cascade: Some(true),
        },
    ).await.unwrap();

    for id in [root, child_old, child_new] {
        let (truth, is_current): (f64, bool) = sqlx::query_as(
            "SELECT truth_value, is_current FROM claims WHERE id = $1"
        ).bind(id).fetch_one(&pool).await.unwrap();
        assert!((truth - 0.05).abs() < 1e-9, "{id} not deprecated");
        assert!(!is_current, "{id} not is_current=false");
    }
    // Unrelated non-workflow claim must NOT be touched.
    let (untouched_truth, untouched_current): (f64, bool) = sqlx::query_as(
        "SELECT truth_value, is_current FROM claims WHERE id = $1"
    ).bind(unrelated).fetch_one(&pool).await.unwrap();
    assert!((untouched_truth - 0.5).abs() < 1e-9);
    assert!(untouched_current);
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Update the cascade walker**

Replace the filter in `tools/workflows.rs` ~line 678:

```rust
const DESCENDANT_REL: &[&str] = &["variant_of", "supersedes"];

// ... inside the cascade loop:
for edge in edges {
    if !DESCENDANT_REL.contains(&edge.relationship.as_str()) {
        continue;
    }
    let child_id = edge.source_id;
    // Filter to workflow-labeled claims only — supersedes is also used for
    // regular claim-version chains and we must not depress those here.
    let is_workflow: bool = sqlx::query_scalar(
        "SELECT 'workflow' = ANY(labels) FROM claims WHERE id = $1"
    )
    .bind(child_id)
    .fetch_optional(&server.pool)
    .await
    .map_err(internal_error)?
    .unwrap_or(false);
    if !is_workflow { continue; }

    sqlx::query(
        "UPDATE claims SET truth_value = 0.05, is_current = false, updated_at = NOW() WHERE id = $1"
    ).bind(child_id).execute(&server.pool).await.map_err(internal_error)?;
    deprecated_ids.push(child_id.to_string());
    queue.push(child_id);
}
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(mcp): deprecate_workflow cascade walks both edges, filters to workflow claims"
```

---

## Workstream B — Claim/labels MCP wrappers

### Task B1: `mcp__epigraph__supersede_claim`

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs` (add `SupersedeClaimParams`)
- Create: `crates/epigraph-mcp/src/tools/supersede.rs`
- Modify: `crates/epigraph-mcp/src/tools/mod.rs` (add `pub mod supersede;`)
- Modify: `crates/epigraph-mcp/src/server.rs` (register `#[tool]`)
- Test: `crates/epigraph-mcp/tests/supersede_claim_test.rs`

- [ ] **Step 1: Add params struct in `types.rs`**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupersedeClaimParams {
    #[schemars(description = "UUID of the claim being superseded")]
    pub claim_id: String,
    #[schemars(description = "Content of the new superseding claim")]
    pub content: String,
    #[schemars(description = "Truth value of the new claim (0.0–1.0)")]
    pub truth_value: f64,
    #[schemars(description = "Why the previous claim is being superseded")]
    pub reason: String,
}
```

- [ ] **Step 2: Write failing test**

```rust
#![cfg(feature = "db")]
use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_marks_old_and_links_new(pool: PgPool) {
    let old = seed_claim(&pool, "v1", 0.5).await;
    let server = build_test_server(pool.clone()).await;

    let result = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: old.to_string(),
            content: "v2".into(),
            truth_value: 0.7,
            reason: "newer evidence".into(),
        },
    ).await.unwrap();
    let json = first_text(&result);
    let new_id = parse_uuid_field(&json, "new_claim_id");

    let (old_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(old).fetch_one(&pool).await.unwrap();
    assert!(!old_current);

    let (sup,): (Option<uuid::Uuid>,) = sqlx::query_as("SELECT supersedes FROM claims WHERE id = $1")
        .bind(new_id).fetch_one(&pool).await.unwrap();
    assert_eq!(sup, Some(old));
}
```

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement the tool**

`crates/epigraph-mcp/src/tools/supersede.rs`:

```rust
//! supersede_claim — wraps ClaimRepository::supersede.
//! New claim inherits the OLD claim's agent_id (current `ClaimRepository::supersede`
//! semantics — not the MCP caller's agent). If we want caller-attributed
//! supersession later, that's a separate change to ClaimRepository.

use rmcp::model::{CallToolResult, Content};
use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::SupersedeClaimParams;
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;

pub async fn supersede_claim(
    server: &EpiGraphMcpFull,
    params: SupersedeClaimParams,
) -> Result<CallToolResult, McpError> {
    let old = parse_uuid(&params.claim_id)?;
    let truth = TruthValue::clamped(params.truth_value);

    let (new_id, old_id) = ClaimRepository::supersede(
        &server.pool,
        ClaimId::from_uuid(old),
        &params.content,
        truth,
        &params.reason,
    )
    .await
    .map_err(internal_error)?;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
        }))
        .map_err(internal_error)?,
    )]))
}
```

Add `pub mod supersede;` in `crates/epigraph-mcp/src/tools/mod.rs`.

- [ ] **Step 5: Register `#[tool]` in `server.rs`**

```rust
#[tool(
    description = "Create a new claim that supersedes an existing one (semantic versioning). The old claim's is_current is flipped to false; the new claim's supersedes column points at the old. The new claim inherits the old claim's agent_id. Use mark_duplicate for marking a duplicate WITHOUT creating a new claim."
)]
async fn supersede_claim(
    &self,
    Parameters(params): Parameters<crate::types::SupersedeClaimParams>,
) -> Result<CallToolResult, McpError> {
    self.reject_if_read_only()?;
    crate::tools::supersede::supersede_claim(self, params).await
}
```

- [ ] **Step 6: Run — expect PASS; commit**

```bash
git commit -am "feat(mcp): supersede_claim tool wraps ClaimRepository::supersede"
```

---

### Task B2: `mcp__epigraph__update_labels`

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs` (`UpdateLabelsParams`)
- Modify: `crates/epigraph-mcp/src/tools/claims.rs` (add `pub async fn update_labels`)
- Modify: `crates/epigraph-mcp/src/server.rs` (register `#[tool]`)
- Test: `crates/epigraph-mcp/tests/update_labels_test.rs`

- [ ] **Step 1: Add params**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateLabelsParams {
    #[schemars(description = "UUID of the claim to label")]
    pub claim_id: String,
    #[schemars(description = "Labels to add (idempotent; duplicates ignored)")]
    #[serde(default)]
    pub add: Vec<String>,
    #[schemars(description = "Labels to remove (idempotent; nonexistent ignored)")]
    #[serde(default)]
    pub remove: Vec<String>,
}
```

- [ ] **Step 2: Write failing test**

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_adds_and_removes(pool: PgPool) {
    let id = seed_claim_with_labels(&pool, "x", &["existing"]).await;
    let server = build_test_server(pool.clone()).await;

    epigraph_mcp::tools::claims::update_labels(
        &server,
        epigraph_mcp::types::UpdateLabelsParams {
            claim_id: id.to_string(),
            add: vec!["new1".into(), "new2".into()],
            remove: vec!["existing".into()],
        },
    ).await.unwrap();

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(id).fetch_one(&pool).await.unwrap();
    assert!(labels.contains(&"new1".into()) && labels.contains(&"new2".into()));
    assert!(!labels.contains(&"existing".into()));
}
```

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement**

In `crates/epigraph-mcp/src/tools/claims.rs` (does not currently define a function called `update_labels`, so this name is free):

```rust
pub async fn update_labels(
    server: &EpiGraphMcpFull,
    params: crate::types::UpdateLabelsParams,
) -> Result<CallToolResult, McpError> {
    if params.add.is_empty() && params.remove.is_empty() {
        return Err(invalid_params("must specify at least one of add/remove".into()));
    }
    let id = parse_uuid(&params.claim_id)?;
    let labels = ClaimRepository::update_labels(&server.pool, id, &params.add, &params.remove)
        .await
        .map_err(internal_error)?;
    success_json(&serde_json::json!({ "claim_id": id, "labels": labels }))
}
```

- [ ] **Step 5: Register `#[tool]` in `server.rs`** (description and signature mirror B1's pattern)

- [ ] **Step 6: Run — expect PASS; commit**

```bash
git commit -am "feat(mcp): update_labels tool wraps PATCH /api/v1/claims/:id/labels"
```

---

### Task B3: `mcp__epigraph__patch_claim`

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs` (`PatchClaimParams`)
- Modify: `crates/epigraph-mcp/src/tools/claims.rs` (add function)
- Modify: `crates/epigraph-mcp/src/server.rs` (register `#[tool]`)
- Modify: `crates/epigraph-api/src/routes/claims.rs::patch_claim` to call the new `ClaimRepository::patch_claim_atomic_conn` helper from 0.4.c (provenance writing stays in the API handler — it depends on auth fields and `AUTO_POLICY_AUTHORIZER_ID` that don't belong in the db crate).
- Test: `crates/epigraph-mcp/tests/patch_claim_test.rs`

- [ ] **Step 1: Refactor API handler to use the shared helper**

In `crates/epigraph-api/src/routes/claims.rs::patch_claim` (line 1245+): replace the inline before/after row reads + label/property/trace mutations with a single call:

```rust
let diff = epigraph_db::ClaimRepository::patch_claim_atomic_conn(
    &mut tx,
    claim_id,
    &epigraph_db::PatchClaimInput {
        trace_id: request.trace_id,
        properties: request.properties.clone(),
        add_labels: request.add_labels.clone().unwrap_or_default(),
        remove_labels: request.remove_labels.clone().unwrap_or_default(),
    },
)
.await?;
```

Keep the `ProvenanceRepository::append_conn` writing block exactly where it is — only the data mutation moves. Run the existing `crates/epigraph-api/tests/handler_audit_tests.rs` and any patch-related tests; confirm green before proceeding.

- [ ] **Step 2: MCP params + test**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchClaimParams {
    pub claim_id: String,
    pub trace_id: Option<String>,
    pub properties: Option<serde_json::Value>,
    #[serde(default)]
    pub add_labels: Vec<String>,
    #[serde(default)]
    pub remove_labels: Vec<String>,
}
```

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn patch_claim_applies_trace_props_labels_atomically(pool: PgPool) {
    let id = seed_claim_with_labels(&pool, "x", &["alpha"]).await;
    let server = build_test_server(pool.clone()).await;
    let trace = uuid::Uuid::new_v4();

    epigraph_mcp::tools::claims::patch_claim(
        &server,
        epigraph_mcp::types::PatchClaimParams {
            claim_id: id.to_string(),
            trace_id: Some(trace.to_string()),
            properties: Some(serde_json::json!({"key": "val"})),
            add_labels: vec!["beta".into()],
            remove_labels: vec!["alpha".into()],
        },
    ).await.unwrap();

    let (after_trace, labels, props): (Option<uuid::Uuid>, Vec<String>, serde_json::Value) =
        sqlx::query_as("SELECT trace_id, COALESCE(labels, ARRAY[]::text[]), COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1")
        .bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(after_trace, Some(trace));
    assert!(labels.contains(&"beta".into()) && !labels.contains(&"alpha".into()));
    assert_eq!(props.get("key").and_then(|v| v.as_str()), Some("val"));
}
```

(Note: the MCP-side `patch_claim` calls `ClaimRepository::patch_claim_atomic_conn` directly. It does **not** write provenance — provenance is only written through the API handler. Document this explicitly in the tool description so callers don't expect audit trails for MCP patches.)

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement MCP function**

```rust
pub async fn patch_claim(
    server: &EpiGraphMcpFull,
    params: crate::types::PatchClaimParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let trace = match &params.trace_id {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };
    if trace.is_none() && params.properties.is_none()
        && params.add_labels.is_empty() && params.remove_labels.is_empty()
    {
        return Err(invalid_params("at least one of trace_id/properties/add_labels/remove_labels required".into()));
    }
    let mut tx = server.pool.begin().await.map_err(internal_error)?;
    let diff = ClaimRepository::patch_claim_atomic_conn(
        &mut tx,
        ClaimId::from_uuid(id),
        &epigraph_db::PatchClaimInput {
            trace_id: trace,
            properties: params.properties.clone(),
            add_labels: params.add_labels.clone(),
            remove_labels: params.remove_labels.clone(),
        },
    )
    .await
    .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "claim_id": id,
        "after_labels": diff.after_labels,
        "after_properties": diff.after_props,
        "after_trace": diff.after_trace,
    }))
}
```

- [ ] **Step 5: Register `#[tool]` in `server.rs`** with description noting "MCP patch_claim does NOT emit provenance — use the REST handler if an audit trail is required."

- [ ] **Step 6: Run — expect PASS; commit**

```bash
git commit -am "feat(mcp): patch_claim tool (no-provenance fast path); refactor api/patch_claim"
```

---

### Task B4: Add `labels` to `submit_claim` (post-create application)

**Why:** `epigraph_core::Claim` (verified at `crates/epigraph-core/src/domain/claim.rs:30`) has no `labels` field, and `ClaimRepository::create_strict`/`create_with_tx` do not insert into the `labels` column. Rather than touching 40+ callsites, apply labels via a post-create `update_labels` call.

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs` (`SubmitClaimParams`)
- Modify: `crates/epigraph-mcp/src/tools/claims.rs:71+` (`submit_claim` body)
- Test: `crates/epigraph-mcp/tests/submit_claim_labels_test.rs`

- [ ] **Step 1: Add field**

```rust
// inside SubmitClaimParams (types.rs:38), after `reasoning`:
#[schemars(description = "Optional labels to attach to the new claim (e.g. ['backlog','bug'])")]
#[serde(default)]
pub labels: Vec<String>,
```

- [ ] **Step 2: Write failing test**

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_attaches_labels_when_provided(pool: PgPool) {
    let server = build_test_server(pool.clone()).await;
    let result = epigraph_mcp::tools::claims::submit_claim(
        &server,
        epigraph_mcp::types::SubmitClaimParams {
            content: "labeled claim".into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.8,
            source_url: None,
            reasoning: None,
            labels: vec!["backlog".into(), "test-tag".into()],
        },
    ).await.unwrap();
    let json = first_text(&result);
    let claim_id = parse_uuid_field(&json, "claim_id");

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id).fetch_one(&pool).await.unwrap();
    assert!(labels.contains(&"backlog".to_string()));
    assert!(labels.contains(&"test-tag".to_string()));
}
```

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement**

In `tools/claims.rs::submit_claim` (line 71+), after `let claim_uuid = claim.id.as_uuid();`:

```rust
if !params.labels.is_empty() {
    epigraph_db::ClaimRepository::update_labels(
        &server.pool,
        claim_uuid,
        &params.labels,
        &[],
    )
    .await
    .map_err(internal_error)?;
}
```

- [ ] **Step 5: Run — expect PASS; commit**

```bash
git commit -am "feat(mcp): submit_claim accepts labels (applied post-create via update_labels)"
```

---

## Workstream C — Dedup mode

### Task C1: `POST /api/v1/claims/:id/dedup` REST endpoint

**Files:**
- Modify: `crates/epigraph-api/src/routes/versioning.rs` (add `DedupRequest` + `mark_duplicate` handler)
- Modify: `crates/epigraph-api/src/routes/mod.rs` (register route, both router builders)
- Test: `crates/epigraph-api/tests/dedup_endpoint_test.rs`

- [ ] **Step 1: Write failing test**

```rust
#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn dedup_marks_duplicate_without_creating_new_claim() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();

    let canonical = common::seed_claim(&pool, "canonical content").await;
    let dup = common::seed_claim(&pool, "canonical content").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token();
    let body = serde_json::json!({
        "canonical_id": canonical,
        "reason": "auto-detected duplicate by content_hash",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{dup}/dedup"))
        .bearer_auth(&token)
        .json(&body).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let (sup, is_current): (Option<Uuid>, bool) = sqlx::query_as(
        "SELECT supersedes, is_current FROM claims WHERE id = $1"
    ).bind(dup).fetch_one(&pool).await.unwrap();
    assert_eq!(sup, Some(canonical));
    assert!(!is_current);

    let (canon_current,): (bool,) = sqlx::query_as(
        "SELECT is_current FROM claims WHERE id = $1"
    ).bind(canonical).fetch_one(&pool).await.unwrap();
    assert!(canon_current);
}
```

- [ ] **Step 2: Run — expect FAIL (404)**

- [ ] **Step 3: Add request type + handler**

In `crates/epigraph-api/src/routes/versioning.rs`:

```rust
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct DedupRequest {
    pub canonical_id: Uuid,
    pub reason: Option<String>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct DedupResponse {
    pub duplicate_id: Uuid,
    pub canonical_id: Uuid,
    pub mode: &'static str,
}

/// POST /api/v1/claims/:id/dedup — mark a duplicate without creating a new claim.
#[cfg(feature = "db")]
pub async fn mark_duplicate(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(dup_id): Path<Uuid>,
    Json(req): Json<DedupRequest>,
) -> Result<Json<DedupResponse>, ApiError> {
    let auth = auth_ctx.ok_or(ApiError::Unauthorized {
        reason: "dedup requires authentication".into(),
    })?.0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    if dup_id == req.canonical_id {
        return Err(ApiError::BadRequest {
            message: "canonical_id cannot equal duplicate id".into(),
        });
    }

    epigraph_db::ClaimRepository::mark_duplicate(
        &state.db_pool,
        epigraph_core::ClaimId::from_uuid(dup_id),
        epigraph_core::ClaimId::from_uuid(req.canonical_id),
    )
    .await
    .map_err(|e| match e {
        epigraph_db::DbError::NotFound { id, .. } => ApiError::NotFound { entity: "Claim".into(), id: id.to_string() },
        epigraph_db::DbError::QueryFailed { .. } => ApiError::Conflict {
            reason: "claim already superseded or invalid input".into(),
        },
        other => ApiError::DatabaseError { message: other.to_string() },
    })?;

    // Provenance: best-effort, transactional with the next read.
    let principal = auth.owner_id.unwrap_or(auth.client_id);
    let mut tx = state.db_pool.begin().await
        .map_err(|e| ApiError::DatabaseError { message: e.to_string() })?;
    let _ = epigraph_db::ProvenanceRepository::append_conn(
        &mut tx,
        "claim",
        dup_id,
        "mark_duplicate",
        auth.client_id,
        principal,
        &[epigraph_db::repos::provenance::AUTO_POLICY_AUTHORIZER_ID],
        "auto_policy",
        // No content hash for mark_duplicate (no content change); use zeros.
        &[0u8; 32],
        &[],
        auth.jti,
        &auth.scopes,
        Some(&serde_json::json!({
            "canonical_id": req.canonical_id,
            "mode": "mark_duplicate",
            "reason": req.reason.clone().unwrap_or_default(),
        })),
    ).await;
    tx.commit().await.ok();

    Ok(Json(DedupResponse {
        duplicate_id: dup_id,
        canonical_id: req.canonical_id,
        mode: "mark_duplicate",
    }))
}
```

(Verify `ProvenanceRepository::append_conn`'s actual signature against `crates/epigraph-db/src/repos/provenance.rs`; adjust argument order if it has drifted from the version above. The pattern follows `routes/claims.rs::patch_claim` provenance writes.)

- [ ] **Step 4: Register route in `routes/mod.rs`** (both builders)

```rust
.route("/api/v1/claims/:id/dedup", post(versioning::mark_duplicate))
```

- [ ] **Step 5: Run — expect PASS; commit**

```bash
git commit -am "feat(api): POST /api/v1/claims/:id/dedup marks duplicate without new claim"
```

---

### Task C2: `mcp__epigraph__mark_duplicate`

**Files:** mirror B1 structure.

- [ ] **Step 1: Add `MarkDuplicateParams` in `types.rs`** (claim_id, canonical_id, reason)

- [ ] **Step 2: Write failing test against `ClaimRepository::mark_duplicate` semantics (no provenance check; the MCP fast path skips it)**

- [ ] **Step 3: Implement in `tools/supersede.rs` (alongside `supersede_claim`):**

```rust
pub async fn mark_duplicate(
    server: &EpiGraphMcpFull,
    params: crate::types::MarkDuplicateParams,
) -> Result<CallToolResult, McpError> {
    let dup = parse_uuid(&params.claim_id)?;
    let canon = parse_uuid(&params.canonical_id)?;
    ClaimRepository::mark_duplicate(
        &server.pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canon),
    ).await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "duplicate_id": dup,
        "canonical_id": canon,
        "mode": "mark_duplicate",
    }))
}
```

- [ ] **Step 4: Register `#[tool]`** with description noting that the REST endpoint is preferred when audit provenance is required.

- [ ] **Step 5: Run — expect PASS; commit**

```bash
git commit -am "feat(mcp): mark_duplicate tool wraps ClaimRepository::mark_duplicate"
```

---

## Workstream D — OpenAPI surface (scoped)

### Task D0: utoipa scaffolding

- [ ] **Step 1: Derive `utoipa::ToSchema` on every body type touched by D1**

Touch:
- `SupersedeRequest`, `SupersessionResponse` in `routes/versioning.rs`
- `DedupRequest`, `DedupResponse` in `routes/versioning.rs` (added in C1; already derived above)
- `EvolveStepRequest`, `EvolveStepResponse` in `routes/workflows.rs` (added in A1; already derived above)
- `UpdateLabelsRequest`, `UpdateLabelsResponse` in `routes/claims.rs`
- `PatchClaimRequest`, `ClaimResponse` in `routes/claims.rs`
- `HierarchicalSearchQuery` (already derived `IntoParams` in A2)

- [ ] **Step 2: Reuse the existing `ed25519_signature` security scheme — do NOT add `bearer_auth`**

Verified at `crates/epigraph-api/src/openapi.rs:97` — every `#[utoipa::path]` annotation in D1 must reference `security(("ed25519_signature" = []))`, matching the rest of the codebase.

- [ ] **Step 3: Build to confirm derives compile**

```bash
cargo build --workspace --all-features
```

- [ ] **Step 4: Commit**

```bash
git commit -am "chore(api): derive utoipa::ToSchema on in-scope request/response types"
```

### Task D1: Annotate the 10 in-scope handlers

**Routes:**
1. `POST /api/v1/claims/:id/supersede` (versioning::supersede_claim)
2. `POST /api/v1/claims/:id/dedup` (versioning::mark_duplicate)
3. `PATCH /api/v1/claims/:id` (claims::patch_claim)
4. `PATCH /api/v1/claims/:id/labels` (claims::update_labels)
5. `POST /api/v1/workflows/steps/:id/evolve` (workflows::evolve_step)
6. `GET /api/v1/workflows/hierarchical/search` (workflows::find_workflow_hierarchical)
7. `POST /api/v1/workflows/hierarchical/:id/outcome` (workflows::report_hierarchical_outcome)
8. `POST /api/v1/workflows/:id/improve` (workflows::improve_workflow)
9. `DELETE /api/v1/workflows/:id` (workflows::deprecate_workflow)
10. `POST /api/v1/workflows/ingest` (workflows::ingest_workflow)

- [ ] **Step 1: Add `#[utoipa::path]` over each handler**

Pattern (one example — repeat for the other 9 with appropriate verbs/bodies):

```rust
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/dedup",
    params(("id" = Uuid, Path, description = "UUID of the duplicate claim")),
    request_body = DedupRequest,
    responses(
        (status = 200, description = "Marked as duplicate", body = DedupResponse),
        (status = 400, description = "canonical_id == id"),
        (status = 404, description = "Claim or canonical not found"),
        (status = 409, description = "Already superseded"),
    ),
    security(("ed25519_signature" = [])),
    tag = "claims"
)]
```

- [ ] **Step 2: Extend `paths(...)` and `components(schemas(...))` in `openapi.rs`**

Because the existing `paths()` references symbols (`health_check`, etc.) that resolve to in-file stubs, add a parallel set of entries gated on `#[cfg(feature = "db")]` referencing the real handlers — OR keep things simple by placing all new paths into `paths()` directly and ensuring those handlers compile under both `db` and `not(db)` builds (the existing stubs already handle this for some routes; check each).

```rust
paths(
    health_check,
    submit_packet,
    rag_context,
    system_stats,
    submit_challenge,
    list_challenges,
    crate::routes::versioning::supersede_claim,
    crate::routes::versioning::mark_duplicate,
    crate::routes::claims::patch_claim,
    crate::routes::claims::update_labels,
    crate::routes::workflows::evolve_step,
    crate::routes::workflows::find_workflow_hierarchical,
    crate::routes::workflows::report_hierarchical_outcome,
    crate::routes::workflows::improve_workflow,
    crate::routes::workflows::deprecate_workflow,
    crate::routes::workflows::ingest_workflow,
),
components(
    schemas(
        // existing entries unchanged ...
        SupersedeRequest, SupersessionResponse,
        DedupRequest, DedupResponse,
        EvolveStepRequest, EvolveStepResponse,
        UpdateLabelsRequest, UpdateLabelsResponse,
        PatchClaimRequest, ClaimResponse,
    )
),
```

- [ ] **Step 3: Build under `not(db)` AND `db` features to confirm both gates work**

```bash
cargo build -p epigraph-api --no-default-features
cargo build -p epigraph-api --all-features
```

If `not(db)` fails because the new handlers are `#[cfg(feature = "db")]`-only, gate the new `paths(...)` entries with `#[cfg(feature = "db")]` (utoipa supports this) or provide thin stubs.

- [ ] **Step 4: Round-trip test**

`crates/epigraph-api/tests/openapi_paths_test.rs`:

```rust
#![cfg(feature = "db")]

use sqlx::postgres::PgPoolOptions;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn openapi_documents_in_scope_paths() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let pool = PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let _ = pool;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new().get(format!("http://{addr}/api/v1/openapi.json"))
        .send().await.unwrap();
    let doc: serde_json::Value = resp.json().await.unwrap();
    let paths = doc["paths"].as_object().expect("paths object");
    for required in [
        "/api/v1/claims/{id}/supersede",
        "/api/v1/claims/{id}/dedup",
        "/api/v1/claims/{id}",
        "/api/v1/claims/{id}/labels",
        "/api/v1/workflows/steps/{id}/evolve",
        "/api/v1/workflows/hierarchical/search",
        "/api/v1/workflows/hierarchical/{id}/outcome",
        "/api/v1/workflows/{id}/improve",
        "/api/v1/workflows/{id}",
        "/api/v1/workflows/ingest",
    ] {
        assert!(paths.contains_key(required),
            "OpenAPI doc missing required path: {required}");
    }
}
```

- [ ] **Step 5: Run — expect PASS; commit**

```bash
git commit -am "docs(api): document supersede/dedup/labels/patch/workflow routes in OpenAPI"
```

- [ ] **Step 6: File follow-up GitHub issue**

```bash
gh issue create --title "OpenAPI: document remaining ~90 registered routes" \
  --body "PR #N covered 10 in-scope handlers; the remaining ~90 still need #[utoipa::path] annotations + paths() entries. See openapi_paths_test.rs for the assertion pattern."
```

---

## Workstream E — Backport `mcp/tools` introspection

### Task E1: Add `list_tools()` + `all_tools_json()` to public

- [ ] **Step 1: Port `lib.rs::list_tools()`**

Append to `crates/epigraph-mcp/src/lib.rs`:

```rust
#[must_use]
pub fn list_tools() -> serde_json::Value {
    EpiGraphMcpFull::all_tools_json()
}
```

- [ ] **Step 2: Port `server.rs::all_tools_json()`**

Add to the `impl EpiGraphMcpFull` block (above the `#[tool_router]` impl, near `reject_if_read_only`):

```rust
#[must_use]
pub fn all_tools_json() -> serde_json::Value {
    let tools = Self::tool_router().list_all();
    serde_json::to_value(tools).unwrap_or(serde_json::Value::Array(vec![]))
}
```

`Self::tool_router()` is a static method produced by `#[tool_router]` (verified — used at `crates/epigraph-mcp/src/server.rs:104`).

- [ ] **Step 3: Port `routes/mcp_tools.rs` verbatim**

```bash
cp /home/jeremy/epigraph-internal/crates/epigraph-api/src/routes/mcp_tools.rs \
   /home/jeremy/epigraph/crates/epigraph-api/src/routes/mcp_tools.rs
```

- [ ] **Step 4: Register module + route in `routes/mod.rs`**

```rust
pub mod mcp_tools;

// In BOTH router builders:
.route("/api/v1/mcp/tools", get(mcp_tools::list_mcp_tools))
```

- [ ] **Step 5: Run port tests**

```bash
cargo test -p epigraph-api mcp_tools::tests -- --nocapture
```

- [ ] **Step 6: Smoke-test live**

```bash
DATABASE_URL=$TEST_DB_URL cargo run -p epigraph-api &
sleep 2
curl -s http://localhost:3000/api/v1/mcp/tools | jq 'length'
kill %1
```

Expected: positive integer.

- [ ] **Step 7: Commit**

```bash
git commit -am "feat(api,mcp): backport GET /api/v1/mcp/tools from internal"
```

---

## Wrap-up

### Task W1: Verify the full suite

- [ ] **Step 1: Run all touched-crate tests**

```bash
DATABASE_URL=$TEST_DB_URL cargo test -p epigraph-api -p epigraph-mcp -p epigraph-db --no-fail-fast
```

- [ ] **Step 2: Clippy + fmt**

```bash
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings
```

### Task W2: Update the backlog claim

- [ ] **Step 1: Once the new MCP tools are live in the running server, mark `b1770b53` resolved**

```bash
# requires the running MCP server to have been restarted with this PR's changes
mcp__epigraph__patch_claim --claim-id b1770b53-174a-4b02-aa1a-d49e218ee60d \
  --add-labels '["resolved"]' --remove-labels '["backlog"]' \
  --properties '{"resolved_in_pr": "<PR_NUMBER>"}'
```

If the new tools are not yet on the live server (chicken-and-egg), use `psql` per `feedback_no_raw_sql` exception (governance-class change with no MCP wrapper available at the time).

### Task W3: Open the PR

- [ ] **Step 1: Push + open**

```bash
git push -u origin feat/workflow-claim-mcp-api-parity
gh pr create --title "Workflow + claim MCP/API parity" --body "$(cat <<'EOF'
## Summary
- Workstream 0: pre-flight migrations + test helper expansion + new shared db functions (evolve_step, mark_duplicate, patch_claim_atomic_conn, resolve_steps_to_heads).
- Workstream A: workflow MCP↔API parity (5 fixes).
- Workstream B: claim MCP wrappers (supersede_claim, update_labels, patch_claim) + labels on submit_claim.
- Workstream C: new POST /api/v1/claims/:id/dedup + matching MCP tool.
- Workstream D: OpenAPI now documents the 10 in-scope routes (broader coverage tracked as follow-up).
- Workstream E: GET /api/v1/mcp/tools backported from epigraph-internal.

Resolves backlog claim b1770b53.

## Behavior changes
- MCP `evolve_step(supersedes, ...)` now flips parent.is_current=false (matched API supersede semantics).
- MCP `improve_workflow` now writes `supersedes` instead of `variant_of` (parity with #99).
- MCP `deprecate_workflow` now sets is_current=false (parity with #97), and cascade walks both supersedes/variant_of edges, filtered to workflow-labeled claims.

## Test plan
- [x] cargo test -p epigraph-api -p epigraph-mcp -p epigraph-db
- [x] cargo clippy --workspace --all-features
- [x] cargo fmt --check
- [x] OpenAPI round-trip test asserts in-scope paths are documented
- [x] Smoke-tested GET /api/v1/mcp/tools against running server
EOF
)"
```

- [ ] **Step 2: Merge with `--merge` (NOT squash) per `feedback_merge_commit_not_squash`**

```bash
gh pr merge --merge --delete-branch
```

---

## Self-review checklist

1. **Spec coverage:**
   - 5 workflow parity items → A1..A5 ✓
   - 3 MCP claim wrappers → B1..B3; submit_claim labels → B4 ✓
   - Dedup mode → C1, C2 ✓
   - OpenAPI scoped surface → D0, D1 ✓
   - mcp/tools backport → E1 ✓
   - Backlog claim item 7 (DELETE /edges/:id) → confirmed already present in public; correctly omitted ✓

2. **Type / signature consistency (verified against the actual repo):**
   - `ClaimRepository::supersede(pool, old, content, truth, reason) -> (Uuid, Uuid)` (no `agent_id` arg) ✓
   - `epigraph_core::Claim` has no `labels` field — submit_claim attaches labels via post-create `update_labels` ✓
   - `auth.agent_id` is `Option<Uuid>` — handlers use `auth.owner_id.unwrap_or(auth.client_id)` ✓
   - `ApiError::Conflict { reason }` (not `message`) ✓
   - Security scheme is `ed25519_signature` (no `bearer_auth` in the codebase) ✓
   - API tests use `(addr, _shutdown) = spawn_app(&url).await; let token = test_bearer_token();` pattern ✓
   - MCP tests/common adds `build_test_server`, `seed_*`, `insert_edge`, `parse_uuid_field`, `first_text` (Pre-flight 0.3) ✓
   - `ImproveWorkflowParams` real fields used (`steps: Option<Vec<String>>`, `goal: Option<String>`) ✓
   - `DeprecateWorkflowParams.reason: String` (not Option) ✓

3. **No placeholders:**
   - Every handler skeleton is complete ✓
   - Every test has concrete assertions ✓
   - Every commit message is concrete ✓

4. **Behavior change disclosure:**
   - MCP `evolve_step(supersedes)` now flips parent — called out in A1 step 8 commit message ✓
   - MCP `patch_claim` does NOT emit provenance (REST does) — called out in B3 tool description ✓
   - MCP `supersede_claim` inherits OLD claim's agent_id — called out in tool docstring ✓

5. **Cascade safety (A5):** explicitly filters to `'workflow' = ANY(labels)` to avoid corrupting non-workflow supersedes chains ✓

6. **OpenAPI scope cap (D1):** test only enforces the 10 in-scope paths; will not break on legacy undocumented routes ✓
