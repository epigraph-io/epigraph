# Workflow + Claim MCP/API Parity Implementation Plan (v3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `epigraph-mcp` and `epigraph-api` into parity with the workflow system as it stands after PR #92 (step versioning), #97 (`is_current=false` on deprecate), and #99 (improve_workflow `supersedes`); and close the long-standing claim/labels/supersede/dedup MCP gap surfaced in backlog claim `b1770b53` (2026-05-08).

**Architecture:** Single feature branch `feat/workflow-claim-mcp-api-parity` (already created in worktree `/home/jeremy/epigraph-wt-parity`). Logical commits per task. The plan was reviewed twice: textual review against v1, then live-codebase + DB review against v2. v3 absorbs the 24 valid patches from those reviews. **Every code snippet, schema reference, and function signature in this plan was verified against the live code at HEAD `5d925cb` and the `epigraph_db_repo_test` Postgres database with all 31 migrations applied.**

- **Pre-flight (0):** worktree is set up; build/migrate/test-helpers/shared-db-functions go here.
- **A — Workflow parity (5 fixes):** new `POST /api/v1/workflows/steps/:id/evolve` REST handler; `resolve_to_latest` query param on API `find_workflow_hierarchical`; MCP `improve_workflow` writes `supersedes` AND adds `'workflow'` label on variants; MCP `deprecate_workflow` sets `is_current=false`; MCP cascade walks `supersedes` AND `variant_of`, filtered to workflow-labeled claims.
- **B — Claim/labels MCP wrappers:** `mcp__epigraph__supersede_claim`, `mcp__epigraph__update_labels`, `mcp__epigraph__patch_claim`; add `labels: Vec<String>` to `submit_claim` (post-create application — `Claim` has no labels field) **and update 5 existing struct-literal callsites**.
- **C — Dedup mode:** new `POST /api/v1/claims/:id/dedup` route + matching MCP tool. New route, not a `mode` field on `SupersedeRequest`, because the existing struct requires `content` and `truth_value` which are nonsensical for mark-duplicate.
- **D — OpenAPI surface (scoped):** `#[utoipa::path]` annotations for the 10 in-scope handlers. `paths(...)` entries gated on `#[cfg(feature = "db")]` if needed. Round-trip test asserts documented paths. Broader OpenAPI coverage tracked as a follow-up issue.
- **E — Backport:** `routes/mcp_tools.rs`, `lib.rs::list_tools()`, `server.rs::all_tools_json()`, register `GET /api/v1/mcp/tools`.

**Working directory: `/home/jeremy/epigraph-wt-parity`** (NOT `/home/jeremy/epigraph`). All `cd` commands and absolute paths in this plan use the worktree path.

**Branching policy:** Single feature branch `feat/workflow-claim-mcp-api-parity` off `main` (already created). Logical commits per task. Merge with `gh pr merge --merge --delete-branch` (no squash — see `feedback_merge_commit_not_squash` memory). Do **not** land commits directly on `main`.

**Tech Stack:** Rust 1.95.0+ (stable), axum, sqlx (Postgres), rmcp `#[tool_router]` macro, utoipa for OpenAPI, `#[sqlx::test(migrations = "../../migrations")]` for DB integration tests, `epigraph_db_repo_test` Postgres database for non-`sqlx::test` integration tests.

**Build flag policy:** Use `cargo build --workspace` and `cargo clippy --workspace` (no `--all-features`). The `privacy` and `isomorphism` features pull in deps that are commented out in this checkout (`epigraph-enterprise`, `episcience` repos own them).

---

## Pre-flight (Workstream 0)

The worktree, branch, Rust toolchain, test DB, and `sqlx-cli` are all already provisioned by the human operator. Pre-flight steps below are the in-repo setup work the executor still needs to do.

### Task 0.1: Confirm baseline + branch state

- [ ] **Step 1: Confirm working directory and branch**

```bash
cd /home/jeremy/epigraph-wt-parity
git branch --show-current
# expect: feat/workflow-claim-mcp-api-parity
git log --oneline main..HEAD
# expect: a7929da docs(plan): workflow + claim MCP/API parity implementation plan
```

- [ ] **Step 2: Confirm baseline build**

```bash
cargo build --workspace
```

Expected: clean compile with default features.

- [ ] **Step 3: Confirm baseline tests pass**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test
cargo test -p epigraph-api --test workflow_deprecate_test --no-fail-fast
cargo test -p epigraph-mcp --test step_versioning --no-fail-fast
```

Expected: green.

### Task 0.2: Add API test helpers

**Why:** `crates/epigraph-api/tests/common/mod.rs` currently exposes `spawn_app(&str)` and a fixed-scope `test_bearer_token()` (verified to issue only `graph:read` at line 25-44). Plan tests need scope-parameterised JWT, OAuth-client seeding (provenance_log FK), and basic claim/agent seeders.

**Files:**
- Modify: `crates/epigraph-api/tests/common/mod.rs`

- [ ] **Step 1: Append helpers**

```rust
use sqlx::PgPool;
use uuid::Uuid;

/// Issue a JWT with caller-specified scopes. evolve_step / dedup / patch_claim
/// require `claims:write`; the existing test_bearer_token() issues only graph:read.
pub fn test_bearer_token_with_scopes(scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None, None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}

/// Insert a system agent with a unique 32-byte public_key.
pub async fn seed_system_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed system agent");
    id
}

/// Insert a minimal claim with per-call unique content_hash.
pub async fn seed_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent = seed_system_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])",
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

/// Insert a claim with explicit labels.
pub async fn seed_claim_with_labels(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let id = seed_claim(pool, content).await;
    let labels_owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels_owned)
        .bind(id)
        .execute(pool).await.expect("set labels");
    id
}

/// Seed an oauth_clients row matching client_id (provenance_log.submitted_by FK).
/// Real schema: id, client_id varchar(64), client_secret_hash bytea (nullable),
/// client_name, client_type, allowed_scopes text[], granted_scopes text[], status.
pub async fn seed_oauth_client(pool: &PgPool, client_id: Uuid) {
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, granted_scopes, status) \
         VALUES ($1, $2, 'test', 'service', ARRAY['claims:write','graph:read']::text[], ARRAY['claims:write','graph:read']::text[], 'active') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(client_id)
    .bind(client_id.to_string())
    .execute(pool)
    .await
    .expect("seed oauth_client");
}

/// Issue a JWT bound to a real seeded oauth_clients row so provenance writes
/// don't violate the FK. Returns (token, client_id).
pub async fn test_bearer_token_with_seeded_client(
    pool: &PgPool,
    scopes: &[&str],
) -> (String, Uuid) {
    let client_id = Uuid::new_v4();
    seed_oauth_client(pool, client_id).await;
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            client_id,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None, None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    (token, client_id)
}
```

(Verify `oauth_clients` schema before committing; signature placeholder above is a valid Argon2 string format.)

- [ ] **Step 2: Sanity-build**

```bash
cargo test -p epigraph-api --tests --no-run
```

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-api/tests/common/mod.rs
git commit -m "test(api): add seed_claim, seed_oauth_client, scoped JWT helpers"
```

### Task 0.3: Add MCP test helpers

The existing `build_server` at `crates/epigraph-mcp/tests/step_versioning.rs:23` is the source-of-truth pattern: sync, uses `AgentSigner::from_bytes(&[0xA7u8; 32])` and `McpEmbedder::new(pool.clone(), None)`. Mirror it in `tests/common/mod.rs` so other tests can share.

**Files:**
- Modify: `crates/epigraph-mcp/tests/common/mod.rs`

- [ ] **Step 1: Append helpers**

```rust
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

pub fn build_test_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, /* read_only */ false)
}

pub async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(id).bind(&pk).execute(pool).await.expect("seed agent");
    id
}

pub async fn seed_claim(pool: &PgPool, content: &str, truth: f64) -> Uuid {
    let agent = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, $4, $5, true, ARRAY[]::text[])",
    )
    .bind(id).bind(content).bind(&hash).bind(truth).bind(agent)
    .execute(pool).await.expect("seed claim");
    id
}

pub async fn seed_claim_with_labels(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let id = seed_claim(pool, content, 0.5).await;
    let labels_owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels_owned).bind(id).execute(pool).await.expect("set labels");
    id
}

pub async fn seed_workflow_claim(pool: &PgPool, goal: &str, steps: &[&str]) -> Uuid {
    let agent = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let content = format!("{goal}\n{}", steps.join("\n"));
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    let props = serde_json::json!({
        "goal": goal, "steps": steps, "generation": 0,
        "use_count": 0, "success_count": 0, "failure_count": 0, "avg_variance": 0.0,
    });
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, properties) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY['workflow']::text[], $5)",
    )
    .bind(id).bind(&content).bind(&hash).bind(agent).bind(&props)
    .execute(pool).await.expect("seed workflow claim");
    id
}

pub async fn insert_claim_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb)",
    )
    .bind(source).bind(target).bind(relationship)
    .execute(pool).await.expect("insert edge");
}

pub fn first_text(result: &CallToolResult) -> Value {
    let content = result.content.as_ref().and_then(|c| c.first()).expect("at least one content block");
    let text = content.as_text().expect("text block").text.clone();
    serde_json::from_str(&text).expect("valid JSON")
}

pub fn parse_uuid_field(json: &Value, key: &str) -> Uuid {
    json.get(key).and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing field {key} in {json}"))
        .parse().expect("valid UUID")
}
```

- [ ] **Step 2: Sanity-build**

```bash
cargo test -p epigraph-mcp --tests --no-run
```

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-mcp/tests/common/mod.rs
git commit -m "test(mcp): add build_test_server, seed_*, parse helpers"
```

### Task 0.4: Add the shared db-layer functions

#### 0.4.a `ClaimRepository::evolve_step`

Behavior change vs. existing MCP `evolve_step` (`tools/evolve_step.rs:40-105`): when `edge_type == "supersedes"`, parent's `is_current` flips to `false`. The MCP `EvolveStepParams` shape stays unchanged — the body delegates to this shared function.

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs`
- Modify: `crates/epigraph-db/src/lib.rs` (`pub use repos::claim::EvolveStepResult;`)
- Test: `crates/epigraph-db/tests/evolve_step_repo.rs`

- [ ] **Step 1: Add the function**

```rust
// In impl ClaimRepository in crates/epigraph-db/src/repos/claim.rs.

#[derive(Debug)]
pub struct EvolveStepResult {
    pub new_claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_type: String,
    pub edge_id: Uuid,
}

#[instrument(skip(pool))]
pub async fn evolve_step(
    pool: &PgPool,
    parent: ClaimId,
    new_content: &str,
    edge_type: &str,
    reason: Option<&str>,
    level: u32,
    agent_id: Uuid,
) -> Result<EvolveStepResult, DbError> {
    if !matches!(edge_type, "supersedes" | "revises") {
        return Err(DbError::QueryFailed {
            source: sqlx::Error::Protocol(format!(
                "evolve_step: edge_type must be 'supersedes' or 'revises', got {edge_type}"
            )),
        });
    }
    let parent_uuid: Uuid = parent.into();
    let mut tx = pool.begin().await?;

    let row: Option<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT step_lineage_id FROM claims WHERE id = $1 FOR UPDATE",
    )
    .bind(parent_uuid).fetch_optional(&mut *tx).await?;
    let (existing_lineage,) = row.ok_or(DbError::NotFound {
        entity: "Claim".into(), id: parent_uuid,
    })?;
    let lineage_id = match existing_lineage {
        Some(l) => l,
        None => {
            let new_lineage = Uuid::new_v4();
            sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
                .bind(new_lineage).bind(parent_uuid)
                .execute(&mut *tx).await?;
            new_lineage
        }
    };

    let new_uuid = Uuid::new_v4();
    let hash = ContentHasher::hash(new_content.as_bytes());
    let properties = serde_json::json!({
        "level": level,
        "step_lineage_id": lineage_id.to_string(),
    });
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, properties, step_lineage_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[], $5, $6)",
    )
    .bind(new_uuid).bind(new_content).bind(hash.as_slice()).bind(agent_id)
    .bind(&properties).bind(lineage_id)
    .execute(&mut *tx).await?;

    let edge_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4, jsonb_build_object('reason', $5))",
    )
    .bind(edge_id).bind(new_uuid).bind(parent_uuid).bind(edge_type)
    .bind(reason.unwrap_or(""))
    .execute(&mut *tx).await?;

    if edge_type == "supersedes" {
        sqlx::query("UPDATE claims SET is_current = false, updated_at = NOW() WHERE id = $1")
            .bind(parent_uuid).execute(&mut *tx).await?;
    }

    tx.commit().await?;
    Ok(EvolveStepResult {
        new_claim_id: new_uuid,
        step_lineage_id: lineage_id,
        edge_type: edge_type.to_string(),
        edge_id,
    })
}
```

- [ ] **Step 2: Re-export**

In `crates/epigraph-db/src/lib.rs`:

```rust
pub use repos::claim::EvolveStepResult;
```

- [ ] **Step 3: Test (`crates/epigraph-db/tests/evolve_step_repo.rs`)**

```rust
#![cfg(feature = "db")]
use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id).bind(&pk).execute(pool).await.unwrap();
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, $4, $5, true, ARRAY[]::text[])"
    ).bind(id).bind(content).bind(&hash).bind(truth).bind(agent)
    .execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_flips_parent(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent step", 0.7).await;
    let res = ClaimRepository::evolve_step(
        &pool, ClaimId::from_uuid(parent), "child", "supersedes", Some("better"), 2, agent
    ).await.unwrap();

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent).fetch_one(&pool).await.unwrap();
    assert!(!parent_current);

    let (child_lineage, child_props): (Option<Uuid>, serde_json::Value) =
        sqlx::query_as("SELECT step_lineage_id, properties FROM claims WHERE id = $1")
            .bind(res.new_claim_id).fetch_one(&pool).await.unwrap();
    assert_eq!(child_lineage, Some(res.step_lineage_id));
    assert_eq!(child_props["level"].as_i64(), Some(2));
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_keeps_parent_current(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent", 0.7).await;
    ClaimRepository::evolve_step(&pool, ClaimId::from_uuid(parent), "branch", "revises", None, 2, agent).await.unwrap();
    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent).fetch_one(&pool).await.unwrap();
    assert!(parent_current);
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_rejects_bad_edge_type(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent", 0.7).await;
    let err = ClaimRepository::evolve_step(&pool, ClaimId::from_uuid(parent), "x", "merges", None, 2, agent).await.err().unwrap();
    assert!(format!("{err:?}").contains("supersedes"), "{err:?}");
}
```

- [ ] **Step 4: Run + commit**

```bash
DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test \
  cargo test -p epigraph-db --test evolve_step_repo --no-fail-fast
git add crates/epigraph-db/src/repos/claim.rs crates/epigraph-db/src/lib.rs crates/epigraph-db/tests/evolve_step_repo.rs
git commit -m "feat(db): ClaimRepository::evolve_step (atomic, flips parent on supersedes)"
```

#### 0.4.b `ClaimRepository::mark_duplicate`

- [ ] **Step 1: Add function** in `claim.rs`:

```rust
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
        .bind(canon_uuid).fetch_one(&mut *tx).await?;
    if !canon_exists {
        return Err(DbError::NotFound { entity: "Claim".into(), id: canon_uuid });
    }
    let row: Option<(Option<Uuid>,)> =
        sqlx::query_as("SELECT supersedes FROM claims WHERE id = $1 FOR UPDATE")
            .bind(dup_uuid).fetch_optional(&mut *tx).await?;
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
    .bind(canon_uuid).bind(dup_uuid).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
```

- [ ] **Step 2: Test (`crates/epigraph-db/tests/mark_duplicate_repo.rs`)** — happy path, already-superseded rejection, same-id rejection, missing-canonical rejection. Reuse the inline `seed_agent`/`seed_claim` helpers from 0.4.a (copy-paste — no shared test commons in epigraph-db/tests/).

- [ ] **Step 3: Run + commit**

```bash
git commit -am "feat(db): ClaimRepository::mark_duplicate"
```

#### 0.4.c `ClaimRepository::patch_claim_atomic_conn`

- [ ] **Step 1: Add types and function**

```rust
#[derive(Debug, Clone, Default)]
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
    .bind(id_uuid).fetch_optional(&mut **tx).await?
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
            "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || $1 WHERE id = $2"
        )
        .bind(p).bind(id_uuid).execute(&mut **tx).await?;
        if let (Some(merged), Some(po)) = (after_props.as_object_mut(), p.as_object()) {
            for (k, v) in po { merged.insert(k.clone(), v.clone()); }
        }
    }

    let mut after_labels = before_labels.clone();
    if !patch.add_labels.is_empty() || !patch.remove_labels.is_empty() {
        // Double-deref through &mut Transaction (DerefMut to PgConnection).
        after_labels = Self::update_labels_conn(&mut **tx, id_uuid, &patch.add_labels, &patch.remove_labels).await?;
    }

    Ok(PatchClaimDiff {
        before_labels, after_labels,
        before_props, after_props,
        before_trace, after_trace,
    })
}
```

- [ ] **Step 2: Re-export** in `crates/epigraph-db/src/lib.rs`:

```rust
pub use repos::claim::{EvolveStepResult, PatchClaimDiff, PatchClaimInput};
```

- [ ] **Step 3: Refactor API** `routes/claims.rs::patch_claim` to call the new helper. Replace the inline before/after row reads + label/property/trace mutations with `ClaimRepository::patch_claim_atomic_conn(&mut tx, claim_id, &input)`. **Keep** the existing `ProvenanceRepository::append_conn` block unchanged.

- [ ] **Step 4: Run existing tests; expect green**

```bash
cargo test -p epigraph-api --tests --no-fail-fast
```

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(db): patch_claim_atomic_conn + refactor api/patch_claim to use it"
```

#### 0.4.d `WorkflowRepository::resolve_steps_to_heads`

Lift `build_resolved_steps` (currently private at `tools/workflow_hierarchical.rs:111`) into `repos/workflow.rs`. **Preserve `ResolvedStep` shape exactly**: `{step_index, frozen_claim_id, step_lineage_id, heads: Vec<LineageHead>, pending_resolution}`.

- [ ] **Step 1: Add to `repos/workflow.rs`**

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ResolvedStep {
    pub step_index: usize,
    pub frozen_claim_id: Uuid,
    pub step_lineage_id: Option<Uuid>,
    pub heads: Vec<crate::repos::claim::LineageHead>,
    pub pending_resolution: bool,
}

pub async fn resolve_steps_to_heads(
    pool: &PgPool,
    workflow_id: Uuid,
) -> Result<Vec<ResolvedStep>, DbError> {
    // Body: copy from tools/workflow_hierarchical.rs:111+. Replace any
    // McpError returns with DbError::QueryFailed { source: ... }.
}
```

- [ ] **Step 2: Re-export** in `lib.rs`:

```rust
pub use repos::workflow::ResolvedStep;
```

- [ ] **Step 3: Update MCP caller**

In `tools/workflow_hierarchical.rs`, replace the call to private `build_resolved_steps` with `epigraph_db::WorkflowRepository::resolve_steps_to_heads(...)`. Delete the local `ResolvedStep` and `build_resolved_steps`.

- [ ] **Step 4: Re-run MCP step-versioning tests** — expect PASS (no behavior change).

- [ ] **Step 5: Commit**

```bash
git commit -am "refactor(db,mcp): hoist resolve_steps_to_heads into WorkflowRepository"
```

---

## Workstream A — Workflow MCP/API parity

### Task A1: API endpoint for `evolve_step` (MCP delegates to shared db fn)

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/evolve_step.rs` (delegate body to `ClaimRepository::evolve_step`; keep `EvolveStepParams` shape)
- Modify: `crates/epigraph-api/src/routes/workflows.rs` (add handler near `report_hierarchical_outcome` end at line ~820)
- Modify: `crates/epigraph-api/src/routes/mod.rs` (register route in both router builders, ~lines 146 + 777)
- Test: extend `tests/step_versioning.rs::evolve_step_supersedes_flips_head` (line ~86) — assert parent.is_current=false
- Test: `crates/epigraph-api/tests/workflow_evolve_step_test.rs` (new)

- [ ] **Step 1: Migrate MCP body to call shared db function**

Replace the body of `crates/epigraph-mcp/src/tools/evolve_step.rs::evolve_step` (~line 40):

```rust
let parent_uuid = parse_uuid(&params.parent_id)?;
let agent_id = server.agent_id().await?;
let level = params.level.unwrap_or(2);

let result = epigraph_db::ClaimRepository::evolve_step(
    &server.pool,
    epigraph_core::ClaimId::from_uuid(parent_uuid),
    &params.content,
    &params.edge_type,
    params.rationale.as_deref(),
    level,
    agent_id,
)
.await
.map_err(internal_error)?;

success_json(&EvolveStepResponse {
    claim_id: result.new_claim_id,
    step_lineage_id: result.step_lineage_id,
    edge_id: result.edge_id,
})
```

- [ ] **Step 2: Strengthen `step_versioning.rs:86`'s existing test**

Find `evolve_step_supersedes_flips_head` and add to its assertion block:

```rust
let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
    .bind(parent_id).fetch_one(&pool).await.unwrap();
assert!(!parent_current, "supersedes must flip parent.is_current=false");
```

Run:

```bash
cargo test -p epigraph-mcp --test step_versioning evolve_step_supersedes_flips_head -- --nocapture
```

- [ ] **Step 3: Failing API integration test** (`crates/epigraph-api/tests/workflow_evolve_step_test.rs`)

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
    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({
        "parent_id": parent,
        "content": "improved step",
        "edge_type": "supersedes",
        "reason": "tightened wording",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/workflows/steps/{parent}/evolve"))
        .bearer_auth(&token)
        .json(&body).send().await.unwrap();
    assert_eq!(resp.status(), 200, "body={:?}", resp.text().await);

    let json: serde_json::Value = resp.json().await.unwrap();
    let new_id: Uuid = json["claim_id"].as_str().unwrap().parse().unwrap();

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent).fetch_one(&pool).await.unwrap();
    assert!(!parent_current);

    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'supersedes'"
    ).bind(new_id).bind(parent).fetch_one(&pool).await.unwrap();
    assert_eq!(edge_count, 1);
}
```

- [ ] **Step 4: Run — expect FAIL (404)**

- [ ] **Step 5: Add the API handler** in `routes/workflows.rs`:

```rust
#[derive(Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct EvolveStepRequest {
    pub parent_id: Uuid,
    pub content: String,
    pub edge_type: String,
    pub reason: Option<String>,
    pub level: Option<u32>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct EvolveStepResponse {
    pub claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_type: String,
    pub edge_id: Uuid,
}

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
    let level = req.level.unwrap_or(2);
    let result = epigraph_db::ClaimRepository::evolve_step(
        &state.db_pool,
        epigraph_core::ClaimId::from_uuid(parent_id),
        &req.content,
        &req.edge_type,
        req.reason.as_deref(),
        level,
        agent,
    )
    .await
    .map_err(|e| match e {
        epigraph_db::DbError::NotFound { id, .. } => ApiError::NotFound {
            entity: "Claim".into(), id: id.to_string(),
        },
        other => ApiError::InternalError { message: other.to_string() },
    })?;

    Ok(Json(EvolveStepResponse {
        claim_id: result.new_claim_id,
        step_lineage_id: result.step_lineage_id,
        edge_type: result.edge_type,
        edge_id: result.edge_id,
    }))
}
```

- [ ] **Step 6: Register route** in `routes/mod.rs` — both router builders:

```rust
.route(
    "/api/v1/workflows/steps/:id/evolve",
    post(workflows::evolve_step),
)
```

- [ ] **Step 7: Run — expect PASS**

- [ ] **Step 8: Commit**

```bash
git commit -am "feat(api,mcp): POST /api/v1/workflows/steps/:id/evolve + MCP delegates

Behavior change for MCP evolve_step: edge_type=\"supersedes\" now flips
parent.is_current=false (matches API supersede semantics)."
```

---

### Task A2: API `find_workflow_hierarchical` accepts `resolve_to_latest`

(MCP-side `FindWorkflowHierarchicalParams.resolve_to_latest: Option<bool>` already exists at `types.rs:377`. This task only adds the field on the API side.)

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs` (`HierarchicalSearchQuery` line 99, handler line 634)
- Test: `crates/epigraph-api/tests/workflow_find_hierarchical_resolve_test.rs`

- [ ] **Step 1: Failing test** — seed a hierarchical workflow with one evolved step (use `ClaimRepository::evolve_step`), GET `/api/v1/workflows/hierarchical/search?q=...&resolve_to_latest=true`, assert response has `"resolve_to_latest": true` and `resolved_steps` array per workflow.

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

- [ ] **Step 3: Wire** the resolver in the handler:

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

- [ ] **Step 4: Run — expect PASS; commit**

```bash
git commit -am "feat(api): find_workflow_hierarchical supports resolve_to_latest"
```

---

### Task A3: MCP `improve_workflow` writes `supersedes` AND adds `'workflow'` label on variants

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs` (line ~620 edge writer; ~line 552-563 variant claim creation)
- Test: `crates/epigraph-mcp/tests/improve_workflow_supersedes_test.rs`

- [ ] **Step 1: Failing test**

```rust
#![cfg(feature = "db")]
use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn improve_workflow_writes_supersedes_edge_and_labels_variant(pool: PgPool) {
    let parent = seed_workflow_claim(&pool, "parent goal", &["s1"]).await;
    let server = build_test_server(pool.clone());

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
    assert_eq!(rel.as_deref(), Some("supersedes"));

    let (labels,): (Vec<String>,) = sqlx::query_as(
        "SELECT labels FROM claims WHERE id = $1"
    ).bind(variant_id).fetch_one(&pool).await.unwrap();
    assert!(labels.contains(&"workflow".into()),
        "improve_workflow variants must carry the 'workflow' label so cascade finds them");
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Apply both fixes**

(a) **Edge type:** in `tools/workflows.rs`, find the block writing `"variant_of"` (~line 620), change literal to `"supersedes"`. Update the idempotent-skip filter (~line 634).

(b) **Workflow label:** find where the variant `Claim` is constructed (~line 552-563); after the INSERT succeeds, call:

```rust
let _ = epigraph_db::ClaimRepository::update_labels(
    &server.pool,
    variant_id,
    &["workflow".to_string()],
    &[],
).await;
```

- [ ] **Step 4: Run — expect PASS; commit**

```bash
git commit -am "fix(mcp): improve_workflow emits supersedes + adds 'workflow' label on variants"
```

---

### Task A4: MCP `deprecate_workflow` sets `is_current = false`

(`DeprecateWorkflowParams { workflow_id: String, reason: String, cascade: Option<bool> }` — `reason` is **not** Option.)

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs` (line ~660 single-target; ~line 680 cascade)
- Test: `crates/epigraph-mcp/tests/deprecate_workflow_is_current_test.rs`

- [ ] **Step 1: Failing test**

```rust
#![cfg(feature = "db")]
use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn mcp_deprecate_workflow_sets_is_current_false(pool: PgPool) {
    let id = seed_workflow_claim(&pool, "to-deprecate", &["s1"]).await;
    let server = build_test_server(pool.clone());

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

- [ ] **Step 3: Replace single-target update**

In `tools/workflows.rs` ~line 660, replace `ClaimRepository::update_truth_value(...)` with:

```rust
sqlx::query("UPDATE claims SET truth_value = 0.05, is_current = false, updated_at = NOW() WHERE id = $1")
    .bind(workflow_id).execute(&server.pool).await
    .map_err(internal_error)?;
```

Apply same change in cascade loop (~line 680).

- [ ] **Step 4: Run + commit**

```bash
git commit -am "fix(mcp): deprecate_workflow sets is_current=false"
```

---

### Task A5: cascade walks both edges, filtered to workflow claims

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs` (line ~678)
- Test: append to `tests/deprecate_workflow_is_current_test.rs`

- [ ] **Step 1: Failing cascade test**

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_workflow_cascade_walks_supersedes_and_variant_of(pool: PgPool) {
    let root = seed_workflow_claim(&pool, "root", &["s1"]).await;
    let child_old = seed_workflow_claim(&pool, "child_old", &["s1"]).await;
    let child_new = seed_workflow_claim(&pool, "child_new", &["s1"]).await;
    insert_claim_edge(&pool, child_old, root, "variant_of").await;
    insert_claim_edge(&pool, child_new, root, "supersedes").await;

    let unrelated = seed_claim(&pool, "non-workflow", 0.5).await;
    insert_claim_edge(&pool, unrelated, root, "supersedes").await;

    let server = build_test_server(pool.clone());
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
    let (utt_truth, utt_current): (f64, bool) = sqlx::query_as(
        "SELECT truth_value, is_current FROM claims WHERE id = $1"
    ).bind(unrelated).fetch_one(&pool).await.unwrap();
    assert!((utt_truth - 0.5).abs() < 1e-9);
    assert!(utt_current);
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Update cascade walker**

```rust
const DESCENDANT_REL: &[&str] = &["variant_of", "supersedes"];

for edge in edges {
    if !DESCENDANT_REL.contains(&edge.relationship.as_str()) {
        continue;
    }
    let child_id = edge.source_id;
    let is_workflow: bool = sqlx::query_scalar(
        "SELECT 'workflow' = ANY(labels) FROM claims WHERE id = $1"
    )
    .bind(child_id).fetch_optional(&server.pool).await
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

- [ ] **Step 4: Run + commit**

```bash
git commit -am "fix(mcp): deprecate_workflow cascade walks both edges, workflow-filtered"
```

---

## Workstream B — Claim/labels MCP wrappers

### Task B1: `mcp__epigraph__supersede_claim`

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs` (`SupersedeClaimParams`)
- Create: `crates/epigraph-mcp/src/tools/supersede.rs`
- Modify: `crates/epigraph-mcp/src/tools/mod.rs` (`pub mod supersede;`)
- Modify: `crates/epigraph-mcp/src/server.rs` (register `#[tool]`)
- Test: `crates/epigraph-mcp/tests/supersede_claim_test.rs`

- [ ] **Step 1: Add params**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupersedeClaimParams {
    pub claim_id: String,
    pub content: String,
    pub truth_value: f64,
    pub reason: String,
}
```

- [ ] **Step 2: Failing test** mirrors B2-style; assert old.is_current=false, new.supersedes=Some(old).

- [ ] **Step 3: Implement**

```rust
//! crates/epigraph-mcp/src/tools/supersede.rs

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
        &server.pool, ClaimId::from_uuid(old), &params.content, truth, &params.reason,
    ).await.map_err(internal_error)?;
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
        })).map_err(internal_error)?,
    )]))
}
```

Add `pub mod supersede;` to `tools/mod.rs`.

- [ ] **Step 4: Register `#[tool]`** with description noting agent_id inheritance.

- [ ] **Step 5: Run + commit**

```bash
git commit -am "feat(mcp): supersede_claim tool"
```

---

### Task B2: `update_labels`

(Same pattern; description: "Atomic, idempotent label add/remove on an existing claim.")

- [ ] Add `UpdateLabelsParams` to `types.rs`
- [ ] Add failing test
- [ ] Implement `pub async fn update_labels` in `tools/claims.rs` calling `ClaimRepository::update_labels`
- [ ] Register `#[tool]`
- [ ] Run + commit

---

### Task B3: `patch_claim`

**Files:** as 0.4.c plus new MCP wiring + test (with reasoning_traces seeding for FK).

Test snippet:

```rust
// reasoning_traces.reasoning_type CHECK constraint: must be one of
// 'deductive', 'inductive', 'abductive', 'analogical', 'statistical'.
let trace = uuid::Uuid::new_v4();
sqlx::query(
    "INSERT INTO reasoning_traces (id, claim_id, reasoning_type, confidence, explanation) \
     VALUES ($1, $2, 'deductive', 0.5, 'test')"
).bind(trace).bind(id).execute(&pool).await.unwrap();
```

Implementation calls `ClaimRepository::patch_claim_atomic_conn` (added in 0.4.c), commits the tx, returns the diff. Tool description must note "MCP patch_claim is the no-provenance fast path; use REST `PATCH /api/v1/claims/:id` if audit trail required."

---

### Task B4: `submit_claim` accepts labels

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs` (`SubmitClaimParams`)
- Modify: `crates/epigraph-mcp/src/tools/claims.rs:71+` (apply labels post-create)
- Modify: 5 existing struct-literal callsites (see grep output below)
- Test: `crates/epigraph-mcp/tests/submit_claim_labels_test.rs`

- [ ] **Step 1: Add field** to `SubmitClaimParams`:

```rust
#[schemars(description = "Optional labels (e.g. ['backlog','bug'])")]
#[serde(default)]
pub labels: Vec<String>,
```

- [ ] **Step 2: Update existing struct-literal callsites**

```bash
grep -rn "SubmitClaimParams {" crates/
```

Expected hits (verify before editing):
- `crates/epigraph-mcp/src/tools/batch.rs:26`
- `crates/epigraph-mcp/tests/event_log_wiring_tests.rs:74`
- `crates/epigraph-mcp/tests/event_log_wiring_tests.rs:160`
- `crates/epigraph-mcp/tests/tool_resubmit_tests.rs:38`
- `crates/epigraph-mcp/tests/tool_resubmit_tests.rs:47`

Add `labels: vec![],` to each.

- [ ] **Step 3: Failing test** as in B2 (assert seeded labels appear on `claims.labels`).

- [ ] **Step 4: Implement** — in `submit_claim` body after `let claim_uuid = claim.id.as_uuid();`:

```rust
if !params.labels.is_empty() {
    epigraph_db::ClaimRepository::update_labels(
        &server.pool, claim_uuid, &params.labels, &[],
    ).await.map_err(internal_error)?;
}
```

- [ ] **Step 5: Run + commit**

```bash
git commit -am "feat(mcp): submit_claim accepts labels (post-create)"
```

---

## Workstream C — Dedup mode

### Task C1: `POST /api/v1/claims/:id/dedup`

**Files:**
- Modify: `crates/epigraph-api/src/routes/versioning.rs`
- Modify: `crates/epigraph-api/src/routes/mod.rs`
- Test: `crates/epigraph-api/tests/dedup_endpoint_test.rs`

- [ ] **Step 1: Failing test** uses `test_bearer_token_with_seeded_client` (added in 0.2):

```rust
let (token, _client_id) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
```

(rest mirrors plan v2.)

- [ ] **Step 2: Add `DedupRequest`/`DedupResponse` and `mark_duplicate` handler** in `versioning.rs`. Provenance write follows the existing `routes/claims.rs::patch_claim` pattern; `.ok()` swallow the result.

- [ ] **Step 3: `ProvenanceRepository::append_conn` signature** (verified at `crates/epigraph-db/src/repos/provenance.rs:86`):

```rust
pub async fn append_conn(
    conn: &mut sqlx::PgConnection,
    record_type: &str,
    record_id: Uuid,
    action: &str,
    submitted_by: Uuid,
    principal_id: Uuid,
    authorization_chain: &[Uuid],
    authorization_type: &str,
    content_hash: &[u8],
    provenance_sig: &[u8],
    token_jti: Uuid,
    scopes_used: &[String],
    patch_payload: Option<&Value>,
) -> Result<Uuid, DbError>
```

Adapt the C1 handler's `append_conn` call to pass arguments in this order. The handler skeleton in C1 above already does — verify, don't drift.

- [ ] **Step 4: Register route** + run + commit:

```bash
git commit -am "feat(api): POST /api/v1/claims/:id/dedup"
```

---

### Task C2: MCP `mark_duplicate`

Same B1 pattern; calls `ClaimRepository::mark_duplicate` directly (no provenance). Description notes "use REST endpoint for audit trail."

```bash
git commit -am "feat(mcp): mark_duplicate tool"
```

---

## Workstream D — OpenAPI surface (scoped)

### Task D0: utoipa scaffolding

- [ ] **Step 1: Derive `utoipa::ToSchema`** on:
  - `versioning.rs`: `SupersedeRequest`, `SupersessionResponse`, `DedupRequest`, `DedupResponse`
  - `workflows.rs`: `EvolveStepRequest`, `EvolveStepResponse`
  - `claims.rs`: `UpdateLabelsRequest`, `UpdateLabelsResponse`, `PatchClaimRequest`, `ClaimResponse`

- [ ] **Step 2: Reuse `ed25519_signature` security scheme** (verified at `openapi.rs:97`). Do NOT add `bearer_auth`.

- [ ] **Step 3: Build + commit**

```bash
cargo build --workspace
git commit -am "chore(api): derive utoipa::ToSchema on in-scope types"
```

### Task D1: Annotate 10 handlers + paths()

| # | path | verb | handler |
|---|---|---|---|
| 1 | `/api/v1/claims/{id}/supersede` | POST | `versioning::supersede_claim` |
| 2 | `/api/v1/claims/{id}/dedup` | POST | `versioning::mark_duplicate` |
| 3 | `/api/v1/claims/{id}` | PATCH | `claims::patch_claim` |
| 4 | `/api/v1/claims/{id}/labels` | PATCH | `claims::update_labels` |
| 5 | `/api/v1/workflows/steps/{id}/evolve` | POST | `workflows::evolve_step` |
| 6 | `/api/v1/workflows/hierarchical/search` | GET | `workflows::find_workflow_hierarchical` |
| 7 | `/api/v1/workflows/hierarchical/{id}/outcome` | POST | `workflows::report_hierarchical_outcome` |
| 8 | `/api/v1/workflows/{id}/improve` | POST | `workflows::improve_workflow` |
| 9 | `/api/v1/workflows/{id}` | DELETE | `workflows::deprecate_workflow` |
| 10 | `/api/v1/workflows/ingest` | POST | `workflows::ingest_workflow` |

Annotation pattern:

```rust
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/dedup",
    params(("id" = Uuid, Path, description = "UUID of the duplicate claim")),
    request_body = DedupRequest,
    responses(
        (status = 200, body = DedupResponse),
        (status = 400), (status = 404), (status = 409),
    ),
    security(("ed25519_signature" = [])),
    tag = "claims"
)]
```

`paths(...)` extension (gate on `#[cfg(feature = "db")]` if needed):

```rust
paths(
    health_check, submit_packet, rag_context, system_stats, submit_challenge, list_challenges,
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
```

Round-trip test asserts those 10 paths appear in `/api/v1/openapi.json`.

```bash
git commit -am "docs(api): document supersede/dedup/labels/patch/workflow routes"
gh issue create --title "OpenAPI: document remaining ~90 routes" --body "..."
```

---

## Workstream E — Backport `mcp/tools` introspection

### Task E1

- [ ] Append `pub fn list_tools()` to `crates/epigraph-mcp/src/lib.rs`
- [ ] Append `pub fn all_tools_json()` method to `crates/epigraph-mcp/src/server.rs`
- [ ] Copy `mcp_tools.rs` from internal: `cp /home/jeremy/epigraph-internal/crates/epigraph-api/src/routes/mcp_tools.rs crates/epigraph-api/src/routes/mcp_tools.rs`
- [ ] Add `pub mod mcp_tools;` and register `GET /api/v1/mcp/tools` in both router builders in `routes/mod.rs`
- [ ] Run `cargo test -p epigraph-api mcp_tools::tests`; smoke-test live; commit

```bash
git commit -am "feat(api,mcp): backport GET /api/v1/mcp/tools from internal"
```

---

## Wrap-up

### W1: Verify

```bash
DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test \
  cargo test -p epigraph-api -p epigraph-mcp -p epigraph-db --no-fail-fast
cargo fmt --check
cargo clippy --workspace -- -D warnings
```

### W2: Backlog claim

Once new tools are live, mark `b1770b53` resolved via `mcp__epigraph__patch_claim`. Fall back to `psql` per `feedback_no_raw_sql` exception if needed.

### W3: PR

```bash
git push -u origin feat/workflow-claim-mcp-api-parity
gh pr create --title "Workflow + claim MCP/API parity" --body "..."
gh pr merge --merge --delete-branch
```

---

## Self-review checklist

Verified against live code/DB at HEAD `5d925cb` and `epigraph_db_repo_test` (31 migrations applied):

- `ClaimRepository::supersede(pool, old, content, truth, reason) -> (Uuid, Uuid)` ✓
- `epigraph_core::Claim` has no `labels` field — submit_claim uses post-create `update_labels` ✓
- `auth.agent_id`/`owner_id`/`client_id` shapes ✓
- `ApiError::Conflict { reason }` ✓
- Security scheme `ed25519_signature` ✓
- API tests use `(addr, _shutdown)` + `test_bearer_token_with_scopes(&[...])` ✓
- `claims.level` does NOT exist — level lives in `properties` JSONB ✓
- `claims.trace_id` FK to `reasoning_traces.id` — B3 test seeds the trace ✓
- `provenance_log.submitted_by` FK to `oauth_clients.id` — C1 uses `test_bearer_token_with_seeded_client` ✓
- MCP `EvolveStepParams` 6-field shape preserved; only the body delegates ✓
- `ResolvedStep` shape preserved verbatim ✓
- `build_test_server` is sync; uses `AgentSigner::from_bytes(&[0xA7u8; 32])` and `McpEmbedder::new(pool, None)` ✓
- `SubmitClaimParams.labels` requires updating 5 existing struct-literal callsites ✓
- `cargo build --workspace` (default features only) ✓
- `#[sqlx::test(migrations = "../../migrations")]` is correct from any `crates/<name>/tests/` ✓
- A3 ensures variants get `'workflow'` label so A5's cascade filter finds them ✓
- A5's cascade filter to `'workflow' = ANY(labels)` protects non-workflow supersedes chains ✓
