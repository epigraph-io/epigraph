# Cross-Source Anchor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Link paper claims to textbook concepts via the `claim_themes` layer (textbook-seeded, LLM-labeled) so papers can be navigated by concept and bridged to each other through shared anchors.

**Architecture:** Seed `claim_themes` from textbook L1 sections (LLM emits labels). Run an HNSW-shortlist + LLM-judge anchor pass over paper L3 atoms — primary anchor goes into `claims.theme_id`, secondary anchors into new `INSTANTIATES` edges. Restore the two tools the nightly maintenance workflow already references (`embedding_neighborhood_density`, `hypothesize(cluster_count=N)`) so the pipeline has real diagnostics and the workflow becomes runnable end-to-end.

**Tech Stack:** Rust (axum, sqlx, pgvector), Python 3 (psycopg2, subprocess→`claude -p`), PostgreSQL 16, pgvector HNSW indexes, existing `epigraph_engine::theme_cluster` k-means primitives.

**Spec:** `docs/superpowers/specs/2026-05-18-cross-source-anchor-design.md`.

**Working branch:** `spec/cross-source-anchor` (already created with the spec commit).

**Test database convention:** Set `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test` for integration tests (per `epigraph/CLAUDE.md` and `feedback_cluster_graph_test_db.md`).

**LLM convention:** Python scripts invoke `claude -p <prompt> --output-format json` via subprocess. Do not import the Anthropic SDK directly (per `feedback_claude_cli_oauth.md`: OAuth is prepaid and was painful to set up).

---

## Task 1: Migration — `claim_themes.properties` JSONB column

**Files:**
- Create: `migrations/032_claim_themes_properties.sql`
- Modify: none

- [ ] **Step 1: Write the migration**

```sql
-- migrations/032_claim_themes_properties.sql
-- Per design 2026-05-18-cross-source-anchor.
-- Adds free-form metadata to claim_themes so textbook-seeded themes can
-- record `source_textbook_claim_id` (the L1 section they were derived from)
-- without inventing a side table. Existing rows default to '{}'::jsonb.

ALTER TABLE claim_themes
    ADD COLUMN IF NOT EXISTS properties JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_claim_themes_properties
    ON claim_themes USING gin (properties jsonb_path_ops);
```

- [ ] **Step 2: Apply to test DB and verify**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph_db_repo_test \
  -f /home/jeremy/epigraph/migrations/032_claim_themes_properties.sql
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph_db_repo_test \
  -c "\d claim_themes" | grep properties
```

Expected: line `properties | jsonb | not null | '{}'::jsonb`.

- [ ] **Step 3: Apply to production DB**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph \
  -f /home/jeremy/epigraph/migrations/032_claim_themes_properties.sql
```

Expected: `ALTER TABLE` and `CREATE INDEX` succeed.

- [ ] **Step 4: Commit**

```bash
cd /home/jeremy/epigraph
git add migrations/032_claim_themes_properties.sql
git commit -m "migration: add claim_themes.properties JSONB column

Backs textbook-seeded theme metadata (source_textbook_claim_id, etc.)
per spec 2026-05-18-cross-source-anchor."
```

---

## Task 2: `embedding_neighborhood_density` HTTP endpoint

**Files:**
- Create: `crates/epigraph-api/src/routes/embeddings.rs`
- Modify: `crates/epigraph-api/src/routes/mod.rs` (add `pub mod embeddings;`)
- Modify: `crates/epigraph-api/src/bin/server.rs` (route wire-up)
- Create: `crates/epigraph-api/tests/embedding_neighborhood_density_test.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/epigraph-api/tests/embedding_neighborhood_density_test.rs`:

```rust
#![cfg(feature = "db")]

//! Integration test for POST /api/v1/embeddings/neighborhood-density.
//! Seeds 6 claims with simple embeddings; queries near one of them; expects
//! a non-zero count and a per-level breakdown.

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn neighborhood_density_returns_count_and_breakdown() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();

    // Wipe prior test rows.
    sqlx::query("DELETE FROM claims WHERE content LIKE 'density-test-%'")
        .execute(&pool).await.unwrap();

    // Seed: 3 atoms (level=3) + 2 paragraphs (level=2) close to query embedding,
    // 1 far away. Use a sentinel agent so we don't depend on the agents table state.
    let agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('AA', 32), 'hex'), 'density-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    ).bind(agent_id).execute(&pool).await.unwrap();

    let near_vec: Vec<f32> = (0..1536).map(|i| if i < 8 { 1.0 } else { 0.0 }).collect();
    let near_str = format!("[{}]", near_vec.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(","));

    for i in 0..5 {
        let level = if i < 3 { 3 } else { 2 };
        sqlx::query(
            "INSERT INTO claims (content, content_hash, agent_id, properties, embedding) \
             VALUES ($1, decode(md5($1), 'hex'), $2, \
                     jsonb_build_object('level', $3::text, 'source_type', 'Textbook'), \
                     $4::vector)",
        )
        .bind(format!("density-test-near-{i}"))
        .bind(agent_id)
        .bind(level.to_string())
        .bind(&near_str)
        .execute(&pool).await.unwrap();
    }

    let far_vec: Vec<f32> = (0..1536).map(|i| if i >= 1500 { 1.0 } else { 0.0 }).collect();
    let far_str = format!("[{}]", far_vec.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(","));
    sqlx::query(
        "INSERT INTO claims (content, content_hash, agent_id, properties, embedding) \
         VALUES ('density-test-far', decode(md5('density-test-far'), 'hex'), $1, '{}'::jsonb, $2::vector)",
    )
    .bind(agent_id).bind(&far_str).execute(&pool).await.unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/embeddings/neighborhood-density"))
        .bearer_auth(&token)
        .json(&json!({ "query": "density test near", "radius": 0.3, "max_sample": 50 }))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "endpoint should return 200");
    let body: Value = resp.json().await.unwrap();
    let n = body["n_claims"].as_i64().expect("n_claims field");
    assert!(n >= 5, "expected ≥5 near claims, got {n}; body: {body}");
    assert!(body["by_level"]["2"].as_i64().unwrap_or(0) >= 2);
    assert!(body["by_level"]["3"].as_i64().unwrap_or(0) >= 3);
    assert!(body["mean_similarity"].as_f64().unwrap_or(0.0) > 0.5);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/jeremy/epigraph
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test --test embedding_neighborhood_density_test --features db 2>&1 | tail -20
```

Expected: compile error referencing missing `routes/embeddings.rs` or missing route.

- [ ] **Step 3: Create the route module**

Create `crates/epigraph-api/src/routes/embeddings.rs`:

```rust
//! Embedding-space diagnostics endpoints.
//!
//! ## Endpoints
//! - `POST /api/v1/embeddings/neighborhood-density` — count + summary stats
//!   for claims within a cosine radius of a query embedding. Used by the
//!   nightly theme-maintenance workflow (`mcp__epigraph__embedding_neighborhood_density`)
//!   and by the cross-source anchor pass to detect dense regions that warrant
//!   theme sub-splitting.
//!
//! See docs/superpowers/specs/2026-05-18-cross-source-anchor-design.md §Component 0.

#[cfg(feature = "db")]
use axum::{extract::State, Json};
#[cfg(feature = "db")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
use std::collections::BTreeMap;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct NeighborhoodDensityRequest {
    pub query: String,
    pub radius: Option<f64>,
    pub max_sample: Option<i64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Serialize)]
pub struct NeighborhoodDensityResponse {
    pub n_claims: i64,
    pub mean_similarity: f64,
    pub median_similarity: f64,
    pub sparsity: f64,
    pub by_level: BTreeMap<String, i64>,
    pub by_source_type: BTreeMap<String, i64>,
    pub radius: f64,
    pub embedding_dim: u32,
}

/// POST /api/v1/embeddings/neighborhood-density
#[cfg(feature = "db")]
pub async fn neighborhood_density(
    State(state): State<AppState>,
    Json(req): Json<NeighborhoodDensityRequest>,
) -> Result<Json<NeighborhoodDensityResponse>, ApiError> {
    let radius = req.radius.unwrap_or(0.30);
    let max_sample = req.max_sample.unwrap_or(500).clamp(1, 5000);

    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;
    let embedding = embedder
        .generate(&req.query)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to embed query: {e}"),
        })?;
    let embedding_dim = embedding.len() as u32;
    let embedding_str = format!(
        "[{}]",
        embedding
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    // Aggregate stats in one round trip. Uses the existing HNSW index on
    // claims.embedding via the `<=>` cosine-distance operator. Cosine
    // similarity = 1 - cosine_distance. Filter is `similarity >= 1 - radius`
    // in distance space because pgvector indexes operate on distance.
    let row = sqlx::query_as::<_, (i64, Option<f64>, Option<f64>)>(
        "SELECT COUNT(*)::bigint AS n, \
                AVG(1 - (embedding <=> $1::vector))::float8 AS mean_sim, \
                percentile_cont(0.5) WITHIN GROUP \
                    (ORDER BY 1 - (embedding <=> $1::vector))::float8 AS median_sim \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND is_current = true \
           AND (embedding <=> $1::vector) <= $2",
    )
    .bind(&embedding_str)
    .bind(radius)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("density aggregate failed: {e}"),
    })?;
    let n_claims = row.0;
    let mean_similarity = row.1.unwrap_or(0.0);
    let median_similarity = row.2.unwrap_or(0.0);

    // Sample for level + source_type breakdown. Use max_sample to bound
    // worst-case scan even when n_claims is huge.
    let breakdown_rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT properties->>'level' AS lvl, properties->>'source_type' AS src \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND is_current = true \
           AND (embedding <=> $1::vector) <= $2 \
         ORDER BY embedding <=> $1::vector \
         LIMIT $3",
    )
    .bind(&embedding_str)
    .bind(radius)
    .bind(max_sample)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("density breakdown failed: {e}"),
    })?;

    let mut by_level: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_source_type: BTreeMap<String, i64> = BTreeMap::new();
    for (lvl, src) in &breakdown_rows {
        let l = lvl.clone().unwrap_or_else(|| "unknown".into());
        let s = src.clone().unwrap_or_else(|| "unknown".into());
        *by_level.entry(l).or_insert(0) += 1;
        *by_source_type.entry(s).or_insert(0) += 1;
    }

    // Sparsity: squashed inverse of n_claims with target_n=200 as the
    // "comfortable" density. Bounded (0, 1]. Lower = denser.
    let sparsity = 1.0 / (1.0 + (n_claims as f64) / 200.0);

    Ok(Json(NeighborhoodDensityResponse {
        n_claims,
        mean_similarity,
        median_similarity,
        sparsity,
        by_level,
        by_source_type,
        radius,
        embedding_dim,
    }))
}
```

- [ ] **Step 4: Register the module**

In `crates/epigraph-api/src/routes/mod.rs`, alphabetically insert after `pub mod edges;`:

```rust
pub mod embeddings;
```

- [ ] **Step 5: Wire the route into the server**

In `crates/epigraph-api/src/bin/server.rs`, locate the block that wires `experiments::hypothesize` (around line 327) and add this route nearby:

```rust
        .route(
            "/api/v1/embeddings/neighborhood-density",
            post(embeddings::neighborhood_density),
        )
```

Also add the import near the other route imports:

```rust
use epigraph_api::routes::embeddings;
```

(Match the surrounding `use` style — if other routes use `use ...::routes::{experiments, ...}` grouped form, append `embeddings` to the group instead.)

- [ ] **Step 6: Update sqlx offline cache**

```bash
cd /home/jeremy/epigraph
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo sqlx prepare --workspace -- --tests 2>&1 | tail -5
```

Expected: `query data written to .sqlx/`. Stage the new `.sqlx/*.json` files for commit later.

- [ ] **Step 7: Run test to verify it passes**

```bash
cd /home/jeremy/epigraph
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test --test embedding_neighborhood_density_test --features db 2>&1 | tail -20
```

Expected: `test result: ok. 1 passed`.

- [ ] **Step 8: Commit**

```bash
cd /home/jeremy/epigraph
git add crates/epigraph-api/src/routes/embeddings.rs \
        crates/epigraph-api/src/routes/mod.rs \
        crates/epigraph-api/src/bin/server.rs \
        crates/epigraph-api/tests/embedding_neighborhood_density_test.rs \
        .sqlx/
git commit -m "feat(api): POST /api/v1/embeddings/neighborhood-density

Aggregates claim count, similarity stats, and per-level/source breakdown
for the embedding ball around a query. Restores the tool the nightly
theme-maintenance workflow already references but was missing from code.

Per spec 2026-05-18-cross-source-anchor §Component 0a."
```

---

## Task 3: `embedding_neighborhood_density` MCP wrapper

**Files:**
- Create: `crates/epigraph-mcp/src/tools/embeddings.rs`
- Modify: `crates/epigraph-mcp/src/tools/mod.rs` (add `pub mod embeddings;`)
- Modify: `crates/epigraph-mcp/src/server.rs` (register tool)

- [ ] **Step 1: Locate where other tools are registered**

```bash
grep -n "theme_cluster\|themes::theme_cluster" /home/jeremy/epigraph/crates/epigraph-mcp/src/server.rs | head -5
```

Note the line numbers for the tool registration block — Step 4 inserts next to them.

- [ ] **Step 2: Create the MCP tool**

Create `crates/epigraph-mcp/src/tools/embeddings.rs`:

```rust
//! `embedding_neighborhood_density` MCP tool. Wraps the HTTP endpoint
//! `POST /api/v1/embeddings/neighborhood-density` so MCP clients (EpiClaw,
//! the nightly theme-maintenance workflow) can query density without an HTTP
//! detour. Per design 2026-05-18-cross-source-anchor §Component 0a.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmbeddingNeighborhoodDensityParams {
    /// Free-text query — embedded server-side via the configured embedder.
    pub query: String,
    /// Cosine distance radius (0.0 = identical, 1.0 = orthogonal). Default 0.30.
    pub radius: Option<f64>,
    /// Cap on sample size used to compute level/source breakdowns. Default 500.
    pub max_sample: Option<i64>,
}

pub async fn embedding_neighborhood_density(
    server: &EpiGraphMcpFull,
    params: EmbeddingNeighborhoodDensityParams,
) -> Result<CallToolResult, McpError> {
    let radius = params.radius.unwrap_or(0.30);
    let max_sample = params.max_sample.unwrap_or(500).clamp(1, 5000);

    let embedder = server
        .embedding_service
        .as_ref()
        .ok_or_else(|| internal_error("Embedding service not configured"))?;
    let embedding = embedder
        .generate(&params.query)
        .await
        .map_err(|e| internal_error(format!("embed failed: {e}")))?;
    let embedding_dim = embedding.len() as u32;
    let embedding_str = format!(
        "[{}]",
        embedding
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    let row: (i64, Option<f64>, Option<f64>) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, \
                AVG(1 - (embedding <=> $1::vector))::float8, \
                percentile_cont(0.5) WITHIN GROUP \
                    (ORDER BY 1 - (embedding <=> $1::vector))::float8 \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND is_current = true \
           AND (embedding <=> $1::vector) <= $2",
    )
    .bind(&embedding_str)
    .bind(radius)
    .fetch_one(&server.pool)
    .await
    .map_err(internal_error)?;
    let n_claims = row.0;
    let mean_similarity = row.1.unwrap_or(0.0);
    let median_similarity = row.2.unwrap_or(0.0);

    let breakdown_rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT properties->>'level', properties->>'source_type' \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND is_current = true \
           AND (embedding <=> $1::vector) <= $2 \
         ORDER BY embedding <=> $1::vector \
         LIMIT $3",
    )
    .bind(&embedding_str)
    .bind(radius)
    .bind(max_sample)
    .fetch_all(&server.pool)
    .await
    .map_err(internal_error)?;

    let mut by_level: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_source_type: BTreeMap<String, i64> = BTreeMap::new();
    for (lvl, src) in &breakdown_rows {
        let l = lvl.clone().unwrap_or_else(|| "unknown".into());
        let s = src.clone().unwrap_or_else(|| "unknown".into());
        *by_level.entry(l).or_insert(0) += 1;
        *by_source_type.entry(s).or_insert(0) += 1;
    }

    let sparsity = 1.0 / (1.0 + (n_claims as f64) / 200.0);

    let body = serde_json::json!({
        "n_claims": n_claims,
        "mean_similarity": mean_similarity,
        "median_similarity": median_similarity,
        "sparsity": sparsity,
        "by_level": by_level,
        "by_source_type": by_source_type,
        "radius": radius,
        "embedding_dim": embedding_dim,
    });

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}
```

- [ ] **Step 3: Register module**

In `crates/epigraph-mcp/src/tools/mod.rs`, alphabetically insert after `pub mod ds_auto;` (or wherever the alphabetical slot for `embeddings` falls):

```rust
pub mod embeddings;
```

- [ ] **Step 4: Wire into MCP server**

In `crates/epigraph-mcp/src/server.rs`, find the `theme_cluster` registration (located at the line number from Step 1) and add a sibling registration for `embedding_neighborhood_density`. Follow the exact macro/pattern used by `theme_cluster` — if that uses an `rmcp` tool macro, mirror it; if it's a manual `tool_list` push, mirror that.

Search for the existing pattern:

```bash
grep -n "theme_cluster\|name.*\"theme_cluster\"" /home/jeremy/epigraph/crates/epigraph-mcp/src/server.rs | head -5
```

Pattern to add (adapt to match existing structure exactly):

```rust
// In tool listing:
tools.push(Tool {
    name: "embedding_neighborhood_density".into(),
    description: Some("Aggregate claim count + similarity stats for the embedding ball around a query".into()),
    input_schema: schema_for_params::<tools::embeddings::EmbeddingNeighborhoodDensityParams>(),
    annotations: None,
});

// In tool dispatch match arm:
"embedding_neighborhood_density" => {
    let params: tools::embeddings::EmbeddingNeighborhoodDensityParams =
        serde_json::from_value(arguments).map_err(invalid_params)?;
    tools::embeddings::embedding_neighborhood_density(self, params).await
}
```

- [ ] **Step 5: Compile-check**

```bash
cd /home/jeremy/epigraph
cargo check --workspace --features db 2>&1 | tail -10
```

Expected: no errors.

- [ ] **Step 6: Smoke-test via the API server**

Start the server, then call the MCP-equivalent HTTP route:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/embeddings/neighborhood-density \
  -H "Content-Type: application/json" \
  -d '{"query": "Bernoulli equation streamline", "radius": 0.3}' | head -30
```

Expected: JSON with `n_claims`, `mean_similarity`, `by_level`, `by_source_type`.

- [ ] **Step 7: Commit**

```bash
cd /home/jeremy/epigraph
git add crates/epigraph-mcp/src/tools/embeddings.rs \
        crates/epigraph-mcp/src/tools/mod.rs \
        crates/epigraph-mcp/src/server.rs
git commit -m "feat(mcp): embedding_neighborhood_density tool

Mirrors POST /api/v1/embeddings/neighborhood-density so MCP clients
(EpiClaw, nightly theme-maintenance workflow) can query density directly.

Per spec 2026-05-18-cross-source-anchor §Component 0a."
```

---

## Task 4: Extend `hypothesize` with `cluster_count`

**Files:**
- Modify: `crates/epigraph-api/src/routes/experiments.rs` (lines 28–162)
- Create: `crates/epigraph-api/tests/hypothesize_cluster_test.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/epigraph-api/tests/hypothesize_cluster_test.rs`:

```rust
#![cfg(feature = "db")]

//! Verifies that hypothesize() with cluster_count=N returns N clusters of
//! similar claims with centroid summaries. Per spec
//! 2026-05-18-cross-source-anchor §Component 0b.

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn hypothesize_returns_clusters_when_cluster_count_set() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();

    sqlx::query("DELETE FROM claims WHERE content LIKE 'hyp-cluster-%'")
        .execute(&pool).await.unwrap();

    let agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('AA', 32), 'hex'), 'hyp-cluster-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    ).bind(agent_id).execute(&pool).await.unwrap();

    // Seed 20 claims in two distinct clusters in embedding space.
    for i in 0..20 {
        let cluster_a = i < 10;
        let vec: Vec<f32> = (0..1536)
            .map(|j| if cluster_a && j < 8 { 1.0 } else if !cluster_a && j >= 1500 { 1.0 } else { 0.0 })
            .collect();
        let vstr = format!("[{}]", vec.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(","));
        sqlx::query(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, properties, embedding) \
             VALUES ($1, decode(md5($1), 'hex'), $2, $3, '{}'::jsonb, $4::vector)",
        )
        .bind(format!("hyp-cluster-{i}"))
        .bind(agent_id)
        .bind(if cluster_a { 0.8 } else { 0.4 })
        .bind(&vstr)
        .execute(&pool).await.unwrap();
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/experiments/hypothesize"))
        .bearer_auth(&token)
        .json(&json!({ "statement": "hyp cluster test", "search_radius": 0.2, "cluster_count": 2 }))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    let clusters = body["clusters"].as_array().expect("clusters field present");
    assert_eq!(clusters.len(), 2, "expected 2 clusters, got {}; body: {body}", clusters.len());
    for c in clusters {
        assert!(c["claim_ids"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
        assert!(c["centroid_summary"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
        assert!(c["mean_prior_belief"].as_f64().is_some());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hypothesize_without_cluster_count_omits_clusters_field() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let _pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/experiments/hypothesize"))
        .bearer_auth(&token)
        .json(&json!({ "statement": "anything", "search_radius": 0.5 }))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    assert!(body.get("clusters").is_none() || body["clusters"].is_null(),
            "clusters field must not appear when cluster_count is absent");
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/jeremy/epigraph
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test --test hypothesize_cluster_test --features db 2>&1 | tail -20
```

Expected: FAIL — `clusters` field missing or test assertion fails.

- [ ] **Step 3: Edit `HypothesizeRequest` and handler**

In `crates/epigraph-api/src/routes/experiments.rs`, modify the request struct (around line 30):

```rust
#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct HypothesizeRequest {
    pub statement: String,
    pub search_radius: Option<f64>,
    /// When set, the handler runs k-means with this many clusters over the
    /// similar-claims neighborhood and returns a `clusters` field with one
    /// entry per cluster (LLM-emitted centroid summary, member claim IDs,
    /// mean prior belief). Per spec 2026-05-18-cross-source-anchor §0b.
    pub cluster_count: Option<u32>,
}
```

At the bottom of the `hypothesize` handler (after the existing `similar_json` construction, before the final `Ok(Json(...))`), add the clustering branch:

```rust
    // Optional clustering branch — only fires when cluster_count is set.
    let clusters_value = if let Some(k) = request.cluster_count {
        if k == 0 || similar.is_empty() {
            serde_json::Value::Array(vec![])
        } else {
            // Pull embeddings for the same neighborhood — re-query because the
            // initial `similar` projection doesn't include the vector column.
            let neighborhood: Vec<(uuid::Uuid, Vec<f32>, Option<f64>)> = sqlx::query_as(
                "SELECT id, embedding::text::vector::float4[], truth_value \
                 FROM claims \
                 WHERE embedding IS NOT NULL \
                   AND is_current = true \
                   AND 1 - (embedding <=> $1::vector) >= $2 \
                 ORDER BY embedding <=> $1::vector \
                 LIMIT 200",
            )
            .bind(format_embedding(&embedding))
            .bind(search_radius)
            .fetch_all(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to fetch neighborhood embeddings: {e}"),
            })?;

            let embeddings: Vec<Vec<f32>> = neighborhood.iter().map(|(_, e, _)| e.clone()).collect();
            let ids: Vec<uuid::Uuid> = neighborhood.iter().map(|(id, _, _)| *id).collect();
            let truths: Vec<f64> = neighborhood.iter().map(|(_, _, t)| t.unwrap_or(0.5)).collect();

            let cluster_result = epigraph_engine::theme_cluster::cluster_embeddings(
                &embeddings,
                k as usize,
                25,
            );

            let mut clusters: Vec<serde_json::Value> = Vec::with_capacity(cluster_result.centroids.len());
            for c in 0..cluster_result.centroids.len() {
                let member_ids: Vec<uuid::Uuid> = cluster_result
                    .assignments
                    .iter()
                    .enumerate()
                    .filter(|(_, &a)| a == c)
                    .map(|(i, _)| ids[i])
                    .collect();
                if member_ids.is_empty() {
                    continue;
                }
                let mean_prior: f64 = {
                    let sum: f64 = cluster_result
                        .assignments
                        .iter()
                        .enumerate()
                        .filter(|(_, &a)| a == c)
                        .map(|(i, _)| truths[i])
                        .sum();
                    sum / member_ids.len() as f64
                };

                // Centroid summary: short label built from the nearest claim's
                // content prefix. LLM-driven summarisation is a follow-up — the
                // anchor pass calls Claude separately; this endpoint stays
                // dependency-light. See spec open question on centroid_summary.
                let summary = {
                    let nearest_idx = cluster_result
                        .assignments
                        .iter()
                        .position(|&a| a == c)
                        .unwrap();
                    let nearest_id = ids[nearest_idx];
                    similar
                        .iter()
                        .find(|s| s.id == nearest_id)
                        .map(|s| s.content.chars().take(80).collect::<String>())
                        .unwrap_or_else(|| format!("cluster-{c}"))
                };

                clusters.push(serde_json::json!({
                    "centroid_summary": summary,
                    "claim_ids": member_ids,
                    "mean_prior_belief": mean_prior,
                    "member_count": member_ids.len(),
                }));
            }
            serde_json::Value::Array(clusters)
        }
    } else {
        serde_json::Value::Null
    };

    let mut response = serde_json::json!({
        "prior_belief": prior_belief,
        "similar_claims": similar_json,
        "similar_count": similar.len(),
        "epistemic_status": status,
    });
    if !clusters_value.is_null() {
        response["clusters"] = clusters_value;
    }
    Ok(Json(response))
```

Replace the final `Ok(Json(serde_json::json!({...})))` block with the `let mut response = ...` block above.

- [ ] **Step 4: Add the engine dependency import if missing**

Ensure `crates/epigraph-api/Cargo.toml` includes `epigraph-engine` (it likely already does — check):

```bash
grep "epigraph-engine" /home/jeremy/epigraph/crates/epigraph-api/Cargo.toml | head -3
```

If absent, add `epigraph-engine = { path = "../epigraph-engine" }` under `[dependencies]`.

- [ ] **Step 5: Update sqlx offline cache**

```bash
cd /home/jeremy/epigraph
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo sqlx prepare --workspace -- --tests 2>&1 | tail -3
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd /home/jeremy/epigraph
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test --test hypothesize_cluster_test --features db 2>&1 | tail -15
```

Expected: `test result: ok. 2 passed`.

- [ ] **Step 7: Commit**

```bash
cd /home/jeremy/epigraph
git add crates/epigraph-api/src/routes/experiments.rs \
        crates/epigraph-api/tests/hypothesize_cluster_test.rs \
        crates/epigraph-api/Cargo.toml \
        .sqlx/
git commit -m "feat(api): hypothesize cluster_count parameter

Adds optional cluster_count to POST /api/v1/experiments/hypothesize.
When set, runs k-means over the similar-claim neighborhood and returns
clusters with centroid summary, member ids, and mean prior belief.

Backward compatible: cluster_count absent => identical response shape
as before (no clusters field). Per spec 2026-05-18-cross-source-anchor
§Component 0b."
```

---

## Task 5: Paper document-type classifier script

**Files:**
- Create: `scripts/classify_paper_document_type.py`

- [ ] **Step 1: Write the script**

Create `scripts/classify_paper_document_type.py`:

```python
#!/usr/bin/env python3
"""Classify each paper L0 claim as 'review' or 'frontier'.

Sets properties.document_type and properties.document_type_confidence on
the L0 claim row via a PATCH through the EpiGraph claims API. Descendants
inherit at query time via decomposes_to walk; no denormalisation.

LLM: spawns `claude -p` per paper. Per feedback_claude_cli_oauth.md we never
import the Anthropic SDK directly.

Idempotent: skips L0 papers that already have a document_type set.
Per spec 2026-05-18-cross-source-anchor-design.md §Component 1.

Usage:
    python3 scripts/classify_paper_document_type.py
    python3 scripts/classify_paper_document_type.py --limit 5 --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Optional

import psycopg2
import psycopg2.extras

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)

PROMPT_TEMPLATE = """\
You are classifying an academic paper as either a REVIEW article or a FRONTIER \
(primary research) article. A review article synthesizes existing literature, \
typically cites many primary sources, and integrates findings across a subfield. \
A frontier article reports new experimental, observational, or theoretical results.

Title: {title}

Opening content:
{opening}

Respond with ONLY a JSON object of the form:
{{"document_type": "review" | "frontier", "confidence": 0.0-1.0, "reason": "one short sentence"}}

Do not include any other text.\
"""


def fetch_paper_l0_claims(conn, limit: Optional[int]) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    q = (
        "SELECT id, content, properties "
        "FROM claims "
        "WHERE is_current = true "
        "  AND properties->>'source_type' = 'Paper' "
        "  AND properties->>'level' = '0' "
        "  AND (properties->>'document_type') IS NULL "
        "ORDER BY created_at ASC"
    )
    if limit:
        q += f" LIMIT {int(limit)}"
    cur.execute(q)
    return list(cur.fetchall())


def fetch_first_l1_child(conn, parent_id: str) -> Optional[str]:
    cur = conn.cursor()
    cur.execute(
        "SELECT c.content FROM edges e JOIN claims c ON c.id = e.target_id "
        "WHERE e.source_id = %s AND e.relationship = 'decomposes_to' "
        "  AND c.properties->>'level' = '1' "
        "ORDER BY e.created_at ASC LIMIT 1",
        (parent_id,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def classify_via_claude(title: str, opening: str) -> dict:
    prompt = PROMPT_TEMPLATE.format(title=title, opening=opening[:2000])
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude CLI exit {proc.returncode}: {proc.stderr[:400]}")
    envelope = json.loads(proc.stdout)
    text = envelope.get("result") if isinstance(envelope, dict) else None
    if not text:
        raise RuntimeError(f"claude returned empty result: {envelope}")
    text = text.strip().strip("`").lstrip("json").strip()
    parsed = json.loads(text)
    if parsed.get("document_type") not in {"review", "frontier"}:
        raise RuntimeError(f"unexpected document_type: {parsed}")
    return parsed


def patch_claim(conn, claim_id: str, document_type: str, confidence: float, reason: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "UPDATE claims SET properties = properties || %s::jsonb, updated_at = NOW() "
        "WHERE id = %s",
        (
            json.dumps({
                "document_type": document_type,
                "document_type_confidence": confidence,
                "document_type_reason": reason,
            }),
            claim_id,
        ),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true", help="classify but do not write")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    papers = fetch_paper_l0_claims(conn, args.limit)
    if not papers:
        print("No unclassified paper L0 claims found.")
        return 0
    print(f"Found {len(papers)} paper L0 claims to classify.")

    for p in papers:
        claim_id = str(p["id"])
        title = (p["content"] or "")[:300]
        opening = fetch_first_l1_child(conn, claim_id) or title
        try:
            result = classify_via_claude(title, opening)
        except Exception as e:
            print(f"[err] {claim_id}: {e}", file=sys.stderr)
            continue
        dt = result["document_type"]
        conf = float(result.get("confidence", 0.5))
        reason = result.get("reason", "")
        print(f"[{dt:8s} conf={conf:.2f}] {claim_id} :: {title[:80]}")
        if not args.dry_run:
            patch_claim(conn, claim_id, dt, conf, reason)
            conn.commit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Dry-run smoke test on 2 papers**

```bash
cd /home/jeremy/epigraph
python3 scripts/classify_paper_document_type.py --limit 2 --dry-run
```

Expected: prints 2 lines like `[frontier conf=0.92] <uuid> :: <title>...` (or `review`). No DB writes.

- [ ] **Step 3: Real run on all unclassified papers**

```bash
cd /home/jeremy/epigraph
python3 scripts/classify_paper_document_type.py
```

Expected: classifies all 25 paper L0 claims; output ends with the last classified line. Re-running prints `No unclassified paper L0 claims found.`

- [ ] **Step 4: Verify via SQL**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph \
  -c "SELECT properties->>'document_type' AS dt, COUNT(*) FROM claims \
      WHERE is_current=true AND properties->>'source_type'='Paper' \
        AND properties->>'level'='0' GROUP BY 1;"
```

Expected: rows like `review | N`, `frontier | M` summing to 25.

- [ ] **Step 5: Commit**

```bash
cd /home/jeremy/epigraph
git add scripts/classify_paper_document_type.py
git commit -m "scripts: classify paper L0 claims as review vs frontier

Per spec 2026-05-18-cross-source-anchor §Component 1. Idempotent;
uses claude -p per the OAuth-CLI convention."
```

---

## Task 6: Textbook-seeded theme rebuild script

**Files:**
- Create: `scripts/seed_themes_from_textbooks.py`

- [ ] **Step 1: Write the script**

Create `scripts/seed_themes_from_textbooks.py`:

```python
#!/usr/bin/env python3
"""Seed claim_themes from textbook L1 sections.

For each textbook L1 claim:
  1. Compute centroid as mean of L1 + decomposes_to descendants' embeddings
     (1536d and 3072d if populated).
  2. Use claude -p to emit a short label (<=60 chars) and description
     (<=250 chars) from the L1 content + descendant atom samples.
  3. INSERT into claim_themes with properties.source_textbook_claim_id.
  4. Backfill claims.theme_id on the L1 and all decomposes_to descendants.

Drops existing auto-NN themes ONLY after a successful seed run (Step 5 in
this script), to free the 500 claims currently in auto-NN themes for the
anchor pass in Task 7.

Idempotent: skips L1 claims whose source_textbook_claim_id already exists
in claim_themes.properties.

Per spec 2026-05-18-cross-source-anchor-design.md §Component 2.

Usage:
    python3 scripts/seed_themes_from_textbooks.py --dry-run --limit 5
    python3 scripts/seed_themes_from_textbooks.py --limit 50
    python3 scripts/seed_themes_from_textbooks.py --drop-auto-after
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Optional

import psycopg2
import psycopg2.extras

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)

LABEL_PROMPT = """\
You are labeling a textbook section that will serve as a "concept anchor" \
in a knowledge graph. Paper claims will be attached to this anchor if they \
instantiate the concept it describes.

Section content:
{section_content}

Three sample atomic claims from this section:
{atoms}

Respond with ONLY a JSON object:
{{"label": "<= 60 chars: short concept name (e.g., 'Bernoulli's Equation — Streamline Form')>",
  "description": "<= 250 chars: what concept this anchor covers and what kind of paper claim would instantiate it>"}}

Do not include any other text.\
"""


def fetch_textbook_l1_claims(conn, limit: Optional[int]) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    q = (
        "SELECT id, content "
        "FROM claims "
        "WHERE is_current = true "
        "  AND properties->>'source_type' = 'Textbook' "
        "  AND properties->>'level' = '1' "
        "  AND id NOT IN ( "
        "    SELECT (properties->>'source_textbook_claim_id')::uuid "
        "    FROM claim_themes "
        "    WHERE properties ? 'source_textbook_claim_id' "
        "  ) "
        "ORDER BY created_at ASC"
    )
    if limit:
        q += f" LIMIT {int(limit)}"
    cur.execute(q)
    return list(cur.fetchall())


def fetch_descendant_ids(conn, root_id: str) -> list[str]:
    cur = conn.cursor()
    cur.execute(
        "WITH RECURSIVE walk(id) AS ( "
        "  SELECT %s::uuid "
        "  UNION "
        "  SELECT e.target_id FROM edges e JOIN walk w ON e.source_id = w.id "
        "  WHERE e.relationship = 'decomposes_to' "
        ") SELECT id FROM walk",
        (root_id,),
    )
    return [str(r[0]) for r in cur.fetchall()]


def fetch_embeddings(conn, ids: list[str], dim: int) -> list[list[float]]:
    if not ids:
        return []
    col = "embedding" if dim == 1536 else "embedding_3072"
    cur = conn.cursor()
    cur.execute(
        f"SELECT {col}::text FROM claims WHERE id = ANY(%s) AND {col} IS NOT NULL",
        (ids,),
    )
    out: list[list[float]] = []
    for row in cur.fetchall():
        s = row[0]
        if s is None:
            continue
        vec = [float(x) for x in s.strip("[]").split(",")]
        out.append(vec)
    return out


def mean_vector(vecs: list[list[float]]) -> Optional[list[float]]:
    if not vecs:
        return None
    n = len(vecs)
    dim = len(vecs[0])
    out = [0.0] * dim
    for v in vecs:
        for i, x in enumerate(v):
            out[i] += x
    return [x / n for x in out]


def fetch_sample_atoms(conn, root_id: str, k: int = 3) -> list[str]:
    cur = conn.cursor()
    cur.execute(
        "WITH RECURSIVE walk(id) AS ( "
        "  SELECT %s::uuid "
        "  UNION "
        "  SELECT e.target_id FROM edges e JOIN walk w ON e.source_id = w.id "
        "  WHERE e.relationship = 'decomposes_to' "
        ") SELECT c.content FROM walk JOIN claims c ON c.id = walk.id "
        "WHERE c.properties->>'level' = '3' "
        "ORDER BY random() LIMIT %s",
        (root_id, k),
    )
    return [r[0] for r in cur.fetchall()]


def label_via_claude(section_content: str, atoms: list[str]) -> dict:
    atom_block = "\n".join(f"- {a[:300]}" for a in atoms) or "(none)"
    prompt = LABEL_PROMPT.format(section_content=section_content[:2000], atoms=atom_block)
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude exit {proc.returncode}: {proc.stderr[:400]}")
    envelope = json.loads(proc.stdout)
    text = envelope.get("result") if isinstance(envelope, dict) else None
    if not text:
        raise RuntimeError(f"empty claude result: {envelope}")
    text = text.strip().strip("`").lstrip("json").strip()
    parsed = json.loads(text)
    label = parsed["label"][:60]
    description = parsed["description"][:250]
    return {"label": label, "description": description}


def insert_theme(conn, label: str, description: str, centroid_1536: Optional[list[float]],
                 centroid_3072: Optional[list[float]], source_textbook_claim_id: str) -> str:
    cur = conn.cursor()
    c1 = "[" + ",".join(str(x) for x in centroid_1536) + "]" if centroid_1536 else None
    c2 = "[" + ",".join(str(x) for x in centroid_3072) + "]" if centroid_3072 else None
    cur.execute(
        "INSERT INTO claim_themes (label, description, centroid, centroid_3072, properties) "
        "VALUES (%s, %s, %s::vector, %s::vector, %s::jsonb) RETURNING id",
        (label, description, c1, c2,
         json.dumps({"source_textbook_claim_id": source_textbook_claim_id, "seeded_by": "textbook_l1"})),
    )
    return str(cur.fetchone()[0])


def assign_theme(conn, theme_id: str, claim_ids: list[str]) -> int:
    if not claim_ids:
        return 0
    cur = conn.cursor()
    cur.execute("UPDATE claims SET theme_id = %s WHERE id = ANY(%s)", (theme_id, claim_ids))
    return cur.rowcount


def update_theme_count(conn, theme_id: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "UPDATE claim_themes SET claim_count = "
        "  (SELECT COUNT(*) FROM claims WHERE theme_id = claim_themes.id) "
        "WHERE id = %s",
        (theme_id,),
    )


def drop_auto_themes(conn) -> int:
    cur = conn.cursor()
    cur.execute("UPDATE claims SET theme_id = NULL WHERE theme_id IN "
                "(SELECT id FROM claim_themes WHERE label LIKE 'auto-%')")
    cur.execute("DELETE FROM claim_themes WHERE label LIKE 'auto-%' RETURNING id")
    return len(cur.fetchall())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--drop-auto-after", action="store_true",
                    help="DELETE existing auto-NN themes after seeding completes (frees their 500 claim assignments).")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    sections = fetch_textbook_l1_claims(conn, args.limit)
    if not sections:
        print("No unprocessed textbook L1 sections found.")
    else:
        print(f"Found {len(sections)} textbook L1 sections to seed.")

    n_created = 0
    n_skipped = 0
    for s in sections:
        sid = str(s["id"])
        content = s["content"] or ""
        descendants = fetch_descendant_ids(conn, sid)
        emb_1536 = mean_vector(fetch_embeddings(conn, descendants, 1536))
        emb_3072 = mean_vector(fetch_embeddings(conn, descendants, 3072))
        if not emb_1536 and not emb_3072:
            print(f"[skip] {sid}: no descendants with embeddings")
            n_skipped += 1
            continue
        atoms = fetch_sample_atoms(conn, sid)
        try:
            label_obj = label_via_claude(content, atoms)
        except Exception as e:
            print(f"[err] {sid}: {e}", file=sys.stderr)
            continue
        label = label_obj["label"]
        description = label_obj["description"]
        print(f"[seed] {sid} :: {label}")
        if args.dry_run:
            n_created += 1
            continue
        theme_id = insert_theme(conn, label, description, emb_1536, emb_3072, sid)
        n_assigned = assign_theme(conn, theme_id, descendants)
        update_theme_count(conn, theme_id)
        conn.commit()
        print(f"       theme_id={theme_id} assigned {n_assigned} claims")
        n_created += 1

    print(f"\nSeeded {n_created} themes; skipped {n_skipped}.")

    if args.drop_auto_after and not args.dry_run:
        # Capture audit first
        cur = conn.cursor()
        cur.execute("SELECT id, label, claim_count FROM claim_themes WHERE label LIKE 'auto-%'")
        rows = cur.fetchall()
        print(f"\nDropping {len(rows)} auto-NN themes:")
        for r in rows:
            print(f"  {r[0]} {r[1]} claim_count={r[2]}")
        n_dropped = drop_auto_themes(conn)
        conn.commit()
        print(f"Dropped {n_dropped} auto-NN themes.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Dry-run on 3 sections**

```bash
cd /home/jeremy/epigraph
python3 scripts/seed_themes_from_textbooks.py --limit 3 --dry-run
```

Expected: prints 3 `[seed]` lines with proposed labels (e.g., `Bernoulli's Equation — Streamline Form`). No DB writes.

- [ ] **Step 3: Real run on 10 sections to validate**

```bash
cd /home/jeremy/epigraph
python3 scripts/seed_themes_from_textbooks.py --limit 10
```

Expected: 10 theme rows created with meaningful labels; claims assigned to themes. Re-run with `--limit 10` should print 10 new sections (idempotency check) until exhausted.

- [ ] **Step 4: Spot-check labels and assignments**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT label, claim_count, properties->>'source_textbook_claim_id' AS src \
   FROM claim_themes WHERE properties ? 'source_textbook_claim_id' \
   ORDER BY claim_count DESC LIMIT 10;"
```

Expected: labels look concept-y (not auto-NN), nonzero `claim_count`, valid source UUID.

- [ ] **Step 5: Full run + drop auto themes**

```bash
cd /home/jeremy/epigraph
python3 scripts/seed_themes_from_textbooks.py --drop-auto-after 2>&1 | tail -30
```

Expected: ~771 more seeded; `auto-NN` themes dropped at the end.

- [ ] **Step 6: Commit**

```bash
cd /home/jeremy/epigraph
git add scripts/seed_themes_from_textbooks.py
git commit -m "scripts: seed claim_themes from textbook L1 sections

Each textbook L1 becomes one claim_themes row with LLM-emitted label,
description, mean-descendant centroid, and source_textbook_claim_id in
properties. Backfills claims.theme_id on the L1 + decomposes_to
descendants. Optionally drops existing auto-NN themes.

Per spec 2026-05-18-cross-source-anchor §Component 2."
```

---

## Task 7: Paper-claim anchor pass script (textbook + review layers)

**Files:**
- Create: `scripts/anchor_papers_to_themes.py`

- [ ] **Step 1: Write the script**

Create `scripts/anchor_papers_to_themes.py`:

```python
#!/usr/bin/env python3
"""Anchor paper L3 atoms to textbook themes (and, for frontier papers, to
review-paper L2 paragraphs) via HNSW shortlist + claude is-instance-of judge.

For each paper claim:
  1. Embed not required — claim already has an embedding column.
  2. HNSW lookup against claim_themes.centroid → top-K theme candidates.
  3. For each candidate over threshold, run claude judge:
     "does this paper claim instantiate this textbook concept?"
  4. Highest-confidence yes -> claims.theme_id (primary anchor).
  5. Other yes/maybe verdicts -> INSTANTIATES edges with confidence + anchor_label.
  6. Frontier papers: also run an anchor pass over review-paper L2 paragraph
     embeddings; emit INSTANTIATES edges into review L2 targets.

Idempotent: skip paper claims whose properties.anchored_at is set.
Resumable: --limit + --skip-anchored cursoring.

Per spec 2026-05-18-cross-source-anchor §§Components 3 + 4.

Usage:
    python3 scripts/anchor_papers_to_themes.py --layer textbook --limit 50 --dry-run
    python3 scripts/anchor_papers_to_themes.py --layer textbook
    python3 scripts/anchor_papers_to_themes.py --layer review
    python3 scripts/anchor_papers_to_themes.py --layer both
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)

JUDGE_MODEL = "claude-haiku-4-5"  # informational only; the CLI picks the model

JUDGE_PROMPT = """\
You are deciding whether a paper claim is an instance of a textbook concept.

PAPER CLAIM:
{paper}

TEXTBOOK CONCEPT:
label: {label}
description: {description}

Question: does the paper claim instantiate (specialize, exemplify, or apply) \
the textbook concept? Be strict — coincidental keyword overlap is not \
instantiation.

Respond with ONLY a JSON object:
{{"verdict": "yes" | "maybe" | "no",
  "confidence": 0.0-1.0,
  "refined_anchor_label": "<= 60 chars: the bridging concept name (e.g. 'adatom mobility vs. temperature'); short and grep-able"}}

Do not include any other text.\
"""


def fetch_paper_claims(conn, layer: str, level: int, limit: Optional[int]) -> list[dict]:
    """Returns paper claims at given level that have embeddings and aren't yet anchored.

    Walks `decomposes_to` upward (leaf → root) tracking the original seed id so
    each row's `ancestor_id` is the deepest L0 reachable from that seed.
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # --layer review only needs frontier seed claims (review papers can't
    # anchor to themselves via the review-L2 bridge layer).
    seed_filter = ""
    if layer == "review":
        seed_filter = "AND ancestor.properties->>'document_type' = 'frontier'"
    q = f"""
        WITH RECURSIVE up(orig_id, cur_id, depth) AS (
          SELECT c.id, c.id, 0
          FROM claims c
          WHERE c.is_current = true
            AND c.properties->>'source_type' = 'Paper'
            AND c.properties->>'level' = '{level}'
            AND c.embedding IS NOT NULL
            AND (c.properties->>'anchored_at') IS NULL
          UNION ALL
          SELECT u.orig_id, e.source_id, u.depth + 1
          FROM edges e JOIN up u ON e.target_id = u.cur_id
          WHERE e.relationship = 'decomposes_to' AND u.depth < 5
        ),
        roots AS (
          SELECT DISTINCT ON (orig_id) orig_id, cur_id AS root_id
          FROM up
          ORDER BY orig_id, depth DESC
        )
        SELECT c.id, c.content,
               roots.root_id AS ancestor_id,
               ancestor.properties->>'document_type' AS doc_type
        FROM roots
        JOIN claims c ON c.id = roots.orig_id
        JOIN claims ancestor ON ancestor.id = roots.root_id
        WHERE TRUE {seed_filter}
        ORDER BY c.created_at ASC
    """
    if limit:
        q += f" LIMIT {int(limit)}"
    cur.execute(q)
    return list(cur.fetchall())


def hnsw_theme_candidates(conn, claim_id: str, top_k: int = 8, min_sim: float = 0.45) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT t.id, t.label, t.description, "
        "       t.properties->>'source_textbook_claim_id' AS source_textbook_claim_id, "
        "       1 - (t.centroid <=> c.embedding) AS sim "
        "FROM claim_themes t, claims c "
        "WHERE c.id = %s "
        "  AND t.centroid IS NOT NULL "
        "  AND t.properties ? 'source_textbook_claim_id' "
        "  AND 1 - (t.centroid <=> c.embedding) >= %s "
        "ORDER BY t.centroid <=> c.embedding "
        "LIMIT %s",
        (claim_id, min_sim, top_k),
    )
    return list(cur.fetchall())


def hnsw_review_l2_candidates(conn, claim_id: str, top_k: int = 8, min_sim: float = 0.45) -> list[dict]:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT rc.id, rc.content AS label, '' AS description, "
        "       rc.id::text AS source_textbook_claim_id, "
        "       1 - (rc.embedding <=> c.embedding) AS sim "
        "FROM claims c, claims rc "
        "JOIN edges e ON e.target_id = rc.id "
        "JOIN claims ancestor ON ancestor.id = e.source_id "
        "WHERE c.id = %s "
        "  AND rc.is_current = true "
        "  AND rc.properties->>'source_type' = 'Paper' "
        "  AND rc.properties->>'level' = '2' "
        "  AND rc.embedding IS NOT NULL "
        "  AND e.relationship = 'decomposes_to' "
        "  AND ancestor.properties->>'document_type' = 'review' "
        "  AND 1 - (rc.embedding <=> c.embedding) >= %s "
        "ORDER BY rc.embedding <=> c.embedding "
        "LIMIT %s",
        (claim_id, min_sim, top_k),
    )
    return list(cur.fetchall())


def judge_via_claude(paper_text: str, label: str, description: str) -> dict:
    prompt = JUDGE_PROMPT.format(paper=paper_text[:1500], label=label[:60], description=description[:250])
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True, text=True, timeout=90, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude exit {proc.returncode}: {proc.stderr[:300]}")
    envelope = json.loads(proc.stdout)
    text = envelope.get("result") if isinstance(envelope, dict) else None
    if not text:
        raise RuntimeError(f"empty claude result: {envelope}")
    text = text.strip().strip("`").lstrip("json").strip()
    parsed = json.loads(text)
    if parsed.get("verdict") not in {"yes", "maybe", "no"}:
        raise RuntimeError(f"bad verdict: {parsed}")
    return parsed


def insert_instantiates_edge(conn, source_id: str, target_id: str,
                             confidence: float, anchor_label: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, "
        "                   relationship, properties) "
        "VALUES (%s, %s, 'claim', 'claim', 'INSTANTIATES', %s::jsonb) "
        "ON CONFLICT DO NOTHING",
        (source_id, target_id,
         json.dumps({
             "confidence": confidence,
             "anchor_label": anchor_label,
             "judge_model": JUDGE_MODEL,
             "created_at": datetime.now(timezone.utc).isoformat(),
         })),
    )


def set_primary_theme(conn, claim_id: str, theme_id: str) -> None:
    cur = conn.cursor()
    cur.execute("UPDATE claims SET theme_id = %s WHERE id = %s", (theme_id, claim_id))


def mark_anchored(conn, claim_id: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "UPDATE claims SET properties = properties || %s::jsonb WHERE id = %s",
        (json.dumps({"anchored_at": datetime.now(timezone.utc).isoformat()}), claim_id),
    )


def anchor_one(conn, claim: dict, layer: str, top_k: int, min_sim: float,
               maybe_threshold: float, dry_run: bool) -> None:
    cid = str(claim["id"])
    content = claim["content"] or ""
    doc_type = claim["doc_type"] or "frontier"

    targets: list[tuple[str, dict]] = []
    if layer in {"textbook", "both"}:
        for cand in hnsw_theme_candidates(conn, cid, top_k=top_k, min_sim=min_sim):
            targets.append(("textbook", cand))
    if layer in {"review", "both"} and doc_type == "frontier":
        for cand in hnsw_review_l2_candidates(conn, cid, top_k=top_k, min_sim=min_sim):
            targets.append(("review", cand))

    if not targets:
        print(f"[noshort] {cid} :: {content[:60]}")
        if not dry_run:
            mark_anchored(conn, cid)
            conn.commit()
        return

    verdicts: list[tuple[str, dict, dict]] = []
    for layer_name, cand in targets:
        try:
            v = judge_via_claude(content, cand["label"] or "", cand["description"] or "")
        except Exception as e:
            print(f"[err] {cid} -> {cand['id']}: {e}", file=sys.stderr)
            continue
        verdicts.append((layer_name, cand, v))

    yes_or_strong_maybe = [
        (ln, c, v) for ln, c, v in verdicts
        if v["verdict"] == "yes" or (v["verdict"] == "maybe" and float(v.get("confidence", 0)) >= maybe_threshold)
    ]
    if not yes_or_strong_maybe:
        print(f"[noanchor] {cid} :: {content[:60]}")
        if not dry_run:
            mark_anchored(conn, cid)
            conn.commit()
        return

    yes_or_strong_maybe.sort(key=lambda t: float(t[2].get("confidence", 0)), reverse=True)
    primary_layer, primary_cand, primary_verdict = yes_or_strong_maybe[0]

    print(f"[anchor] {cid} -> {primary_layer}:{primary_cand['id']} "
          f"({primary_verdict['verdict']} conf={primary_verdict.get('confidence', 0):.2f}) "
          f"{primary_verdict.get('refined_anchor_label', '')[:50]}")

    if dry_run:
        return

    # Primary: textbook theme → theme_id; review L2 → INSTANTIATES only (no theme_id flip).
    if primary_layer == "textbook":
        set_primary_theme(conn, cid, primary_cand["id"])
        textbook_l1 = primary_cand["source_textbook_claim_id"]
        if textbook_l1:
            insert_instantiates_edge(conn, cid, textbook_l1,
                                     float(primary_verdict.get("confidence", 0.5)),
                                     primary_verdict.get("refined_anchor_label", primary_cand["label"]))
    else:
        insert_instantiates_edge(conn, cid, primary_cand["id"],
                                 float(primary_verdict.get("confidence", 0.5)),
                                 primary_verdict.get("refined_anchor_label", primary_cand["label"]))

    # Secondaries
    for layer_name, cand, v in yes_or_strong_maybe[1:]:
        target_id = cand["source_textbook_claim_id"] if layer_name == "textbook" else cand["id"]
        if not target_id:
            continue
        insert_instantiates_edge(conn, cid, target_id,
                                 float(v.get("confidence", 0.5)),
                                 v.get("refined_anchor_label", cand["label"]))

    mark_anchored(conn, cid)
    conn.commit()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--layer", choices=["textbook", "review", "both"], default="both")
    ap.add_argument("--level", type=int, default=3, help="Paper claim level to anchor (default 3 = atoms).")
    ap.add_argument("--top-k", type=int, default=8)
    ap.add_argument("--min-sim", type=float, default=0.45)
    ap.add_argument("--maybe-threshold", type=float, default=0.6)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False

    claims = fetch_paper_claims(conn, args.layer, args.level, args.limit)
    print(f"Anchoring {len(claims)} paper L{args.level} claims (layer={args.layer}).")

    for c in claims:
        try:
            anchor_one(conn, c, args.layer, args.top_k, args.min_sim,
                       args.maybe_threshold, args.dry_run)
        except Exception as e:
            print(f"[fatal] {c['id']}: {e}", file=sys.stderr)
            conn.rollback()

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Calibration sample (hand-label 10 anchors)**

Pick 10 paper L3 atoms manually and check what theme HNSW returns top-1 for each. If most top-1 candidates already have cosine ≥ 0.45 and pass eyeball "is-instance" check, the threshold is fine; otherwise tighten or loosen `--min-sim`.

```bash
cd /home/jeremy/epigraph
python3 scripts/anchor_papers_to_themes.py --layer textbook --limit 10 --dry-run
```

Expected: 10 lines mostly `[anchor]`, possibly some `[noshort]` (no candidate within threshold) or `[noanchor]` (candidates found but LLM said no). If most are `[noshort]`, lower `--min-sim` to 0.35 and re-try.

- [ ] **Step 3: Real run on 50 atoms for sanity**

```bash
cd /home/jeremy/epigraph
python3 scripts/anchor_papers_to_themes.py --layer textbook --limit 50
```

Expected: ~50 lines, mix of `[anchor]` and `[noanchor]/[noshort]`; SQL `SELECT COUNT(*) FROM edges WHERE relationship='INSTANTIATES'` shows nonzero count.

- [ ] **Step 4: Full textbook layer run**

```bash
cd /home/jeremy/epigraph
python3 scripts/anchor_papers_to_themes.py --layer textbook 2>&1 | tee /tmp/anchor-textbook.log | tail -20
```

Expected: ~2349 paper atoms processed; log captured to `/tmp/anchor-textbook.log`. Wall time ~30 min.

- [ ] **Step 5: Review-layer run (frontier papers only)**

```bash
cd /home/jeremy/epigraph
python3 scripts/anchor_papers_to_themes.py --layer review 2>&1 | tee /tmp/anchor-review.log | tail -20
```

Expected: only frontier-tagged paper claims processed; review L2 paragraphs as INSTANTIATES targets.

- [ ] **Step 6: Coverage report**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT properties->>'document_type' AS dt, \
          COUNT(*) FILTER (WHERE theme_id IS NOT NULL) AS with_theme, \
          COUNT(*) AS total \
   FROM claims c \
   WHERE c.is_current=true \
     AND c.properties->>'source_type'='Paper' \
     AND c.properties->>'level'='3' \
   GROUP BY c.properties->>'document_type';"

PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT COUNT(*) AS n_instantiates_edges FROM edges WHERE relationship='INSTANTIATES';"
```

Expected: anchor coverage ≥ 40% of paper atoms; nonzero INSTANTIATES edge count.

- [ ] **Step 7: Commit**

```bash
cd /home/jeremy/epigraph
git add scripts/anchor_papers_to_themes.py
git commit -m "scripts: anchor paper claims to textbook themes + review L2 bridges

HNSW shortlist over claim_themes.centroid (and review-paper L2 embeddings
for frontier papers) → claude is-instance-of judge → primary theme_id +
secondary INSTANTIATES edges.

Per spec 2026-05-18-cross-source-anchor §§Components 3 + 4."
```

---

## Task 8: Update nightly workflow steps

**Files:**
- Create: `scripts/update_theme_workflow_steps.py`

- [ ] **Step 1: Write the script**

Create `scripts/update_theme_workflow_steps.py`:

```python
#!/usr/bin/env python3
"""Update the stored 'Run k-means theme maintenance' workflow steps to reflect
the anchor-aware behaviour added by spec 2026-05-18-cross-source-anchor.

Calls mcp__epigraph__evolve_step (via the HTTP API) on the affected step
claims. Idempotent: skips steps whose current content already matches the
new content.

Affected step IDs (verified 2026-05-18):
  - 4d9bf697-e53c-57ac-ad92-526c8e86f06a  (old: "Run hypothesize() with cluster_count=8 ...")
  - 764aa179-2d19-5018-9581-573dbba2badc  (embedding_neighborhood_density step — keep as-is now that tool exists)
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg2

DEFAULT_DATABASE_URL = (
    "postgres://epigraph_admin:epigraph_admin@127.0.0.1:5432/epigraph"
)

UPDATES = {
    "4d9bf697-e53c-57ac-ad92-526c8e86f06a":
        "Run hypothesize(statement='knowledge graph claims themes topics research', "
        "cluster_count=8, search_radius=0.25) to diagnose dense embedding "
        "neighborhoods that lack textbook anchors. For each returned cluster "
        "without strong textbook coverage, surface as a candidate for new "
        "textbook ingest or a theme sub-split.",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    conn.autocommit = False
    cur = conn.cursor()

    for step_id, new_content in UPDATES.items():
        cur.execute("SELECT content FROM claims WHERE id = %s AND is_current = true", (step_id,))
        row = cur.fetchone()
        if not row:
            print(f"[skip] {step_id}: not found")
            continue
        current = row[0]
        if current.strip() == new_content.strip():
            print(f"[skip] {step_id}: already up to date")
            continue
        print(f"[update] {step_id}")
        if args.dry_run:
            continue
        # Mark current as superseded; insert new current with same lineage.
        # We don't have a Python evolve_step helper, so do it inline:
        cur.execute(
            "INSERT INTO claims (content, content_hash, agent_id, properties, supersedes, is_current) "
            "SELECT %s, decode(md5(%s), 'hex'), agent_id, properties, %s, true "
            "FROM claims WHERE id = %s RETURNING id",
            (new_content, new_content, step_id, step_id),
        )
        new_id = cur.fetchone()[0]
        cur.execute("UPDATE claims SET is_current = false WHERE id = %s", (step_id,))
        conn.commit()
        print(f"  -> {new_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Dry-run**

```bash
cd /home/jeremy/epigraph
python3 scripts/update_theme_workflow_steps.py --dry-run
```

Expected: `[update] 4d9bf697-...` (single line).

- [ ] **Step 3: Real run**

```bash
cd /home/jeremy/epigraph
python3 scripts/update_theme_workflow_steps.py
```

Expected: `[update] 4d9bf697-...` followed by `-> <new uuid>`.

- [ ] **Step 4: Commit**

```bash
cd /home/jeremy/epigraph
git add scripts/update_theme_workflow_steps.py
git commit -m "scripts: update nightly theme-maintenance workflow steps

Replaces the aspirational k-means-clustering step language with the
anchor-aware variant now that hypothesize(cluster_count=N) actually
clusters. Per spec 2026-05-18-cross-source-anchor §Component 6."
```

---

## Task 9: Bootstrap pipeline run and final verification

**Files:** none (operational).

- [ ] **Step 1: Pause the `theme_cluster_rebuild` cron**

The nightly k-means job would otherwise overwrite or duplicate the textbook-seeded themes. Locate the job registration:

```bash
grep -n "theme_cluster_rebuild" /home/jeremy/epigraph/crates/epigraph-jobs/src/lib.rs | head -5
```

Comment out the registration (or gate behind an env flag). Recompile and redeploy the job runner. Note this as a separate operational change — do not commit a code change here unless the env flag is the right long-term answer.

- [ ] **Step 2: Verify all components landed**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT 'paper L0 doc_type set' AS check, \
          COUNT(*) FILTER (WHERE properties ? 'document_type') AS n, \
          COUNT(*) AS total \
   FROM claims WHERE is_current=true \
     AND properties->>'source_type'='Paper' AND properties->>'level'='0';"

PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT 'textbook themes seeded' AS check, COUNT(*) AS n \
   FROM claim_themes WHERE properties ? 'source_textbook_claim_id';"

PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT 'auto themes remaining' AS check, COUNT(*) AS n \
   FROM claim_themes WHERE label LIKE 'auto-%';"

PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT 'paper atoms with theme' AS check, \
          COUNT(*) FILTER (WHERE theme_id IS NOT NULL) AS anchored, \
          COUNT(*) AS total \
   FROM claims WHERE is_current=true \
     AND properties->>'source_type'='Paper' AND properties->>'level'='3';"

PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "SELECT relationship, COUNT(*) FROM edges \
   WHERE relationship='INSTANTIATES' GROUP BY 1;"
```

Expected:
- Paper L0 doc_type set: 25 of 25
- Textbook themes seeded: ≥ 700 (target ~781)
- Auto themes remaining: 0
- Paper atoms with theme: ≥ 40 % of total
- INSTANTIATES edge count: ≥ 1000

- [ ] **Step 3: Smoke-test diverse search**

```bash
curl -s "http://127.0.0.1:8080/api/v1/search/semantic?diverse=true&max_themes=5" \
  -H "Content-Type: application/json" \
  -d '{"query": "Bernoulli equation streamline"}' | head -40
```

Expected: theme labels in the response include meaningful names like *"Bernoulli's Equation — Streamline Form"*, NOT `auto-08`.

- [ ] **Step 4: Smoke-test paper-paper bridge query**

Pick one paper atom UUID with a `theme_id` (e.g., from the SQL in Step 2). Run:

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph -c \
  "WITH seed AS (SELECT id, theme_id FROM claims WHERE id = '<paste-uuid>') \
   SELECT c2.id, c2.content \
   FROM claims c2 JOIN seed ON c2.theme_id = seed.theme_id \
   WHERE c2.id <> seed.id \
     AND c2.properties->>'source_type' = 'Paper' \
     AND c2.properties->>'level' = '3' \
   LIMIT 10;"
```

Expected: several paper atoms sharing the seed atom's textbook concept.

- [ ] **Step 5: Smoke-test bridge spine report**

```bash
cd /home/jeremy/epigraph
cargo run -p epigraph-cli --features db -- bridge sweep --dry-run --top-spine 5 2>&1 | tail -20
```

Expected: spine umbrella labels are concept names, not `auto-NN`.

- [ ] **Step 6: Final commit**

```bash
cd /home/jeremy/epigraph
git status
# If any final config/cron change was made:
git add <files>
git commit -m "ops: pause theme_cluster_rebuild cron post anchor bootstrap

Textbook-seeded themes are now the curated anchor layer. K-means rebuild
stays paused pending decision on its long-term role (per spec open
question 4)."
```

- [ ] **Step 7: Push the branch and open a draft PR**

```bash
cd /home/jeremy/epigraph
git push -u origin spec/cross-source-anchor
gh pr create --draft --title "Cross-source anchor: papers ↔ textbook concepts via theme layer" \
  --body "$(cat <<'EOF'
## Summary
- Restores `embedding_neighborhood_density` + extends `hypothesize` with `cluster_count` (the nightly workflow's missing tools).
- Seeds `claim_themes` from textbook L1 sections with LLM-emitted labels (replaces 16 abandoned `auto-NN` themes).
- Anchors paper L3 atoms to themes via HNSW + LLM judge; primary `theme_id`, secondary `INSTANTIATES` edges.
- Adds review/frontier paper classification + parallel anchor layer.
- Wires the nightly maintenance workflow to reference real tools.

## Test plan
- [ ] `cargo test --workspace --features db` green
- [ ] `embedding_neighborhood_density` returns sane stats on the production DB
- [ ] `hypothesize(cluster_count=2)` returns 2 clusters on a small fixture
- [ ] All 25 paper L0 rows have `properties.document_type` set
- [ ] ≥ 700 textbook-seeded themes; 0 `auto-NN` themes
- [ ] ≥ 40 % of paper L3 atoms have a `theme_id`
- [ ] Diverse search returns concept names instead of `auto-NN`
- [ ] Bridge spine report shows meaningful umbrella labels

Spec: docs/superpowers/specs/2026-05-18-cross-source-anchor-design.md
Plan: docs/superpowers/plans/2026-05-18-cross-source-anchor.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Coverage check

Spec sections → tasks:

| Spec section | Task |
|---|---|
| §State of the art | (informational; no task) |
| §Component 0a: `embedding_neighborhood_density` | Tasks 2 + 3 |
| §Component 0b: `hypothesize(cluster_count=N)` | Task 4 |
| §Component 1: paper doc-type classifier | Task 5 |
| §Component 2: textbook-seeded theme rebuild | Tasks 1 + 6 |
| §Component 3: paper-claim anchor pass | Task 7 |
| §Component 4: review-paper bridge layer | Task 7 (same script, `--layer review/both`) |
| §Component 5: paper-paper bridge query | Task 9 step 4 (query-time SQL; no new code) |
| §Component 6: wire nightly workflow | Task 8 |
| §Data model summary | Task 1 (migration) + Task 7 (edges) |
| §Pipeline | Task 9 (bootstrap) |
