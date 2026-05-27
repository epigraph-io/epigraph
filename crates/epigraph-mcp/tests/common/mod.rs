//! Shared test helpers for epigraph-mcp integration tests. Mirrors
//! crates/epigraph-db/tests/claim_repo_helpers.rs — same try_test_pool,
//! pre-107/post-107 fixture toggling, agent insert, claim builder.

#![allow(dead_code)]

use epigraph_core::{AgentId, Claim, TruthValue};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
    Some(pool)
}

#[macro_export]
macro_rules! test_pool_or_skip {
    () => {{
        match $crate::common::try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

/// Drop the (content_hash, agent_id) UNIQUE constraint to exercise the
/// pre-107 fixture path.
pub async fn drop_unique_constraint(pool: &PgPool) {
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent")
        .execute(pool)
        .await
        .expect("drop constraint");
}

/// Add the (content_hash, agent_id) UNIQUE constraint, deduping any
/// existing duplicate rows first. Postgres has no `ADD CONSTRAINT IF NOT
/// EXISTS`, so the DO block swallows duplicate_object.
pub async fn add_unique_constraint(pool: &PgPool) {
    sqlx::query(
        "DELETE FROM claims a USING claims b
         WHERE a.ctid > b.ctid
           AND a.content_hash = b.content_hash
           AND a.agent_id = b.agent_id",
    )
    .execute(pool)
    .await
    .expect("dedup before constraint");

    sqlx::query(
        r#"DO $$ BEGIN
              ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent
                  UNIQUE (content_hash, agent_id);
           EXCEPTION WHEN duplicate_object THEN NULL;
           END $$"#,
    )
    .execute(pool)
    .await
    .expect("add constraint");
}

pub async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
}

pub fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

// ── Additional helpers for workflow/claim/edge seeding and MCP server ────────

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::EpiGraphMcpFull;
use rmcp::model::CallToolResult;
use serde_json::Value;

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
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
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
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(truth)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Seed a claim with explicit DST belief-measure fields.
///
/// Used by `update_with_evidence_plausibility_one.rs` (issue #139 regression):
/// the test needs to plant a claim at `plausibility = 1.0` so that any
/// post-evidence drift above 1.0 trips `claims_plausibility_bounds`. The
/// standard `seed_claim` helper leaves these columns at their defaults.
///
/// Returns the new claim's UUID. Reuses `seed_agent`'s test-signer pattern.
pub async fn seed_claim_with_belief(
    pool: &PgPool,
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
) -> Uuid {
    let agent_id = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims \
            (id, content, content_hash, agent_id, truth_value, \
             belief, plausibility, pignistic_prob, is_current, labels) \
         VALUES ($1, $2, $3, $4, 0.5, $5, $6, $7, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(format!("seed_claim_with_belief regression {id}"))
    .bind(&hash)
    .bind(agent_id)
    .bind(belief)
    .bind(plausibility)
    .bind(pignistic_prob)
    .execute(pool)
    .await
    .expect("seed claim with belief");
    id
}

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
    .bind(id)
    .bind(&content)
    .bind(&hash)
    .bind(agent)
    .bind(&props)
    .execute(pool)
    .await
    .expect("seed workflow claim");
    id
}

pub async fn insert_claim_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
}

pub fn first_text(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("at least one text content block");
    serde_json::from_str(&text).expect("valid JSON")
}

pub fn parse_uuid_field(json: &Value, key: &str) -> Uuid {
    json.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing field {key} in {json}"))
        .parse()
        .expect("valid UUID")
}
