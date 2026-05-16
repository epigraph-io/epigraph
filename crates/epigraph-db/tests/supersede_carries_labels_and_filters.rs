//! Regression for two compounding bugs in supersede ↔ find_workflow.
//!
//! Filed 2026-05-16 after `supersede_claim` on workflow claims
//! (a04928e5, 500003fd, 2f76fdc8) left `find_workflow` returning the
//! pre-supersede step lists indefinitely:
//!
//! 1. `search_by_label_and_text` did not filter `is_current`, so the demoted
//!    old claim kept winning the workflow ILIKE fallback. (`supersedes` is
//!    the new claim's lineage pointer, not an exclusion predicate.)
//! 2. `ClaimRepository::supersede` did not copy `labels` to the new claim,
//!    so even if (1) had filtered, the replacement was invisible to
//!    `labels @> ['workflow']`. Only labels are carried — properties are
//!    intentionally NOT copied so a supersession can legitimately fix a
//!    bug that lived in `properties` without re-introducing it.
//!
//! These tests pin both behaviors together: after supersede, the new claim
//! must carry the old labels AND it must be the only one returned by the
//! workflow label search.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_workflow_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, \
                             labels, properties, is_current) \
         VALUES ($1, $2, $3, $4, 0.8, ARRAY['workflow']::text[], \
                 jsonb_build_object('canonical_name', 'test-wf'), true)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn labels_of(pool: &PgPool, claim_id: Uuid) -> Vec<String> {
    let row: (Vec<String>,) =
        sqlx::query_as("SELECT COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .unwrap();
    row.0
}

async fn properties_of(pool: &PgPool, claim_id: Uuid) -> serde_json::Value {
    let row: (serde_json::Value,) =
        sqlx::query_as("SELECT COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .unwrap();
    row.0
}

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_carries_labels_but_not_properties_to_new_claim(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let v1 = seed_workflow_claim(&pool, agent, r#"{"goal":"old goal","steps":["a"]}"#).await;

    let (v2, _old) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(v1),
        r#"{"goal":"new goal","steps":["b"]}"#,
        TruthValue::clamped(0.85),
        "test supersede",
    )
    .await
    .unwrap();

    let new_labels = labels_of(&pool, v2).await;
    assert!(
        new_labels.contains(&"workflow".to_string()),
        "new claim must inherit the 'workflow' label; got {new_labels:?}"
    );

    // Properties are intentionally NOT carried — a supersession that fixes
    // something in `properties` would otherwise re-introduce the bug.
    let new_props = properties_of(&pool, v2).await;
    assert!(
        new_props.get("canonical_name").is_none(),
        "new claim must NOT inherit old properties (caller's job to set fresh ones); got {new_props}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn search_by_label_and_text_excludes_superseded_returns_replacement(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let v1 = seed_workflow_claim(
        &pool,
        agent,
        r#"{"goal":"deploy widget","steps":["legacy step calling /api/v1/old"]}"#,
    )
    .await;

    let (v2, _) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(v1),
        r#"{"goal":"deploy widget","steps":["mcp-only step"]}"#,
        TruthValue::clamped(0.85),
        "MCP migration",
    )
    .await
    .unwrap();

    let hits = ClaimRepository::search_by_label_and_text(
        &pool,
        &["workflow".to_string()],
        "deploy widget",
        0.0,
        10,
    )
    .await
    .unwrap();

    let hit_ids: Vec<Uuid> = hits.iter().map(|c| c.id.as_uuid()).collect();
    assert!(
        !hit_ids.contains(&v1),
        "search must NOT return the superseded v1 ({v1}); returned {hit_ids:?}"
    );
    assert!(
        hit_ids.contains(&v2),
        "search MUST return the replacement v2 ({v2}); returned {hit_ids:?}"
    );
}
