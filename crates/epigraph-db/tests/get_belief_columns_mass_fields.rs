//! Integration tests for `ClaimRepository::get_belief_columns` reading the
//! `mass_on_empty` / `mass_on_missing` columns in addition to the existing
//! `belief` / `plausibility` / `pignistic_prob` trio, so a caller can fully
//! reconstruct a claim's cached Dempster-Shafer interval
//! (mass_on_conflict == mass_on_empty, mass_on_missing).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_db::ClaimRepository;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
    Some(pool)
}

macro_rules! test_pool_or_skip {
    () => {{
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
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

fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

#[tokio::test]
async fn get_belief_columns_includes_mass_on_empty_and_missing() {
    let pool = test_pool_or_skip!();
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("belief mass fields {}", Uuid::new_v4()), agent_id);
    let created = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create");

    let claim_id: Uuid = created.id.into();
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4, \
         mass_on_empty = $5, mass_on_missing = $6 WHERE id = $1",
    )
    .bind(claim_id)
    .bind(0.4_f64)
    .bind(0.7_f64)
    .bind(0.55_f64)
    .bind(0.1_f64)
    .bind(0.05_f64)
    .execute(&pool)
    .await
    .expect("update ds columns");

    let cols = ClaimRepository::get_belief_columns(
        &pool,
        &fixture::public_viewer(&pool).await,
        created.id,
    )
    .await
    .expect("get_belief_columns call")
    .expect("row should exist");

    assert_eq!(cols.belief, Some(0.4));
    assert_eq!(cols.plausibility, Some(0.7));
    assert_eq!(cols.pignistic_prob, Some(0.55));
    assert_eq!(cols.mass_on_empty, Some(0.1));
    assert_eq!(cols.mass_on_missing, Some(0.05));
}

#[tokio::test]
async fn get_belief_columns_mass_fields_default_to_zero_on_fresh_claim() {
    let pool = test_pool_or_skip!();
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(
        &format!("belief mass fields default {}", Uuid::new_v4()),
        agent_id,
    );
    let created = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create");

    let cols = ClaimRepository::get_belief_columns(
        &pool,
        &fixture::public_viewer(&pool).await,
        created.id,
    )
    .await
    .expect("get_belief_columns call")
    .expect("row should exist");

    // belief/plausibility/pignistic_prob are NULL until a BBA is combined;
    // mass_on_empty/mass_on_missing default to 0.0 per the schema.
    assert_eq!(cols.belief, None);
    assert_eq!(cols.plausibility, None);
    assert_eq!(cols.pignistic_prob, None);
    assert_eq!(cols.mass_on_empty, Some(0.0));
    assert_eq!(cols.mass_on_missing, Some(0.0));
}
