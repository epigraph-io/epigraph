//! `GET /api/v1/sheaf/consistency` scores the same neighbourhood the MCP
//! `check_sheaf_consistency` does (drain U030 PR 2): direction-aware,
//! case-insensitive on the relationship, and honouring `profile`. The MCP
//! twin (`crates/epigraph-mcp/tests/check_sheaf_consistency_neighbourhood.rs`)
//! covers truncation and retraction through the shared repo query; this file
//! pins that the HTTP consumer is rewired too, since the two handlers are
//! separate code.
//!
//! The query is decoded from JSON so the test compiles against a
//! `SheafConsistencyQuery` without a `profile` field (serde ignores it there).

#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::{Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::computation::{sheaf_consistency, SheafConsistencyQuery};
use epigraph_api::state::{ApiConfig, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{downgraded_pool, public_viewer, scoped_pool};

async fn state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(
        downgraded_pool(pool, "epigraph_app").await,
        ApiConfig::default(),
    );
    state.scoped = Some(scoped_pool(pool).await);
    state
}

async fn agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at) \
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

/// A public, current claim with belief interval [bel, pl] and BetP its midpoint.
async fn claim(pool: &PgPool, bel: f64, pl: f64) -> Uuid {
    let author = agent(pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, \
                             belief, plausibility, pignistic_prob, is_current) \
         VALUES ($1, $2, sha256($2::bytea), $3, 0.5, $4, $5, $6, true)",
    )
    .bind(id)
    .bind(format!("u030 api sheaf probe {id}"))
    .bind(author)
    .bind(bel)
    .bind(pl)
    .bind((bel + pl) / 2.0)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("edge");
}

async fn sections(pool: &PgPool, query: Value) -> Vec<Value> {
    let q: SheafConsistencyQuery = serde_json::from_value(query).expect("query decodes");
    let body = sheaf_consistency(
        ViewerExtractor(public_viewer(pool).await),
        State(state(pool).await),
        Query(q),
    )
    .await
    .expect("sheaf_consistency serves")
    .0;
    body["sections"].as_array().expect("sections").clone()
}

fn section_of(sections: &[Value], id: Uuid) -> Option<&Value> {
    sections.iter().find(|s| s["node_id"] == json!(id))
}

fn radius(s: &Value) -> f64 {
    s["consistency_radius"].as_f64().expect("radius")
}

/// A weak claim `SUPPORTS` a strong one (UPPER-case, as most prod edges are).
/// The target is consistent (0.8*0.1 below its Bel 0.9) and so is the
/// supporter, which a supports edge does not constrain. On the old handler the
/// UPPER-case edge was invisible, and with `supports` the supporter was
/// flagged at 0.62.
#[sqlx::test(migrations = "../../migrations")]
async fn the_http_handler_is_direction_aware_and_case_insensitive(pool: PgPool) {
    let weak = claim(&pool, 0.1, 0.2).await;
    let strong = claim(&pool, 0.9, 0.9).await;
    edge(&pool, weak, strong, "SUPPORTS").await;
    // and a second, lower-case pair where the weak claim is the TARGET
    let weak_target = claim(&pool, 0.1, 0.2).await;
    edge(&pool, strong, weak_target, "Supports").await;

    let all = sections(&pool, json!({"min_radius": 0.0, "limit": 200})).await;

    let s = section_of(&all, weak).expect("the SUPPORTS source must be scanned");
    assert!(
        radius(s) < 1e-9,
        "a supporter is not constrained by its target, got {}",
        radius(s)
    );
    assert_eq!(
        s["neighbor_count"], 0,
        "its outgoing supports row is skipped"
    );

    let t = section_of(&all, weak_target).expect("the mixed-case edge must reach the scan");
    assert!(
        (radius(t) - 0.62).abs() < 1e-9,
        "the weak TARGET of a Bel-0.9 supporter is under-supported: 0.8*0.9 - 0.1 = 0.62, got {}",
        radius(t)
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_http_handler_honours_the_regulatory_profile(pool: PgPool) {
    let weak = claim(&pool, 0.1, 0.2).await;
    let strong = claim(&pool, 0.9, 0.9).await;
    edge(&pool, strong, weak, "supports").await;

    let sci = sections(&pool, json!({"min_radius": 0.0, "limit": 200})).await;
    let reg = sections(
        &pool,
        json!({"min_radius": 0.0, "limit": 200, "profile": "regulatory"}),
    )
    .await;

    let r_sci = radius(section_of(&sci, weak).expect("scientific"));
    let r_reg = radius(section_of(&reg, weak).expect("regulatory"));
    assert!((r_sci - 0.62).abs() < 1e-9, "scientific 0.62, got {r_sci}");
    assert!(
        (r_reg - 0.755).abs() < 1e-9,
        "regulatory 0.95*0.9 - 0.1 = 0.755, got {r_reg}"
    );
}
