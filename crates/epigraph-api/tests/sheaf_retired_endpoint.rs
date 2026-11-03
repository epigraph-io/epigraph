//! `GET /api/v1/sheaf/cohomology`, `GET /api/v1/sheaf/consistency` and
//! `POST /api/v1/sheaf/reconcile` must stop reporting an edge once one of its
//! endpoints is retired (`is_current = false`), per DD-20 (backlog 174ffd23).
//! The MCP twin is `crates/epigraph-mcp/tests/sheaf_retired_endpoint.rs`; the
//! handlers here are separate code over the same repo queries.
//!
//! Numbers (scientific profile, contradicts 0.9): a contradictor at Bel 0.9
//! caps its target's Pl at 0.19, so a target at Bel 0.8 exceeds it by 0.61.

#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::{Json, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::computation::{
    sheaf_cohomology, sheaf_consistency, sheaf_reconcile, ReconcileRequest, SheafCohomologyQuery,
    SheafConsistencyQuery,
};
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
    .bind(format!("174ffd23 api sheaf probe {id}"))
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

async fn retire(pool: &PgPool, id: Uuid) {
    let n = sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("retire")
        .rows_affected();
    assert_eq!(n, 1, "retired exactly the seeded claim");
}

struct Seed {
    ctl_src: Uuid,
    ctl_tgt: Uuid,
    contester: Uuid,
    retired: Uuid,
}

async fn seed(pool: &PgPool) -> Seed {
    let ctl_src = claim(pool, 0.9, 0.9).await;
    let ctl_tgt = claim(pool, 0.8, 0.9).await;
    edge(pool, ctl_src, ctl_tgt, "contradicts").await;
    let contester = claim(pool, 0.9, 0.9).await;
    let retired = claim(pool, 0.8, 0.9).await;
    edge(pool, contester, retired, "CONTRADICTS").await;
    Seed {
        ctl_src,
        ctl_tgt,
        contester,
        retired,
    }
}

async fn cohomology(pool: &PgPool) -> Value {
    let q: SheafCohomologyQuery =
        serde_json::from_value(json!({"threshold": 0.05})).expect("query decodes");
    sheaf_cohomology(
        ViewerExtractor(public_viewer(pool).await),
        State(state(pool).await),
        Query(q),
    )
    .await
    .expect("sheaf_cohomology serves")
    .0
}

fn has_obstruction(body: &Value, source: Uuid, target: Uuid) -> bool {
    body["obstructions"]
        .as_array()
        .expect("obstructions")
        .iter()
        .any(|o| o["source_id"] == json!(source) && o["target_id"] == json!(target))
}

#[sqlx::test(migrations = "../../migrations")]
async fn http_cohomology_drops_the_obstruction_of_a_retired_endpoint(pool: PgPool) {
    let s = seed(&pool).await;

    let before = cohomology(&pool).await;
    assert!(
        has_obstruction(&before, s.ctl_src, s.ctl_tgt)
            && has_obstruction(&before, s.contester, s.retired),
        "precondition: both pairs are obstructions while current; got {before}"
    );

    retire(&pool, s.retired).await;
    let after = cohomology(&pool).await;
    assert!(
        has_obstruction(&after, s.ctl_src, s.ctl_tgt),
        "control: the current pair is still an obstruction; got {after}"
    );
    assert!(
        !has_obstruction(&after, s.contester, s.retired),
        "an edge to a retired claim must not be reported as an obstruction"
    );
    assert_eq!(
        after["obstruction_count"].as_u64().expect("count"),
        before["obstruction_count"].as_u64().expect("count") - 1,
        "obstruction_count must drop by exactly the retired pair"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn http_consistency_has_no_section_for_a_retired_endpoint(pool: PgPool) {
    let s = seed(&pool).await;
    retire(&pool, s.retired).await;

    let q: SheafConsistencyQuery =
        serde_json::from_value(json!({"min_radius": 0.0, "limit": 200})).expect("query decodes");
    let body = sheaf_consistency(
        ViewerExtractor(public_viewer(&pool).await),
        State(state(&pool).await),
        Query(q),
    )
    .await
    .expect("sheaf_consistency serves")
    .0;
    let nodes: Vec<Value> = body["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .map(|sec| sec["node_id"].clone())
        .collect();

    assert!(
        nodes.contains(&json!(s.ctl_tgt)),
        "control: the current pair has a section; got {nodes:?}"
    );
    assert!(
        !nodes.contains(&json!(s.retired)),
        "a retired claim must not get a consistency section; got {nodes:?}"
    );
    assert!(
        !nodes.contains(&json!(s.contester)),
        "a current claim whose only neighbour is retired has no neighbourhood; got {nodes:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn http_reconcile_does_not_reconcile_a_retired_endpoint(pool: PgPool) {
    let s = seed(&pool).await;
    retire(&pool, s.retired).await;

    let req: ReconcileRequest =
        serde_json::from_value(json!({"min_inconsistency": 0.15})).expect("request decodes");
    let body = sheaf_reconcile(
        ViewerExtractor(public_viewer(&pool).await),
        State(state(&pool).await),
        Json(req),
    )
    .await
    .expect("sheaf_reconcile serves")
    .0;
    let updated: Vec<Value> = body["updated_intervals"]
        .as_array()
        .expect("updated_intervals")
        .iter()
        .map(|u| u["node_id"].clone())
        .collect();

    assert!(
        updated.contains(&json!(s.ctl_tgt)) || updated.contains(&json!(s.ctl_src)),
        "control: the current contradicts pair is reconciled; got {updated:?}"
    );
    for id in [s.retired, s.contester] {
        assert!(
            !updated.contains(&json!(id)),
            "{id} is constrained only by an edge to a retired claim and must not be \
             reconciled; got {updated:?}"
        );
    }
}
