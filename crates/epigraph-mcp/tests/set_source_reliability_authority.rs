//! Batch H-b review (authority-attack, low): `set_source_reliability` reported
//! `status: set` over zero changed rows, and checked no ownership.
//!
//! Measured on config A through the real binary: `OK` with nothing stored for a
//! group-private foreign perspective and for a random uuid. The tool now runs on
//! a stamped transaction, reads the perspective through the caller's viewer,
//! requires its owner (or the owner's operator, or `claims:admin`) over HTTP,
//! and refuses a write that changed no row.
//!
//! The ownership and not-found decisions are Rust-side, so this superuser
//! harness observes them; the RLS half (a row the stamp cannot write) is the
//! e2e's (`scripts/e2e/probe-batch-h.sh review_http`). The tool's signature
//! gained the request's viewer and `auth`, so the revert is measured there too,
//! with the previous tip's binary.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use std::collections::HashMap;

use common::{build_scoped_test_server, seed_caller};
use epigraph_mcp::tools;
use epigraph_mcp::types::SetSourceReliabilityParams;
use sqlx::PgPool;
use uuid::Uuid;

fn params(id: Uuid) -> SetSourceReliabilityParams {
    SetSourceReliabilityParams {
        perspective_id: id.to_string(),
        source_reliability: HashMap::from([("western_clinical".to_string(), 0.4)]),
    }
}

async fn stored(pool: &PgPool, id: Uuid) -> Option<serde_json::Value> {
    sqlx::query_scalar("SELECT properties->'source_reliability' FROM perspectives WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("read perspective")
        .flatten()
}

async fn perspective_owned_by(pool: &PgPool, owner: Uuid, name: &str) -> Uuid {
    epigraph_db::PerspectiveRepository::create(
        pool,
        name,
        None,
        Some(owner),
        Some("analytical"),
        &[],
        Some("ai_generated"),
        Some(0.5),
    )
    .await
    .expect("seed perspective")
    .id
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_perspective_is_not_found_rather_than_set(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_caller, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let err = tools::perspectives::set_source_reliability(
        &server,
        &viewer,
        params(Uuid::new_v4()),
        Some(&token),
    )
    .await
    .expect_err("a random uuid must not report success");
    assert!(err.message.contains("not found"), "{}", err.message);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_foreign_perspective_is_refused_over_http_and_the_owner_writes(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let id = perspective_owned_by(&pool, owner, "the owner's lens").await;

    let err = tools::perspectives::set_source_reliability(
        &server,
        &stranger_viewer,
        params(id),
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not set another agent's lens");
    assert!(err.message.contains("is owned by agent"), "{}", err.message);
    assert_eq!(stored(&pool, id).await, None, "nothing written");

    tools::perspectives::set_source_reliability(
        &server,
        &owner_viewer,
        params(id),
        Some(&owner_token),
    )
    .await
    .expect("the owner sets its own lens");
    assert_eq!(
        stored(&pool, id).await,
        Some(serde_json::json!({"western_clinical": 0.4}))
    );
}
