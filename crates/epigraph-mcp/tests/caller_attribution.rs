//! Batch H-b review: MCP writes over the authenticated transport must not
//! attribute a row to an agent other than the caller.
//!
//! D1 made every write tool author its rows as the request's principal, but two
//! tools still took the attributed agent from a PARAMETER: `create_perspective`
//! (`owner_agent_id`, which also materialises a `PERSPECTIVE_OF` edge to it)
//! and `publish_event` (`actor_id`). Measured by the review on the real binary,
//! configs A and B: an OAuth caller wrote a perspective owned by, and an event
//! acted by, a FOREIGN agent. Over HTTP a different agent is now refused with
//! nothing written; stdio keeps the parameter as given.
//!
//! The decision is Rust-side, so this superuser harness observes it.
//! Load-bearing, verified by reverting: with `tools/perspectives.rs` at the
//! previous tip, `a_foreign_perspective_owner_is_refused_over_http` fails (the
//! perspective is written). `publish_event`'s signature changed to carry the
//! request's `auth`, so its revert is measured on the real binary instead
//! (`scripts/e2e/probe-batch-h.sh review_http`).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_caller};
use epigraph_mcp::tools;
use epigraph_mcp::types::{CreatePerspectiveParams, PublishEventParams};
use sqlx::PgPool;
use uuid::Uuid;

fn perspective(name: &str, owner: Option<Uuid>) -> CreatePerspectiveParams {
    CreatePerspectiveParams {
        name: name.to_string(),
        description: None,
        owner_agent_id: owner.map(|o| o.to_string()),
        perspective_type: None,
        frame_ids: None,
        extraction_method: None,
        confidence_calibration: None,
    }
}

async fn perspectives_named(pool: &PgPool, name: &str) -> Vec<Option<Uuid>> {
    sqlx::query_scalar("SELECT owner_agent_id FROM perspectives WHERE name = $1")
        .bind(name)
        .fetch_all(pool)
        .await
        .expect("perspectives")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_foreign_perspective_owner_is_refused_over_http(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let foreign = common::seed_agent(&pool).await;

    let err = tools::perspectives::create_perspective(
        &server,
        &viewer,
        perspective("forged owner", Some(foreign)),
        Some(&token),
    )
    .await
    .expect_err("an OAuth caller must not create a perspective owned by another agent");
    assert!(
        err.message.contains("is not the calling agent"),
        "{}",
        err.message
    );
    assert!(perspectives_named(&pool, "forged owner").await.is_empty());

    // Calibration: omitted, and named as itself, the caller owns it.
    tools::perspectives::create_perspective(
        &server,
        &viewer,
        perspective("default owner", None),
        Some(&token),
    )
    .await
    .expect("default owner");
    tools::perspectives::create_perspective(
        &server,
        &viewer,
        perspective("own owner", Some(caller)),
        Some(&token),
    )
    .await
    .expect("own owner");
    assert_eq!(
        perspectives_named(&pool, "default owner").await,
        vec![Some(caller)]
    );
    assert_eq!(
        perspectives_named(&pool, "own owner").await,
        vec![Some(caller)]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_perspective_owner_is_unchanged(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let other = common::seed_agent(&pool).await;
    tools::perspectives::create_perspective(
        &server,
        &viewer,
        perspective("stdio owner", Some(other)),
        None,
    )
    .await
    .expect("stdio keeps the parameter as given (the batch H-b bar)");
    assert_eq!(
        perspectives_named(&pool, "stdio owner").await,
        vec![Some(other)]
    );
}

async fn events_of(pool: &PgPool, event_type: &str) -> Vec<Option<Uuid>> {
    sqlx::query_scalar("SELECT actor_id FROM events WHERE event_type = $1")
        .bind(event_type)
        .fetch_all(pool)
        .await
        .expect("events")
}

fn event(event_type: &str, actor: Option<Uuid>) -> PublishEventParams {
    PublishEventParams {
        event_type: event_type.to_string(),
        actor_id: actor.map(|a| a.to_string()),
        payload: serde_json::json!({"probe": true}),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_foreign_event_actor_is_refused_over_http(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let foreign = common::seed_agent(&pool).await;

    let err = tools::events::publish_event(
        &server,
        &viewer,
        event("review.forged", Some(foreign)),
        Some(&token),
    )
    .await
    .expect_err("an OAuth caller must not record an event acted by another agent");
    assert!(
        err.message.contains("is not the calling agent"),
        "{}",
        err.message
    );
    assert!(events_of(&pool, "review.forged").await.is_empty());

    tools::events::publish_event(
        &server,
        &viewer,
        event("review.default", None),
        Some(&token),
    )
    .await
    .expect("an omitted actor defaults to the caller");
    assert_eq!(events_of(&pool, "review.default").await, vec![Some(caller)]);

    // stdio: recorded as given, as before.
    let public = fixture::public_viewer(&pool).await;
    tools::events::publish_event(&server, &public, event("review.stdio", Some(foreign)), None)
        .await
        .expect("stdio keeps the parameter");
    assert_eq!(events_of(&pool, "review.stdio").await, vec![Some(foreign)]);
}
