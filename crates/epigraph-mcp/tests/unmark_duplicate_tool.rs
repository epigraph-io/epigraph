//! The `unmark_duplicate` tool: the reverse of `mark_duplicate`.
//!
//! With the server's administrative connection, a mark followed by an un-mark
//! puts the duplicate back (current, its edges re-pointed back onto it) and
//! answers with counts only. Without it, the un-mark is refused before
//! anything is written: unlike the mark's cascade, it cannot be deferred.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_claim};
use epigraph_mcp::tools::supersede::{mark_duplicate, unmark_duplicate};
use epigraph_mcp::types::{MarkDuplicateParams, UnmarkDuplicateParams};
use sqlx::PgPool;
use uuid::Uuid;

fn body(r: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &r
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(text).expect("json body")
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("edge")
}

async fn state(pool: &PgPool, dup: Uuid) -> (Option<Uuid>, bool, i64) {
    let (sup, cur): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(pool)
            .await
            .expect("dup");
    let in_force: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'same_as' \
            AND valid_to IS NULL",
    )
    .bind(dup)
    .fetch_one(pool)
    .await
    .expect("identity edges");
    (sup, cur, in_force)
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_then_unmark_through_the_tools_restores_the_duplicate(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    let supporter = seed_claim(&pool, "supporter", 0.5).await;
    let e = edge(&pool, supporter, dup).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let marked = mark_duplicate(
        &server,
        &viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: Some("an index family restatement".to_string()),
        },
        Some(&auth),
    )
    .await
    .expect("mark");
    assert_eq!(body(&marked)["cascade"]["status"], "applied");
    assert_eq!(state(&pool, dup).await, (Some(canonical), false, 1));
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(
        target, canonical,
        "calibration: the mark re-pointed the edge"
    );

    let r = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("unmark");
    let b = body(&r);
    assert_eq!(b["mode"], "unmark_duplicate", "{b}");
    assert_eq!(b["canonical_id"], serde_json::json!(canonical), "{b}");
    assert_eq!(b["cascade"]["status"], "applied", "{b}");
    assert_eq!(b["cascade"]["touched"]["edges_retargeted_back"], 1, "{b}");
    assert!(
        !b.to_string().contains(&e.to_string()),
        "the caller's copy carries counts, not other writers' row ids: {b}"
    );
    assert_eq!(state(&pool, dup).await, (None, true, 0));
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, dup, "the edge is back on the duplicate");
}

#[sqlx::test(migrations = "../../migrations")]
async fn unmark_without_the_administrative_connection_writes_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;
    let marked = mark_duplicate(
        &server,
        &viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&auth),
    )
    .await
    .expect("mark");
    assert_eq!(body(&marked)["cascade"]["status"], "deferred");
    let events_before: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");

    let err = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect_err("refused without the administrative connection");
    assert!(
        err.message.contains("administrative") && err.message.contains("nothing was written"),
        "{}",
        err.message
    );
    assert_eq!(
        state(&pool, dup).await,
        (Some(canonical), false, 1),
        "nothing changed"
    );
    let events_after: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(events_after, events_before, "no audit row either");
}
