//! The library-level `recall` audits too (backlog 8cbffa0e / design F5).
//!
//! This is the THIRD retrieval surface — episcience synthesis calls it
//! directly, not over MCP. Since backlog 41841f7b the row is owned by the
//! principal the caller's viewer names (see `recall_audit_app_role.rs`, which
//! drives that path as `epigraph_app`). These two pin the edges around it, on
//! the superuser harness pool:
//!
//! * a `Bypass` viewer has no principal, so its row is agent-less and
//!   instance-wide — the one agent-less row the path writes;
//! * a principal that holds no personal group cannot own a row, so the row is
//!   DROPPED rather than widened to instance-wide.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_claim(pool: &PgPool, content: &str) {
    let agent = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-engine-audit', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool).await.expect("seed agent");

    sqlx::query(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.8, $2, true)",
    )
    .bind(content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_bypass_recall_writes_an_agentless_audit_row(pool: PgPool) {
    let (scoped, viewer) = fixture::bypass(&pool).await;
    assert!(viewer.principal().is_none(), "precondition: no principal");
    seed_claim(&pool, "grendlewick synthesis seed").await;

    let provider = MockProvider::new(EmbeddingConfig::local(64));
    let results =
        epigraph_engine::recall::recall(&pool, &scoped, &viewer, &provider, "grendlewick", 10, 0.0)
            .await
            .expect("engine recall ok");

    let row = sqlx::query!(
        "SELECT tool, agent_id, query_text, returned_claim_ids FROM recall_events
         ORDER BY created_at DESC LIMIT 1"
    )
    .fetch_optional(&pool)
    .await
    .unwrap()
    .expect("the library path must write an audit row, not silently skip auditing");

    assert_eq!(
        row.tool, "engine::recall",
        "attributed to the library surface"
    );
    assert!(
        row.agent_id.is_none(),
        "a bypass viewer names no principal => NULL agent_id"
    );
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT owner_group_id FROM recall_events WHERE query_text = 'grendlewick'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        owner,
        Some(fixture::world_group(&pool).await),
        "agent-less => instance-wide"
    );
    assert_eq!(row.query_text, "grendlewick");
    assert_eq!(
        row.returned_claim_ids.len(),
        results.len(),
        "the row records exactly what the caller received"
    );
}

/// `fixture::public_viewer` is the NIL principal: a scoped viewer with no
/// personal group. Nothing can own its row, so nothing is written — and in
/// particular the row is not widened to instance-wide, where every
/// authenticated agent could read its query text.
#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_without_a_personal_group_writes_no_audit_row(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    assert!(
        viewer.principal().is_some(),
        "precondition: a scoped viewer"
    );
    let scoped = fixture::scoped_pool(&pool).await;
    seed_claim(&pool, "brindlequay synthesis seed").await;

    let provider = MockProvider::new(EmbeddingConfig::local(64));
    epigraph_engine::recall::recall(&pool, &scoped, &viewer, &provider, "brindlequay", 10, 0.0)
        .await
        .expect("the recall itself is served");

    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM recall_events WHERE query_text = 'brindlequay'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        n, 0,
        "no owner => the row is dropped, never written agent-less or instance-wide"
    );

    // The drop must be the DESIGNED one (no owner), not a write that failed
    // for some other reason and happened to leave the count at zero.
    assert!(
        logs_contain("engine recall audit skipped rather than widened"),
        "the row must be dropped as owner-less"
    );
    assert!(
        !logs_contain("engine recall audit log failed"),
        "no write was attempted, so none can have failed"
    );
}

/// A principal whose personal membership is REVOKED cannot own a row either.
///
/// On this superuser pool the personal group row is visible whether or not
/// the membership is live, so "visible" alone would own the row by the group
/// the principal lost. The second check, against the viewer's live group set,
/// is what drops it.
#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_personal_membership_writes_no_audit_row(pool: PgPool) {
    let (principal, group) = fixture::seed_agent_with_group(&pool, "engine-audit-revoked").await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(principal)
    .execute(&pool)
    .await
    .expect("revoke the personal membership");
    let viewer = epigraph_db::Viewer::resolve(&pool, principal)
        .await
        .expect("resolve");
    assert!(
        !viewer.group_bind().unwrap_or(&[]).contains(&group),
        "precondition: the revoked group is not in the live set"
    );
    let scoped = fixture::scoped_pool(&pool).await;
    seed_claim(&pool, "quillmarrow synthesis seed").await;

    let provider = MockProvider::new(EmbeddingConfig::local(64));
    epigraph_engine::recall::recall(&pool, &scoped, &viewer, &provider, "quillmarrow", 10, 0.0)
        .await
        .expect("the recall itself is served");

    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM recall_events WHERE query_text = 'quillmarrow'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        n, 0,
        "a revoked principal's row must not be owned by the group it was revoked from"
    );

    // The drop must be the DESIGNED one (no owner), not a write that failed
    // for some other reason and happened to leave the count at zero.
    assert!(
        logs_contain("engine recall audit skipped rather than widened"),
        "the row must be dropped as owner-less"
    );
    assert!(
        !logs_contain("engine recall audit log failed"),
        "no write was attempted, so none can have failed"
    );
}
