//! The library `recall` writes its audit row AS THE APPLICATION ROLE
//! (backlog 41841f7b).
//!
//! `recall_audit_test.rs` runs on the `#[sqlx::test]` superuser pool, where no
//! row policy applies, so it could never see what production sees: on an
//! `epigraph_app` connection `recall_events_tenancy`'s WITH CHECK admits a row
//! only when `epigraph_principal_id() IS NOT NULL AND agent_id =
//! epigraph_principal_id()`. An agent-less row on an unstamped connection fails
//! that structurally, and the episcience worker logged
//! `new row violates row-level security policy for table "recall_events"` on
//! every synthesis: zero audit rows where one per synthesis is expected.
//!
//! Every connection here is `epigraph_app` without bypass: the engine reads on
//! an unstamped app pool (the worker's engine pool), and the audit write goes
//! through a `ScopedPool` downgraded to the same role.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider, EmbeddingService};
use sqlx::PgPool;

#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn a_worker_recall_as_epigraph_app_writes_exactly_one_audit_row(pool: PgPool) {
    // Seed on the SUPERUSER pool; the viewer is resolved below on the app
    // pool, as the worker resolves it.
    let (principal, personal_group) =
        fixture::seed_agent_with_group(&pool, "engine-audit-app-role").await;
    // A semantic hit, as in production: the deterministic mock embeds the query
    // to a fixed vector, and the seed claim carries exactly that vector.
    let provider = MockProvider::new(EmbeddingConfig::openai(1536));
    let qvec = provider
        .generate_query("vorpaline")
        .await
        .expect("mock embed");
    let pgvec = format!(
        "[{}]",
        qvec.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    let seed = fixture::seed_public_claim(&pool, principal, "vorpaline synthesis seed").await;
    fixture::set_claim_embedding(&pool, seed, &pgvec).await;

    // The worker's shape: a ScopedPool on the application role, and the engine
    // reading on its UNSTAMPED inner pool.
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(&pool).await,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let app = scoped.inner();
    let role: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(app)
        .await
        .unwrap();
    assert_eq!(
        role, "epigraph_app",
        "precondition: the engine pool is the app role"
    );

    // The worker resolves its viewer on its unstamped app-role pool too
    // (episcience `jobs/worker.rs`: `Viewer::resolve(&self.resolve_pool, ..)`),
    // and the audit write's liveness check reads that viewer's group set. A
    // resolve that came back without the personal group would DROP every row
    // with "audit skipped" — the original zero-rows symptom by another road —
    // so resolve where the worker does and pin the group set first.
    let viewer = epigraph_db::Viewer::resolve(app, principal)
        .await
        .expect("resolve the synthesis principal on the app pool");
    assert!(
        viewer
            .group_bind()
            .is_some_and(|groups| groups.contains(&personal_group)),
        "precondition: an app-role resolve sees the principal's live personal group \
         (epigraph_live_memberships is a definer); got {:?}",
        viewer.group_bind()
    );

    let results =
        epigraph_engine::recall::recall(app, &scoped, &viewer, &provider, "vorpaline", 10, 0.0)
            .await
            .expect("engine recall ok");
    assert_eq!(
        results.len(),
        1,
        "precondition: the public seed is found through the app pool"
    );

    let rows: Vec<(Option<uuid::Uuid>, Option<uuid::Uuid>, String, String)> = sqlx::query_as(
        "SELECT agent_id, owner_group_id, visibility, tool FROM recall_events \
         WHERE query_text = 'vorpaline'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "every recall the engine performs is audited: exactly one recall_events row \
         per worker recall, written as epigraph_app"
    );
    let (agent_id, owner_group_id, visibility, tool) = &rows[0];
    assert_eq!(tool, "engine::recall");
    assert_eq!(
        *agent_id,
        Some(principal),
        "the row records the principal the recall ran as"
    );
    assert_eq!(
        *owner_group_id,
        Some(personal_group),
        "owned by that principal's personal group"
    );
    assert_eq!(
        visibility, "group",
        "group-visible, so only its author reads it back"
    );
    assert!(
        !logs_contain("engine recall audit log failed"),
        "the audit write must not have been refused"
    );
    assert!(
        !logs_contain("engine recall audit skipped"),
        "the audit write must not have been dropped for want of an owner"
    );
}
