//! `epigraph_engine::recall::recall` refuses a `Bypass` viewer on a connection
//! that cannot spend it (backlog ef57f3b9).
//!
//! A `Bypass` viewer names no principal, so the library's audit row for it is
//! agent-less and is written on the connection `recall` took from its `pool`.
//! `recall_events_tenancy` admits an agent-less row only through the bypass arm,
//! i.e. only on a connection whose session user satisfies `epigraph_bypass()`.
//! Before this check, a `Bypass` viewer paired with an application pool was
//! served its recall and the audit row was refused by row security, logged as
//! "engine recall audit log failed; recall unaffected", and lost: the contract
//! that the pool be a maintenance pool was documented, not enforced.
//!
//! The refusal must be about the POOL, not about `Bypass`: the control below
//! runs the same recall with a `Bypass` viewer on the harness pool (whose
//! session user satisfies `epigraph_bypass()`) and expects it to be served and
//! audited.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::SystemReason;
use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider};
use sqlx::PgPool;

async fn audit_rows(pool: &PgPool, query: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM recall_events WHERE query_text = $1")
        .bind(query)
        .fetch_one(pool)
        .await
        .expect("count recall_events")
}

#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn a_bypass_recall_on_an_application_pool_is_refused_not_unaudited(pool: PgPool) {
    let agent: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-engine-bypass', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed agent");
    fixture::seed_public_claim(&pool, agent, "thrennic bypass seed").await;
    // Every query embed fails, so both recalls take the current-only text
    // fallback: the seed has no embedding, and an ANN read over a corpus with
    // no embedded row returns an empty page rather than an error.
    let provider = MockProvider::new(EmbeddingConfig::openai(1536)).with_failures(1.0);

    // Control: a Bypass viewer on a connection that satisfies
    // `epigraph_bypass()` is served AND audited, so the refusal below is the
    // pool deciding, not Bypass being refused outright.
    let (harness_scoped, harness_bypass) = fixture::bypass(&pool).await;
    let served = epigraph_engine::recall::recall(
        &pool,
        &harness_scoped,
        &harness_bypass,
        &provider,
        "thrennic",
        10,
        0.0,
    )
    .await
    .expect("control: a Bypass viewer on a privileged pool is served");
    assert_eq!(served.len(), 1, "control: the public seed is found");
    assert_eq!(
        audit_rows(&pool, "thrennic").await,
        1,
        "control: the privileged pool writes the agent-less audit row"
    );

    // The misuse: an application-role ScopedPool with no maintenance pool
    // attached, so its maintenance lease is drawn from the APPLICATION pool,
    // and `recall` handed that same application pool.
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(&pool).await,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let app = scoped.inner();
    let (_conn, lease) = scoped
        .unscoped_for_maintenance(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance lease from the app pool");
    let viewer = epigraph_db::Viewer::system(&lease, SystemReason::SchemaContractTest);
    assert!(viewer.is_bypass(), "precondition: a Bypass viewer");
    let bypass_ok: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(app)
        .await
        .expect("probe");
    assert!(
        !bypass_ok,
        "precondition: the application pool does not satisfy epigraph_bypass()"
    );

    let got =
        epigraph_engine::recall::recall(app, &scoped, &viewer, &provider, "orlivand", 10, 0.0)
            .await;
    let err = match got {
        Ok(results) => panic!(
            "a Bypass viewer on an application pool must be refused, not served with its \
             audit row silently lost; got {} result(s)",
            results.len()
        ),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("epigraph_bypass()"),
        "the refusal names the privilege the pool lacks; got: {err}"
    );
    assert_eq!(
        audit_rows(&pool, "orlivand").await,
        0,
        "a refused recall writes no audit row"
    );
    assert!(
        !logs_contain("engine recall audit log failed"),
        "the misuse must be refused up front, not discovered by a failed audit write"
    );
}
