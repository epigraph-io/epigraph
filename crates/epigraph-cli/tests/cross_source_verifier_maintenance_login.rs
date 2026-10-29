//! `RerankBridgesClient::verify` (the cross-source sweep's verifier) run as a
//! real maintenance login: a NOSUPERUSER role that is a member of
//! `epigraph_maintenance`, which holds USAGE but not CREATE on schema
//! `public`, by design.
//!
//! What is pinned:
//! - the verifier's scratch pair table can be created and filled by that
//!   login (it has no CREATE on `public`, so the table must be a TEMP table);
//! - the reranker's candidate read sees exactly the pairs written to it, which
//!   is only possible when the read runs in the same session that created the
//!   table, including a pair whose claim is group-private to a group the login
//!   is not a member of (the maintenance bypass survives on that session);
//! - nothing named `matcher_verify_*` is left in any schema afterwards.
//!
//! The mock provider answers nothing, so `verify` ends in its documented
//! "verifier outage" error, whose text carries the number of pairs the reranker
//! read back from the scratch table. That count is the observation.

#![cfg(feature = "genai")]

mod viewer_fixture;

use epigraph_cli::matching_client::RerankBridgesClient;
use epigraph_cli::rerank::RerankConfig;
use epigraph_engine::matching::verifier::VerifierClient;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

/// Create a NOSUPERUSER login in `epigraph_maintenance` and return
/// `(role, dsn)`. The caller drops the role.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("sweep_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let dsn = format!("{scheme}://{role}:probe-only@{host}");
    (role, dsn)
}

/// A 1536-d pgvector literal pointing along `axis0`/`axis1`.
fn vector(axis0: f64, axis1: f64) -> String {
    let mut v = vec!["0".to_string(); 1536];
    v[0] = axis0.to_string();
    v[1] = axis1.to_string();
    format!("[{}]", v.join(","))
}

async fn scratch_tables_left(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_class WHERE relname LIKE 'matcher\\_verify\\_%'")
        .fetch_one(pool)
        .await
        .expect("pg_class probe")
}

#[sqlx::test(migrations = "../../migrations")]
async fn verify_runs_on_a_maintenance_login_without_create_on_public(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "sweep-scratch").await;
    let a = fixture::seed_public_claim(&pool, owner, "scratch pair a").await;
    let b = fixture::seed_public_claim(&pool, owner, "scratch pair b").await;
    let c = fixture::seed_public_claim(&pool, owner, "scratch pair c").await;
    // Group-private: only a bypassing session reads it.
    let d = fixture::seed_group_claim(&pool, owner, group, "scratch pair d").await;
    for (id, v) in [
        (a, vector(1.0, 0.0)),
        (b, vector(1.0, 0.1)),
        (c, vector(0.0, 1.0)),
        (d, vector(0.1, 1.0)),
    ] {
        fixture::set_claim_embedding(&pool, id, &v).await;
    }

    let (role, dsn) = maintenance_login(&pool).await;
    let outcome = async {
        let maint = epigraph_cli::MaintenancePool::connect_to(&dsn, "sweep-scratch-test")
            .await
            .expect("maintenance pool");

        // Preconditions: the login is the shape this test is about.
        let (create_on_public, temp_on_db): (bool, bool) = sqlx::query_as(
            "SELECT has_schema_privilege(current_user, 'public', 'CREATE'), \
                    has_database_privilege(current_database(), 'TEMPORARY')",
        )
        .fetch_one(maint.pool())
        .await
        .expect("privilege probe");
        assert!(
            !create_on_public,
            "fixture: the maintenance login must NOT hold CREATE on public"
        );
        assert!(
            temp_on_db,
            "fixture: the maintenance login must hold TEMPORARY on the database"
        );

        let client = RerankBridgesClient::with_config(
            maint.pool().clone(),
            RerankConfig {
                provider: "mock".to_string(),
                ..RerankConfig::default()
            },
        );
        client.verify(&[(a, b), (c, d)]).await
    }
    .await;

    // Drop the cluster-global role BEFORE asserting, so a failure cannot leak it.
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");

    let err = outcome
        .expect_err("the mock provider answers nothing, so verify must report an outage")
        .to_string();
    assert!(
        !err.contains("permission denied"),
        "the scratch table must not need CREATE on public: {err}"
    );
    assert!(
        err.contains("sent 2 candidate pair(s)"),
        "the reranker must read back both scratch pairs, the group-private one \
         included, in the session that wrote them: {err}"
    );
    assert_eq!(
        scratch_tables_left(&pool).await,
        0,
        "no matcher_verify_* table may outlive verify"
    );
}
