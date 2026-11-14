#![cfg(feature = "db")]
//! The server's pgvector floor (backlog e30316ae), through the compiled
//! `server` binary.
//!
//! `epigraph-migrate`'s refusal and the version comparison are main's
//! `migrate::check_pgvector_version` / `require_supported_pgvector`, unit-tested
//! in `src/migrate.rs`. The server runs the same check at boot. No test
//! database can be downgraded below 0.8.0 (pgvector ships upgrade scripts
//! only), so the server's refusal is driven by the state a real deployment can
//! be in: a database the extension was never created in.
//!
//! Verified to fail without the server check: the server boots past the
//! migration block on an empty database and fails later, on the entity-type
//! cache, without naming pgvector.

#[path = "common/served.rs"]
mod served;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn the_server_refuses_a_database_without_pgvector(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let boot = tokio::task::spawn_blocking(move || served::boot(served::base_command(&db_url)))
        .await
        .expect("join");
    match boot {
        served::Boot::Serving(server) => {
            panic!("served an unmigrated database:\n{}", server.boot_log)
        }
        served::Boot::Exited { status, log } => {
            assert_eq!(status.code(), Some(1), "{log}");
            assert!(
                log.contains("refusing to serve")
                    && log.contains("pgvector extension (`vector`) is not installed"),
                "the refusal must name pgvector:\n{log}"
            );
        }
    }
}
