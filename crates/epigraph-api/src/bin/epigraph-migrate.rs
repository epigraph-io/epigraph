//! Apply pending SQL migrations and exit. Suitable for ExecStartPre= in
//! systemd units, or for ops dry-runs (with sqlx-cli for plan visibility).
//!
//! The bin requires the `db` feature (see Cargo.toml `required-features`).
//! When `cargo clippy --workspace` runs without `db` activated, this body
//! compiles out and `main` becomes a no-op so the build still succeeds.

#[cfg(feature = "db")]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable required");
    // Log the host but not credentials.
    let host_hint = url.split('@').nth(1).unwrap_or("<unknown>");
    tracing::info!(host = host_hint, "Connecting to PostgreSQL");
    // MAINTENANCE-DSN-EXEMPT: the migrator needs DDL privilege, which is a
    // different and strictly stronger role than `epigraph_maintenance` — a
    // maintenance DSN here would be the WRONG credential, not a safer one.
    // PR-16's Files line assigns this binary `MIGRATION_DATABASE_URL`, together
    // with the `.github/workflows/ci.yml` change that has to ship in the same
    // PR (CI runs this binary with only `DATABASE_URL` set). Pinned with this
    // reason in `crates/epigraph-db/tests/no_unmaintained_dsn.rs`.
    let pool = epigraph_db::PgPool::connect(&url)
        .await
        .expect("PgPool::connect to DATABASE_URL failed");
    tracing::info!("Applying migrations");
    epigraph_api::run_migrations(&pool)
        .await
        .expect("sqlx::migrate failed — refusing to leave DB in a half-migrated state");
    tracing::info!("migrations: ok");
    println!("migrations: ok"); // keep stdout marker for ops scripts that grep for it
}

#[cfg(not(feature = "db"))]
fn main() {
    eprintln!("epigraph-migrate requires the `db` feature");
    std::process::exit(1);
}
