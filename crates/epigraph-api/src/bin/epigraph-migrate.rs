//! Apply pending SQL migrations and exit. Suitable for ExecStartPre= in
//! systemd units, or for ops dry-runs (with sqlx-cli for plan visibility).

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL environment variable required");
    // Log the host but not credentials.
    let host_hint = url.split('@').nth(1).unwrap_or("<unknown>");
    tracing::info!(host = host_hint, "Connecting to PostgreSQL");
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
