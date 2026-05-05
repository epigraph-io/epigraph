//! Apply pending SQL migrations and exit. Suitable for ExecStartPre= in
//! systemd units, or for ops dry-runs (with sqlx-cli for plan visibility).

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let pool = epigraph_db::PgPool::connect(&url)
        .await
        .expect("connect failed");
    epigraph_api::run_migrations(&pool)
        .await
        .expect("migrate failed");
    println!("migrations: ok");
}
